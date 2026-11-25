//! QR decoding for the in-app "Scan your sheet" flow.
//!
//! Pure Rust and wasm-safe. Frames from the camera (or a chosen photo) are
//! drawn to a canvas, read back as RGBA, reduced to 8-bit luma and decoded
//! with [`rqrr`] (MIT OR Apache-2.0; a port of the quirc
//! decoder with no `unsafe` code in 0.8.0, used without its `image` feature). iOS Safari has no
//! `BarcodeDetector`, so one in-WASM decoder serves every platform and every
//! test runs through the same code path.
//!
//! Decoded payloads are secrets (a sheet QR carries the account key): they
//! are returned as [`Zeroizing<String>`] and never logged. The luma buffer is
//! wiped on drop too, because the picture of the code is as sensitive as the
//! decoded text.

use zeroize::Zeroizing;

/// Longest side, in pixels, a frame is scaled to before decoding. A sheet QR
/// held at arm's length fills a good part of the frame, so 640 px keeps the
/// modules several pixels wide while keeping each decode cheap on a phone.
pub const MAX_DECODE_SIDE: u32 = 640;

/// Scale `(w, h)` so the longer side is at most `max`, keeping the aspect
/// ratio. Never returns a zero dimension for a non-empty input.
pub fn scaled_dims(w: u32, h: u32, max: u32) -> (u32, u32) {
    if w == 0 || h == 0 {
        return (0, 0);
    }
    let long = w.max(h);
    if long <= max {
        return (w, h);
    }
    let sw = (u64::from(w) * u64::from(max) / u64::from(long)).max(1) as u32;
    let sh = (u64::from(h) * u64::from(max) / u64::from(long)).max(1) as u32;
    (sw, sh)
}

/// RGBA (canvas `ImageData` order) to 8-bit luma with integer BT.601
/// weights. Returns `None` if the buffer length does not match `w * h * 4`.
pub fn rgba_to_luma(rgba: &[u8], w: usize, h: usize) -> Option<Zeroizing<Vec<u8>>> {
    if w.checked_mul(h)?.checked_mul(4)? != rgba.len() {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(w * h));
    for px in rgba.chunks_exact(4) {
        let (r, g, b) = (u32::from(px[0]), u32::from(px[1]), u32::from(px[2]));
        // Transparent pixels (an alpha-only PNG) read as white paper.
        let y = if px[3] == 0 { 255 } else { (299 * r + 587 * g + 114 * b) / 1000 };
        out.push(y as u8);
    }
    Some(out)
}

/// What a frame contained.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// No readable code (keep scanning).
    Nothing,
    /// Exactly one distinct payload.
    One(Zeroizing<String>),
    /// Two or more DIFFERENT codes in view: refuse rather than guess which
    /// one the member meant (a second code could be planted beside theirs).
    Several,
}

/// Decode every readable QR code in a luma image.
///
/// Malformed input sizes give [`Decoded::Nothing`], never a panic here
/// (rqrr itself can still panic on pathological images: a wasm panic traps
/// the app, accepted as tab-level DoS; see `tests::fuzz_never_panics_*`).
pub fn decode_luma(luma: &[u8], w: usize, h: usize) -> Decoded {
    if w == 0 || h == 0 || w.checked_mul(h) != Some(luma.len()) {
        return Decoded::Nothing;
    }
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    let mut found: Option<Zeroizing<String>> = None;
    for grid in prepared.detect_grids() {
        let Ok((_, text)) = grid.decode() else { continue };
        let text = Zeroizing::new(text);
        match &found {
            None => found = Some(text),
            Some(prev) if *prev == text => {}
            Some(_) => return Decoded::Several,
        }
    }
    found.map_or(Decoded::Nothing, Decoded::One)
}

/// Decode a canvas `ImageData` buffer (RGBA) in one call.
pub fn decode_rgba(rgba: &[u8], w: usize, h: usize) -> Decoded {
    match rgba_to_luma(rgba, w, h) {
        Some(luma) => decode_luma(&luma, w, h),
        None => Decoded::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::{Color, EcLevel, QrCode};

    /// Render `data` as a luma image: `scale` px per module, 4-module quiet
    /// zone, placed at (`ox`, `oy`) on a `canvas`-sized white page.
    fn render(data: &str, scale: usize, canvas: (usize, usize), ox: usize, oy: usize) -> Vec<u8> {
        let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M).unwrap();
        let n = code.width();
        let colors = code.to_colors();
        let (cw, ch) = canvas;
        let mut img = vec![255u8; cw * ch];
        for my in 0..n {
            for mx in 0..n {
                if colors[my * n + mx] == Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let x = ox + (mx + 4) * scale + dx;
                            let y = oy + (my + 4) * scale + dy;
                            img[y * cw + x] = 0;
                        }
                    }
                }
            }
        }
        img
    }

    fn synthetic_link() -> String {
        let nsec = nostr_bbs_core::encode_nsec(&"01".repeat(32)).unwrap();
        crate::utils::connect_link::connect_url("https://forum.example", "/community", &nsec)
    }

    #[test]
    fn decodes_a_sheet_link_at_several_scales() {
        let link = synthetic_link();
        for scale in [2usize, 3, 5, 8] {
            let side = (45 + 8) * scale + 40;
            let img = render(&link, scale, (side, side), 20, 20);
            assert_eq!(decode_luma(&img, side, side), Decoded::One(Zeroizing::new(link.clone())), "scale {scale}");
        }
    }

    #[test]
    fn decodes_off_centre_in_a_wide_frame_with_noise() {
        let link = synthetic_link();
        let (w, h) = (640, 360);
        let mut img = render(&link, 4, (w, h), 300, 60);
        // Deterministic speckle noise (LCG), +/-40 on every pixel.
        let mut s: u32 = 0x1234_5678;
        for p in img.iter_mut() {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let n = (s >> 24) as i32 % 81 - 40;
            *p = (i32::from(*p) + n).clamp(0, 255) as u8;
        }
        assert_eq!(decode_luma(&img, w, h), Decoded::One(Zeroizing::new(link)));
    }

    #[test]
    fn rgba_path_matches_luma_path() {
        let link = synthetic_link();
        let side = 300;
        let luma = render(&link, 4, (side, side), 10, 10);
        let rgba: Vec<u8> = luma.iter().flat_map(|&y| [y, y, y, 255]).collect();
        assert_eq!(decode_rgba(&rgba, side, side), Decoded::One(Zeroizing::new(link)));
    }

    #[test]
    fn blank_and_malformed_inputs() {
        assert_eq!(decode_luma(&vec![255u8; 100 * 100], 100, 100), Decoded::Nothing);
        assert_eq!(decode_luma(&[0u8; 10], 100, 100), Decoded::Nothing);
        assert_eq!(decode_luma(&[], 0, 0), Decoded::Nothing);
        assert!(rgba_to_luma(&[0u8; 7], 1, 2).is_none());
        assert!(rgba_to_luma(&[0u8; 8], usize::MAX, 2).is_none());
    }

    #[test]
    fn luma_weights() {
        let px = [255, 255, 255, 255, 0, 0, 0, 255, 255, 0, 0, 255, 9, 9, 9, 0];
        let l = rgba_to_luma(&px, 4, 1).unwrap();
        assert_eq!(l.as_slice(), &[255, 0, 76, 255]);
    }

    /// Paste a second luma image into `dst` at (ox, oy).
    fn paste(dst: &mut [u8], dw: usize, src: &[u8], sw: usize, ox: usize, oy: usize) {
        for (y, row) in src.chunks_exact(sw).enumerate() {
            dst[(oy + y) * dw + ox..(oy + y) * dw + ox + sw].copy_from_slice(row);
        }
    }

    #[test]
    fn two_different_codes_are_refused_two_identical_accepted() {
        let link = synthetic_link();
        let other = "https://evil.example/#k=x";
        let (w, h) = (640, 300);
        let mut img = vec![255u8; w * h];
        let a = render(&link, 4, (240, 240), 0, 0);
        let b = render(other, 4, (240, 240), 0, 0);
        paste(&mut img, w, &a, 240, 10, 30);
        paste(&mut img, w, &b, 240, 380, 30);
        assert_eq!(decode_luma(&img, w, h), Decoded::Several);
        let mut same = vec![255u8; w * h];
        paste(&mut same, w, &a, 240, 10, 30);
        paste(&mut same, w, &a, 240, 380, 30);
        assert_eq!(decode_luma(&same, w, h), Decoded::One(Zeroizing::new(link)));
    }

    /// Deterministic fuzz: random noise, random blocks, and a real code with
    /// random module flips, crops and sizes. Native panics are caught so a
    /// failing seed is reported; on wasm a panic would trap the app (S5).
    #[test]
    fn fuzz_never_panics_on_noise_and_mutations() {
        let link = synthetic_link();
        let base = render(&link, 3, (200, 200), 10, 10);
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for case in 0..400u32 {
            let kind = case % 3;
            let (w, h, img) = match kind {
                0 => {
                    let w = 1 + (next() % 300) as usize;
                    let h = 1 + (next() % 300) as usize;
                    (w, h, (0..w * h).map(|_| next() as u8).collect::<Vec<u8>>())
                }
                1 => {
                    let (w, h) = (160usize, 160usize);
                    let mut img = vec![255u8; w * h];
                    for _ in 0..(next() % 60) {
                        let (x, y) = ((next() % 150) as usize, (next() % 150) as usize);
                        let (bw, bh) = (1 + (next() % 20) as usize, 1 + (next() % 20) as usize);
                        for yy in y..(y + bh).min(h) {
                            for xx in x..(x + bw).min(w) {
                                img[yy * w + xx] = 0;
                            }
                        }
                    }
                    (w, h, img)
                }
                _ => {
                    let mut img = base.clone();
                    for _ in 0..(1 + next() % 400) {
                        let i = (next() as usize) % img.len();
                        img[i] = 255 - img[i];
                    }
                    let crop_h = 40 + (next() % 160) as usize;
                    img.truncate(200 * crop_h);
                    (200, crop_h, img)
                }
            };
            let r = std::panic::catch_unwind(|| decode_luma(&img, w, h));
            assert!(r.is_ok(), "rqrr panicked on fuzz case {case} (kind {kind}, {w}x{h})");
        }
    }

    #[test]
    fn scaling() {
        assert_eq!(scaled_dims(1920, 1080, 640), (640, 360));
        assert_eq!(scaled_dims(1080, 1920, 640), (360, 640));
        assert_eq!(scaled_dims(320, 240, 640), (320, 240));
        assert_eq!(scaled_dims(0, 10, 640), (0, 0));
        assert_eq!(scaled_dims(10_000, 1, 640), (640, 1));
    }
}
