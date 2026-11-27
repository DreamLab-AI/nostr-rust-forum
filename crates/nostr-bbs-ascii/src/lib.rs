//! On-theme ASCII-art image rendering for the retro BBS.
//!
//! An image is projected onto a character grid: each cell takes a **glyph**
//! from a dark→light ramp (by luma) and a **phosphor level** `0..=7` (also by
//! luma). The HTML emitter writes the level as a `pN` class — deliberately
//! *theme-agnostic*. The BBS stylesheet maps `p0..p7` onto the active theme's
//! `--bg`..`--fg-bright` phosphor ramp with `color-mix`, so a single cached
//! render recolours across amber/green/purple/sky for free and the render
//! cache needs no theme key.
//!
//! The projection + emitters are pure and dependency-free, so this crate
//! compiles for any target (including the `wasm32-unknown-unknown` clients).
//! Image *decoding* lives behind the `decode` feature (the `image` crate),
//! enabled only by the server-side preview/pod workers — clients fetch the
//! rendered HTML fragment, they never pull a decoder into their bundle.

#![forbid(unsafe_code)]

use core::fmt::Write as _;

/// Number of phosphor brightness levels emitted as `p0..p{LEVELS-1}` classes.
pub const LEVELS: u8 = 8;

/// Default character-grid width (columns) when none is requested.
pub const DEFAULT_COLS: u32 = 80;
/// Default maximum character-grid height (rows).
pub const DEFAULT_ROWS: u32 = 48;

/// Monospace cells are about twice as tall as they are wide; the vertical
/// sampling step is scaled by this so projected images keep their aspect.
const CELL_ASPECT: f32 = 0.5;

/// Hard ceilings so an attacker-supplied grid request can't blow up output.
const MAX_COLS: u32 = 400;
const MAX_ROWS: u32 = 300;

/// A dark→light glyph ramp. Index `0` is "darkest" (sparsest ink).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum GlyphRamp {
    /// `  .:-=+*#%@` — the classic 10-step ramp; reads well at any size.
    #[default]
    Standard,
    /// ` ░▒▓█` — Unicode block shades; dense, poster-like.
    Blocks,
    /// A 70-step ramp for large renders where fine tonal detail matters.
    Dense,
}

impl GlyphRamp {
    /// Parse from a query/config string; unknown values fall back to standard.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "blocks" | "block" => GlyphRamp::Blocks,
            "dense" | "fine" => GlyphRamp::Dense,
            _ => GlyphRamp::Standard,
        }
    }

    fn glyphs(self) -> &'static [char] {
        match self {
            GlyphRamp::Standard => &[' ', '.', ':', '-', '=', '+', '*', '#', '%', '@'],
            GlyphRamp::Blocks => &[' ', '░', '▒', '▓', '█'],
            GlyphRamp::Dense => &[
                ' ', '.', '\'', '`', '^', '"', ',', ':', ';', 'I', 'l', '!', 'i', '>', '<', '~',
                '+', '_', '-', '?', ']', '[', '}', '{', '1', ')', '(', '|', '/', 't', 'f', 'j',
                'r', 'x', 'n', 'u', 'v', 'c', 'z', 'X', 'Y', 'U', 'J', 'C', 'L', 'Q', '0', 'O',
                'Z', 'm', 'w', 'q', 'p', 'd', 'b', 'k', 'h', 'a', 'o', '*', '#', 'M', 'W', '&',
                '8', '%', 'B', '@', '$',
            ],
        }
    }
}

/// How an image is projected onto the character grid.
#[derive(Clone, Copy, Debug)]
pub struct RenderOptions {
    /// Target grid width in columns (clamped to `1..=MAX_COLS`).
    pub cols: u32,
    /// Maximum grid height in rows (clamped to `1..=MAX_ROWS`); the actual row
    /// count is derived from the source aspect ratio and may be smaller.
    pub max_rows: u32,
    /// Glyph ramp.
    pub ramp: GlyphRamp,
    /// Invert luma — render bright source pixels as *sparse* ink (dark-on-light)
    /// rather than the default phosphor (bright source → dense bright glyph).
    pub invert: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            cols: DEFAULT_COLS,
            max_rows: DEFAULT_ROWS,
            ramp: GlyphRamp::Standard,
            invert: false,
        }
    }
}

impl RenderOptions {
    /// Clamp user-supplied dimensions into the safe range.
    fn sanitized(self) -> Self {
        Self {
            cols: self.cols.clamp(1, MAX_COLS),
            max_rows: self.max_rows.clamp(1, MAX_ROWS),
            ..self
        }
    }
}

/// One projected cell: a glyph plus its phosphor brightness level `0..LEVELS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub glyph: char,
    pub level: u8,
}

/// A rendered ASCII image: a `cols × rows` row-major grid of [`Cell`]s.
#[derive(Clone, Debug)]
pub struct AsciiArt {
    pub cols: u32,
    pub rows: u32,
    cells: Vec<Cell>,
}

impl AsciiArt {
    /// The projected cells, row-major (`rows * cols` of them).
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// Plain text — glyphs joined by newlines. No colour.
    pub fn to_plain(&self) -> String {
        let mut out = String::with_capacity((self.cols as usize + 1) * self.rows as usize);
        for row in self.cells.chunks(self.cols as usize) {
            for cell in row {
                out.push(cell.glyph);
            }
            out.push('\n');
        }
        out
    }

    /// HTML fragment for the BBS: a `<pre class="ascii-img">` whose runs of
    /// equal-level cells are wrapped in `<span class="pN">`. Glyphs are
    /// HTML-escaped. The `pN` classes are theme-agnostic — the stylesheet
    /// colours them per active theme.
    pub fn to_html(&self) -> String {
        let mut out = String::with_capacity(self.cells.len() * 2 + 64);
        out.push_str("<pre class=\"ascii-img\" aria-hidden=\"true\">");
        for row in self.cells.chunks(self.cols as usize) {
            let mut i = 0;
            while i < row.len() {
                let level = row[i].level;
                let _ = write!(out, "<span class=\"p{level}\">");
                while i < row.len() && row[i].level == level {
                    push_escaped(&mut out, row[i].glyph);
                    i += 1;
                }
                out.push_str("</span>");
            }
            out.push('\n');
        }
        out.push_str("</pre>");
        out
    }

    /// 24-bit-colour ANSI for a terminal, tinting each level toward `fg`
    /// (`(r,g,b)`), darkest level on the terminal's own background. Useful for
    /// CLI/log rendering; the web BBS uses [`AsciiArt::to_html`].
    pub fn to_ansi(&self, fg: (u8, u8, u8)) -> String {
        let mut out = String::with_capacity(self.cells.len() * 12);
        for row in self.cells.chunks(self.cols as usize) {
            for cell in row {
                let f = cell.level as f32 / (LEVELS - 1) as f32;
                let (r, g, b) = (
                    (fg.0 as f32 * f) as u8,
                    (fg.1 as f32 * f) as u8,
                    (fg.2 as f32 * f) as u8,
                );
                let _ = write!(out, "\x1b[38;2;{r};{g};{b}m{}", cell.glyph);
            }
            out.push_str("\x1b[0m\n");
        }
        out
    }
}

#[inline]
fn push_escaped(out: &mut String, c: char) {
    match c {
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '&' => out.push_str("&amp;"),
        _ => out.push(c),
    }
}

/// Map a luma byte to a [`Cell`] under `opts`.
#[inline]
fn cell_for_luma(luma: u8, glyphs: &[char], invert: bool) -> Cell {
    let l = if invert { 255 - luma } else { luma } as u32;
    let glyph = glyphs[(l * (glyphs.len() as u32 - 1) / 255) as usize];
    let level = (l * (LEVELS as u32 - 1) / 255) as u8;
    Cell { glyph, level }
}

/// Project an 8-bit luma grid (`src_w × src_h`, row-major) onto a character
/// grid. This is the pure, dependency-free core — both the `decode` path and
/// the tests funnel through it.
pub fn render_luma(src: &[u8], src_w: u32, src_h: u32, opts: &RenderOptions) -> AsciiArt {
    let opts = opts.sanitized();
    let glyphs = opts.ramp.glyphs();

    if src_w == 0 || src_h == 0 || src.len() < (src_w * src_h) as usize {
        return AsciiArt {
            cols: 0,
            rows: 0,
            cells: Vec::new(),
        };
    }

    let cols = opts.cols.min(src_w.max(1));
    // Preserve aspect: rows ∝ cols * (src_h/src_w) * cell-aspect, then cap.
    let rows = (((cols as f32) * (src_h as f32 / src_w as f32) * CELL_ASPECT).round() as u32)
        .clamp(1, opts.max_rows);

    let mut cells = Vec::with_capacity((cols * rows) as usize);
    for cy in 0..rows {
        // Nearest-sample the source row/column for this cell.
        let sy = (cy * src_h / rows).min(src_h - 1);
        for cx in 0..cols {
            let sx = (cx * src_w / cols).min(src_w - 1);
            let luma = src[(sy * src_w + sx) as usize];
            cells.push(cell_for_luma(luma, glyphs, opts.invert));
        }
    }
    AsciiArt { cols, rows, cells }
}

/// Decode an encoded image (PNG/JPEG/GIF/WebP/BMP) and render it to ASCII.
///
/// Server-side only (preview/pod workers). The format is sniffed from the
/// bytes (never trusted from a header), the dimensions are read from the
/// image header and checked against [`MAX_PIXELS`] **before** any pixel buffer
/// is allocated, and the decode itself is bounded:
///
/// * a JPEG is downscaled while it is decoded (DCT scaling to 1/2, 1/4 or
///   1/8), so a 12-megapixel photo decodes to well under a megapixel;
/// * any other format decodes at full size within [`MAX_DECODE_BYTES`].
///
/// A GIF renders its first frame.
///
/// # Errors
///
/// [`AsciiError::NotAnImage`] when the bytes are not a supported image
/// format, [`AsciiError::TooLarge`] past either budget, and
/// [`AsciiError::Decode`] for a recognised but corrupt image.
///
/// # Examples
///
/// ```
/// use nostr_bbs_ascii::{render_bytes, AsciiError, RenderOptions};
///
/// let not_an_image = b"<!doctype html><title>404</title>";
/// assert_eq!(
///     render_bytes(not_an_image, &RenderOptions::default()).unwrap_err(),
///     AsciiError::NotAnImage
/// );
/// ```
#[cfg(feature = "decode")]
pub fn render_bytes(bytes: &[u8], opts: &RenderOptions) -> Result<AsciiArt, AsciiError> {
    use image::ImageFormat;

    let format = match image::guess_format(bytes) {
        Ok(
            f @ (ImageFormat::Png
            | ImageFormat::Jpeg
            | ImageFormat::Gif
            | ImageFormat::WebP
            | ImageFormat::Bmp),
        ) => f,
        _ => return Err(AsciiError::NotAnImage),
    };
    let reader = || image::io::Reader::with_format(std::io::Cursor::new(bytes), format);
    let (w, h) = reader().into_dimensions().map_err(|_| AsciiError::Decode)?;
    check_pixels(w, h)?;

    let img = if format == ImageFormat::Jpeg {
        decode_jpeg_scaled(bytes, opts)?
    } else {
        let mut r = reader();
        let mut limits = image::io::Limits::default();
        limits.max_alloc = Some(MAX_DECODE_BYTES);
        r.limits(limits);
        r.decode().map_err(map_image_error)?
    };
    let luma = img.to_luma8();
    let (w, h) = luma.dimensions();
    Ok(render_luma(luma.as_raw(), w, h, opts))
}

/// Refuse an image whose header declares more than [`MAX_PIXELS`].
#[cfg(feature = "decode")]
fn check_pixels(w: u32, h: u32) -> Result<(), AsciiError> {
    if w == 0 || h == 0 {
        return Err(AsciiError::Decode);
    }
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(AsciiError::TooLarge);
    }
    Ok(())
}

/// Classify a decoder failure: a limit is "too large", anything else corrupt.
#[cfg(feature = "decode")]
fn map_image_error(e: image::ImageError) -> AsciiError {
    match e {
        image::ImageError::Limits(_) => AsciiError::TooLarge,
        _ => AsciiError::Decode,
    }
}

/// The smallest source size a render needs: a few source pixels per cell
/// across, so the nearest-sample projection still reads well.
#[cfg(feature = "decode")]
fn wanted_source_width(opts: &RenderOptions) -> u16 {
    let cols = opts.sanitized().cols;
    u16::try_from((cols * 4).max(256)).unwrap_or(u16::MAX)
}

/// Decode a JPEG downscaled during decode (DCT scaling), bounded by
/// [`MAX_DECODE_BYTES`] for the output buffer.
#[cfg(feature = "decode")]
fn decode_jpeg_scaled(
    bytes: &[u8],
    opts: &RenderOptions,
) -> Result<image::DynamicImage, AsciiError> {
    use image::ImageDecoder as _;

    let mut dec = image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(bytes))
        .map_err(map_image_error)?;
    let want = wanted_source_width(opts);
    // Ask for at least `want` across; the decoder picks the smallest DCT
    // scale that still meets it in one axis, never upscaling.
    dec.scale(want, want).map_err(map_image_error)?;
    if dec.total_bytes() > MAX_DECODE_BYTES {
        return Err(AsciiError::TooLarge);
    }
    image::DynamicImage::from_decoder(dec).map_err(map_image_error)
}

/// Upper bound on image area (pixels) accepted by [`render_bytes`], read from
/// the image header before anything is decoded: a guard against
/// decompression bombs. Comfortably above a 12-megapixel phone photo.
#[cfg(feature = "decode")]
pub const MAX_PIXELS: u64 = 24_000_000;

/// Upper bound on the pixel buffer a full-size (non-JPEG) decode may allocate
/// in [`render_bytes`]: a 12-megapixel RGBA image fits, within a Worker's
/// 128 MB memory.
#[cfg(feature = "decode")]
pub const MAX_DECODE_BYTES: u64 = 64 * 1024 * 1024;

/// Failure modes of [`render_bytes`].
#[cfg(feature = "decode")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsciiError {
    /// The bytes are not an image in a supported format (an HTML error page,
    /// JSON, SVG, an unknown format).
    NotAnImage,
    /// A supported format whose bytes are corrupt or truncated.
    Decode,
    /// Over [`MAX_PIXELS`] or [`MAX_DECODE_BYTES`].
    TooLarge,
}

#[cfg(feature = "decode")]
impl core::fmt::Display for AsciiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AsciiError::NotAnImage => f.write_str("not an image (or an unsupported format)"),
            AsciiError::Decode => f.write_str("corrupt or truncated image"),
            AsciiError::TooLarge => f.write_str("image too large to render"),
        }
    }
}

#[cfg(feature = "decode")]
impl std::error::Error for AsciiError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4×2 luma ramp: black, mid, light, white on the top row; inverse below.
    fn grid() -> (Vec<u8>, u32, u32) {
        (vec![0, 85, 170, 255, 255, 170, 85, 0], 4, 2)
    }

    #[test]
    fn projects_to_requested_columns_and_keeps_one_row_for_wide_input() {
        let (src, w, h) = grid();
        let art = render_luma(
            &src,
            w,
            h,
            &RenderOptions {
                cols: 4,
                ..Default::default()
            },
        );
        assert_eq!(art.cols, 4);
        assert_eq!(art.rows, 1); // 4 wide, 2 tall, ×0.5 aspect → 1 row
        assert_eq!(art.cells().len(), 4);
    }

    #[test]
    fn luma_maps_darkest_to_space_and_brightest_to_at() {
        let (src, w, h) = grid();
        let art = render_luma(
            &src,
            w,
            h,
            &RenderOptions {
                cols: 4,
                max_rows: 2,
                ..Default::default()
            },
        );
        let first = art.cells()[0];
        let last = art.cells()[art.cols as usize - 1];
        assert_eq!(first.glyph, ' '); // luma 0
        assert_eq!(first.level, 0);
        assert_eq!(last.glyph, '@'); // luma 255, standard ramp
        assert_eq!(last.level, LEVELS - 1);
    }

    #[test]
    fn invert_flips_the_ramp() {
        let (src, w, h) = grid();
        let art = render_luma(
            &src,
            w,
            h,
            &RenderOptions {
                cols: 4,
                invert: true,
                ..Default::default()
            },
        );
        assert_eq!(art.cells()[0].glyph, '@'); // luma 0 inverted → brightest glyph
        assert_eq!(art.cells()[0].level, LEVELS - 1);
    }

    #[test]
    fn html_escapes_glyphs_and_groups_equal_levels() {
        // Two cells at the same level collapse into one span.
        let art = render_luma(
            &[255, 255],
            2,
            1,
            &RenderOptions {
                cols: 2,
                ..Default::default()
            },
        );
        let html = art.to_html();
        assert!(html.starts_with("<pre class=\"ascii-img\""));
        assert_eq!(
            html.matches("<span").count(),
            1,
            "equal-level run is one span"
        );
        assert!(html.contains(&format!("p{}", LEVELS - 1)));
        assert!(html.ends_with("</pre>"));
    }

    #[test]
    fn html_escapes_special_chars() {
        // The dense ramp contains `<`, `>`, `&`-adjacent glyphs; force one.
        let mut out = String::new();
        push_escaped(&mut out, '<');
        push_escaped(&mut out, '>');
        push_escaped(&mut out, '&');
        assert_eq!(out, "&lt;&gt;&amp;");
    }

    #[test]
    fn empty_or_malformed_input_is_safe() {
        assert_eq!(
            render_luma(&[], 0, 0, &RenderOptions::default())
                .cells()
                .len(),
            0
        );
        // Claimed dimensions exceed the buffer → empty, no panic.
        assert_eq!(
            render_luma(&[1, 2], 8, 8, &RenderOptions::default())
                .cells()
                .len(),
            0
        );
    }

    #[test]
    fn ramp_parse_is_lenient() {
        assert_eq!(GlyphRamp::parse("BLOCKS"), GlyphRamp::Blocks);
        assert_eq!(GlyphRamp::parse(" dense "), GlyphRamp::Dense);
        assert_eq!(GlyphRamp::parse("nonsense"), GlyphRamp::Standard);
    }

    #[test]
    fn dimensions_are_clamped() {
        let art = render_luma(
            &[128; 64],
            8,
            8,
            &RenderOptions {
                cols: 99_999,
                max_rows: 99_999,
                ..Default::default()
            },
        );
        assert!(art.cols <= MAX_COLS);
        assert!(art.rows <= MAX_ROWS);
        // cols is also bounded by source width here.
        assert_eq!(art.cols, 8);
    }

    #[test]
    fn ansi_tints_toward_fg_and_resets_each_row() {
        let art = render_luma(
            &[0, 255],
            2,
            1,
            &RenderOptions {
                cols: 2,
                ..Default::default()
            },
        );
        let ansi = art.to_ansi((255, 176, 0));
        assert!(ansi.contains("\x1b[38;2;"));
        assert!(ansi.ends_with("\x1b[0m\n"));
    }
}

#[cfg(all(test, feature = "decode"))]
mod decode_tests {
    use super::*;
    use image::{DynamicImage, ImageOutputFormat, RgbImage};

    /// A synthetic photo-like test card (gradients plus a hard-edged
    /// pattern), generated here: no member content in the tests.
    fn test_card(w: u32, h: u32) -> DynamicImage {
        DynamicImage::ImageRgb8(RgbImage::from_fn(w, h, |x, y| {
            let check = if (x / 120 + y / 120) % 2 == 0 { 40 } else { 0 };
            image::Rgb([
                ((x * 255 / w) as u8).saturating_add(check),
                (y * 255 / h) as u8,
                ((x ^ y) % 256) as u8,
            ])
        }))
    }

    fn encode(img: &DynamicImage, fmt: ImageOutputFormat) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, fmt).expect("encode");
        out.into_inner()
    }

    fn opts(cols: u32) -> RenderOptions {
        RenderOptions {
            cols,
            ..Default::default()
        }
    }

    #[test]
    fn a_1920x1440_baseline_jpeg_photo_renders() {
        let jpeg = encode(&test_card(1920, 1440), ImageOutputFormat::Jpeg(85));
        assert_eq!(&jpeg[..3], &[0xFF, 0xD8, 0xFF], "a JPEG fixture");
        let art = render_bytes(&jpeg, &opts(68)).expect("renders");
        assert_eq!(art.cols, 68);
        // 4:3 at a 0.5 cell aspect: 68 × 0.75 × 0.5 ≈ 26 rows.
        assert_eq!(art.rows, 26);
        assert!(art.to_html().starts_with("<pre class=\"ascii-img\""));
    }

    #[test]
    fn a_12_megapixel_jpeg_renders_downscaled() {
        let jpeg = encode(&test_card(4000, 3000), ImageOutputFormat::Jpeg(80));
        let art = render_bytes(&jpeg, &opts(80)).expect("renders");
        assert_eq!((art.cols, art.rows), (80, 30));
        // The decode itself was scaled: the JPEG decoder's output for an
        // 80-column render is at most a quarter of the source width.
        let mut dec = image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(&jpeg)).unwrap();
        let w = wanted_source_width(&opts(80));
        let (sw, _) = dec.scale(w, w).unwrap();
        assert!(sw <= 1000, "scaled width {sw}");
    }

    #[test]
    fn png_and_gif_render() {
        let card = test_card(1920, 1440);
        let png = encode(&card, ImageOutputFormat::Png);
        assert_eq!(render_bytes(&png, &opts(40)).unwrap().cols, 40);
        let gif = encode(&test_card(320, 240), ImageOutputFormat::Gif);
        assert_eq!(render_bytes(&gif, &opts(40)).unwrap().cols, 40);
    }

    #[test]
    fn non_images_are_not_images() {
        for body in [
            &b"<!DOCTYPE html><html><body>error code: 1042</body></html>"[..],
            br#"{"error":"Authentication required"}"#,
            b"<svg xmlns='http://www.w3.org/2000/svg'/>",
            b"",
        ] {
            assert_eq!(
                render_bytes(body, &opts(40)).unwrap_err(),
                AsciiError::NotAnImage
            );
        }
    }

    #[test]
    fn a_truncated_jpeg_is_corrupt() {
        let jpeg = encode(&test_card(640, 480), ImageOutputFormat::Jpeg(85));
        let cut = &jpeg[..200];
        assert_eq!(
            render_bytes(cut, &opts(40)).unwrap_err(),
            AsciiError::Decode
        );
    }

    #[test]
    fn an_oversized_header_is_refused_before_decoding() {
        // A PNG whose header declares 20000 × 20000 (400 MP): refused from
        // the header alone, without allocating its pixels.
        let mut png = encode(&test_card(8, 8), ImageOutputFormat::Png);
        // IHDR data starts at byte 16: width then height, big-endian.
        png[16..20].copy_from_slice(&20_000u32.to_be_bytes());
        png[20..24].copy_from_slice(&20_000u32.to_be_bytes());
        // Re-seal the IHDR chunk's CRC (over type + data, bytes 12..29).
        let crc = crc32(&png[12..29]);
        png[29..33].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(
            render_bytes(&png, &opts(40)).unwrap_err(),
            AsciiError::TooLarge
        );
        assert!(check_pixels(4000, 3000).is_ok(), "12 MP is accepted");
        assert_eq!(check_pixels(6000, 5000), Err(AsciiError::TooLarge));
    }

    /// CRC-32 (IEEE), as PNG chunks use; bitwise, for a test fixture.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn errors_say_which_failure() {
        let texts = [
            AsciiError::NotAnImage.to_string(),
            AsciiError::Decode.to_string(),
            AsciiError::TooLarge.to_string(),
        ];
        assert!(texts[0].contains("not an image"));
        assert!(texts[1].contains("corrupt"));
        assert!(texts[2].contains("too large"));
    }
}
