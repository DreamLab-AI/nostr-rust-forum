//! Media: content-addressed image optimisation for zone containers.
//!
//! Every `ok` image attachment of the archive is processed once per
//! SHA-256 of its archived bytes, however often it was posted:
//!
//! 1. the type is sniffed from the **magic bytes** (never the extension or
//!    the declared type) and must be one of JPEG, PNG, GIF, WebP, HEIC/HEIF,
//!    AVIF, TIFF or BMP; anything else is refused (SVG, PostScript, PDF, text
//!    and every other ImageMagick coder never run);
//! 2. ImageMagick (`magick`, a thin wrapper) runs with the input coder
//!    pinned (`png:<file>`), under a policy file that denies every coder
//!    but those eight, every delegate and `@file` indirection, with
//!    resource limits: `-auto-orient -strip -resize 2048x2048> -quality 82`
//!    to WebP (animated GIFs keep their frames, stripped) and a 480 px WebP
//!    thumbnail;
//! 3. the output is checked to carry no EXIF/XMP chunk; an image that fails
//!    any step is recorded as failed and **never** uploaded raw (it may carry
//!    GPS).
//!
//! Original timestamps (first send time, EXIF `DateTimeOriginal`) live in
//! `media/manifest.json`, not in the stored bytes. Objects are named by the
//! full source digest, `<sha256>.webp` / `.gif` and `<sha256>_thumb.webp`
//! (the client's thumbnail convention; a shorter prefix could be collided
//! by a crafted archive) and placed in the archivist's zone
//! container ([`crate::target::Target::zone_media_url`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::format::{Archive, AttachmentStatus};
use crate::fsutil;

/// Longest edge of the main image.
pub const MAX_EDGE: u32 = 2048;
/// Longest edge of the thumbnail.
pub const THUMB_EDGE: u32 = 480;

/// ImageMagick policy: deny everything but the eight raster coders.
pub const POLICY_XML: &str = r#"<policymap>
  <policy domain="delegate" rights="none" pattern="*" />
  <policy domain="coder" rights="none" pattern="*" />
  <policy domain="coder" rights="read | write" pattern="{JPEG,PNG,GIF,WEBP,HEIC,AVIF,TIFF,BMP}" />
  <policy domain="path" rights="none" pattern="@*" />
  <policy domain="resource" name="memory" value="512MiB"/>
  <policy domain="resource" name="map" value="1GiB"/>
  <policy domain="resource" name="disk" value="2GiB"/>
  <policy domain="resource" name="width" value="20KP"/>
  <policy domain="resource" name="height" value="20KP"/>
  <policy domain="resource" name="area" value="200MP"/>
  <policy domain="resource" name="time" value="120"/>
</policymap>
"#;

/// An image type recognised by its magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageType {
    /// JPEG.
    Jpeg,
    /// PNG.
    Png,
    /// GIF (animation kept).
    Gif,
    /// WebP.
    Webp,
    /// HEIC / HEIF.
    Heic,
    /// AVIF.
    Avif,
    /// TIFF.
    Tiff,
    /// BMP.
    Bmp,
}

impl ImageType {
    /// The ImageMagick coder prefix pinned on the input.
    pub fn coder(self) -> &'static str {
        match self {
            ImageType::Jpeg => "jpeg",
            ImageType::Png => "png",
            ImageType::Gif => "gif",
            ImageType::Webp => "webp",
            ImageType::Heic => "heic",
            ImageType::Avif => "avif",
            ImageType::Tiff => "tiff",
            ImageType::Bmp => "bmp",
        }
    }
}

/// Sniff the image type from the first bytes of a file.
pub fn sniff(head: &[u8]) -> Option<ImageType> {
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageType::Jpeg);
    }
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(ImageType::Png);
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Some(ImageType::Gif);
    }
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Some(ImageType::Webp);
    }
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        return match &head[8..12] {
            b"avif" | b"avis" => Some(ImageType::Avif),
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"mif1" | b"msf1" => Some(ImageType::Heic),
            _ => None,
        };
    }
    if head.starts_with(b"II*\0") || head.starts_with(b"MM\0*") {
        return Some(ImageType::Tiff);
    }
    if head.starts_with(b"BM") && head.len() >= 14 {
        return Some(ImageType::Bmp);
    }
    None
}

/// Whether a WebP file carries an `EXIF` or `XMP ` chunk.
pub fn webp_has_metadata(bytes: &[u8]) -> bool {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return true; // not a WebP we wrote: treat as unsafe
    }
    let mut i = 12usize;
    while i + 8 <= bytes.len() {
        let id = &bytes[i..i + 4];
        let len =
            u32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]) as usize;
        if id == b"EXIF" || id == b"XMP " {
            return true;
        }
        i = i.saturating_add(8).saturating_add(len + (len & 1));
    }
    false
}

/// Whether a GIF carries a comment extension or an application extension
/// other than the animation loop block (`NETSCAPE2.0` / `ANIMEXTS1.0`);
/// XMP lives in an application extension. Walks the block structure, so
/// image data never causes a false match. A malformed file counts as
/// carrying metadata.
pub fn gif_has_metadata(b: &[u8]) -> bool {
    fn skip_sub_blocks(b: &[u8], mut i: usize) -> Option<usize> {
        loop {
            let n = *b.get(i)? as usize;
            i += 1;
            if n == 0 {
                return Some(i);
            }
            i += n;
        }
    }
    let walk = || -> Option<bool> {
        if b.len() < 13 || !(b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a")) {
            return None;
        }
        let flags = b[10];
        let mut i = 13
            + if flags & 0x80 != 0 {
                3 * (1usize << ((flags & 7) + 1))
            } else {
                0
            };
        loop {
            match *b.get(i)? {
                0x3B => return Some(false),
                0x21 => {
                    let label = *b.get(i + 1)?;
                    match label {
                        0xFE => return Some(true),
                        0xFF => {
                            let n = *b.get(i + 2)? as usize;
                            let id = b.get(i + 3..i + 3 + n)?;
                            if id != b"NETSCAPE2.0" && id != b"ANIMEXTS1.0" {
                                return Some(true);
                            }
                            i = skip_sub_blocks(b, i + 3 + n)?;
                        }
                        _ => {
                            let n = *b.get(i + 2)? as usize;
                            i = skip_sub_blocks(b, i + 3 + n)?;
                        }
                    }
                }
                0x2C => {
                    let f = *b.get(i + 9)?;
                    i += 10
                        + if f & 0x80 != 0 {
                            3 * (1usize << ((f & 7) + 1))
                        } else {
                            0
                        };
                    i = skip_sub_blocks(b, i + 1)?; // LZW minimum code size, then data
                }
                _ => return None,
            }
        }
    };
    walk().unwrap_or(true)
}

/// One stored object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredObject {
    /// Object name in the zone container.
    pub name: String,
    /// Media type served.
    pub mime: String,
    /// Size in bytes.
    pub bytes: u64,
    /// SHA-256 of the stored bytes.
    pub sha256: String,
    /// File under `media/` holding the bytes.
    pub file: String,
}

/// Processing outcome of one source image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaEntry {
    /// `ok` or `failed`.
    pub status: String,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Sniffed type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_type: Option<ImageType>,
    /// Earliest message time that posted it.
    pub first_seen: u64,
    /// EXIF `DateTimeOriginal` (camera-local, `YYYY-MM-DDTHH:MM:SS`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exif_date_time_original: Option<String>,
    /// Original file name as first posted.
    pub filename: String,
    /// The main object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<StoredObject>,
    /// The thumbnail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumb: Option<StoredObject>,
}

/// `media/manifest.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaManifest {
    /// Always 1.
    pub version: u32,
    /// Source SHA-256 → entry.
    pub objects: BTreeMap<String, MediaEntry>,
}

impl MediaManifest {
    /// Load `media/manifest.json` from the media directory (missing: empty).
    pub fn load(media_dir: &Path) -> Result<Self, ImportError> {
        let p = media_dir.join("manifest.json");
        match std::fs::read(&p) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| ImportError::Format(format!("{}: {e}", p.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MediaManifest {
                version: 1,
                objects: BTreeMap::new(),
            }),
            Err(e) => Err(ImportError::io(&p, e)),
        }
    }

    /// Save atomically (0600).
    pub fn save(&self, media_dir: &Path) -> Result<(), ImportError> {
        fsutil::create_private_dir(media_dir)?;
        fsutil::write_private_atomic(
            &media_dir.join("manifest.json"),
            &serde_json::to_vec_pretty(self).expect("manifest serialises"),
        )
    }

    /// The main object of a processed image.
    pub fn main_of(&self, sha: &str) -> Option<&StoredObject> {
        self.objects
            .get(sha)
            .filter(|e| e.status == "ok")
            .and_then(|e| e.main.as_ref())
    }

    /// Total stored bytes (main + thumbnail) of the given source hashes.
    pub fn stored_bytes<'a>(&self, shas: impl IntoIterator<Item = &'a str>) -> u64 {
        shas.into_iter()
            .filter_map(|s| self.objects.get(s))
            .filter(|e| e.status == "ok")
            .map(|e| {
                e.main.as_ref().map_or(0, |o| o.bytes) + e.thumb.as_ref().map_or(0, |o| o.bytes)
            })
            .sum()
    }
}

/// EXIF `2024:05:17 14:03:22` → `2024-05-17T14:03:22`.
pub fn parse_exif_date(s: &str) -> Option<String> {
    let t = s.trim();
    let b = t.as_bytes();
    if b.len() < 19
        || b[4] != b':'
        || b[7] != b':'
        || !(b[10] == b' ' || b[10] == b'T')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| {
        t.get(r.clone())
            .filter(|x| x.bytes().all(|c| c.is_ascii_digit()))
    };
    Some(format!(
        "{}-{}-{}T{}:{}:{}",
        digits(0..4)?,
        digits(5..7)?,
        digits(8..10)?,
        digits(11..13)?,
        digits(14..16)?,
        digits(17..19)?
    ))
}

/// Runs ImageMagick under [`POLICY_XML`].
#[derive(Debug, Clone)]
pub struct Magick {
    binary: PathBuf,
    policy_dir: PathBuf,
}

impl Magick {
    /// Prepare the policy directory under `work` and check `magick` runs.
    pub fn new(binary: &Path, work: &Path) -> Result<Self, ImportError> {
        let policy_dir = work.join("magick-policy");
        fsutil::create_private_dir(&policy_dir)?;
        fsutil::write_private_atomic(&policy_dir.join("policy.xml"), POLICY_XML.as_bytes())?;
        let m = Magick {
            binary: binary.to_path_buf(),
            policy_dir,
        };
        let out = m
            .cmd()
            .arg("-version")
            .output()
            .map_err(|e| ImportError::Tool(format!("{}: {e}", binary.display())))?;
        if !out.status.success() {
            return Err(ImportError::Tool(format!(
                "{} -version failed",
                binary.display()
            )));
        }
        Ok(m)
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.binary);
        c.env("MAGICK_CONFIGURE_PATH", &self.policy_dir)
            .env("MAGICK_THREAD_LIMIT", "2")
            .env_remove("MAGICK_CODER_MODULE_PATH")
            .env_remove("MAGICK_CODER_FILTER_PATH")
            .stdin(std::process::Stdio::null());
        c
    }

    fn run(&self, args: &[String]) -> Result<Vec<u8>, ImportError> {
        let out = self
            .cmd()
            .args(args)
            .output()
            .map_err(|e| ImportError::Tool(format!("magick: {e}")))?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            return Err(ImportError::Tool(
                msg.lines()
                    .next()
                    .unwrap_or("magick failed")
                    .chars()
                    .take(200)
                    .collect(),
            ));
        }
        Ok(out.stdout)
    }

    /// Process one image into `dir` (`main.webp|main.gif`, `thumb.webp`).
    pub fn process(
        &self,
        src: &Path,
        ty: ImageType,
        dir: &Path,
    ) -> Result<(PathBuf, PathBuf, Option<String>), ImportError> {
        let input = |frame0: bool| {
            format!(
                "{}:{}{}",
                ty.coder(),
                src.display(),
                if frame0 { "[0]" } else { "" }
            )
        };
        let exif = self
            .run(&[
                input(true),
                "-format".into(),
                "%[EXIF:DateTimeOriginal]".into(),
                "info:".into(),
            ])
            .ok()
            .and_then(|o| parse_exif_date(&String::from_utf8_lossy(&o)));
        let thumb = dir.join("thumb.webp");
        let main = if ty == ImageType::Gif {
            let main = dir.join("main.gif");
            self.run(&[
                input(false),
                "-strip".into(),
                format!("gif:{}", main.display()),
            ])?;
            main
        } else {
            let main = dir.join("main.webp");
            self.run(&[
                input(true),
                "-auto-orient".into(),
                "-strip".into(),
                "-resize".into(),
                format!("{MAX_EDGE}x{MAX_EDGE}>"),
                "-quality".into(),
                "82".into(),
                "-define".into(),
                "webp:method=4".into(),
                format!("webp:{}", main.display()),
            ])?;
            main
        };
        self.run(&[
            input(true),
            "-auto-orient".into(),
            "-strip".into(),
            "-thumbnail".into(),
            format!("{THUMB_EDGE}x{THUMB_EDGE}>"),
            "-quality".into(),
            "75".into(),
            format!("webp:{}", thumb.display()),
        ])?;
        Ok((main, thumb, exif))
    }
}

/// What [`process_archive`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MediaReport {
    /// Distinct source images.
    pub images: usize,
    /// Processed now.
    pub processed: usize,
    /// Already in the manifest.
    pub reused: usize,
    /// Failed (never uploaded).
    pub failed: usize,
}

/// Process every `ok` image attachment of `archive` into `media_dir`,
/// resumably (entries already `ok` are kept; failures are retried).
pub fn process_archive(
    archive: &Archive,
    magick: &Magick,
    media_dir: &Path,
) -> Result<(MediaManifest, MediaReport), ImportError> {
    fsutil::create_private_dir(media_dir)?;
    let mut manifest = MediaManifest::load(media_dir)?;
    manifest.version = 1;
    let mut report = MediaReport::default();
    let mut todo: BTreeMap<String, (&crate::format::Attachment, u64)> = BTreeMap::new();
    for m in &archive.messages {
        for a in &m.attachments {
            if a.status != AttachmentStatus::Ok
                || !a.mime.to_ascii_lowercase().starts_with("image/")
            {
                continue;
            }
            if let Some(sha) = &a.sha256 {
                let e = todo.entry(sha.clone()).or_insert((a, m.created_at));
                e.1 = e.1.min(m.created_at);
            }
        }
    }
    report.images = todo.len();
    let seen: BTreeSet<String> = todo.keys().cloned().collect();
    for (n, (sha, (att, first))) in todo.into_iter().enumerate() {
        if let Some(e) = manifest.objects.get_mut(&sha) {
            e.first_seen = e.first_seen.min(first);
            if e.status == "ok" {
                report.reused += 1;
                continue;
            }
        }
        let entry = process_one(archive, magick, media_dir, &sha, att, first);
        if entry.status == "ok" {
            report.processed += 1;
        } else {
            report.failed += 1;
        }
        manifest.objects.insert(sha, entry);
        if n % 50 == 49 {
            manifest.save(media_dir)?;
        }
    }
    manifest.objects.retain(|k, _| seen.contains(k));
    manifest.save(media_dir)?;
    Ok((manifest, report))
}

fn process_one(
    archive: &Archive,
    magick: &Magick,
    media_dir: &Path,
    sha: &str,
    att: &crate::format::Attachment,
    first: u64,
) -> MediaEntry {
    let mut entry = MediaEntry {
        status: "failed".into(),
        reason: None,
        image_type: None,
        first_seen: first,
        exif_date_time_original: None,
        filename: att.filename.clone(),
        main: None,
        thumb: None,
    };
    let res = (|| -> Result<(), ImportError> {
        let src = archive.attachment_file(att)?;
        let mut head = [0u8; 32];
        let n = {
            use std::io::Read;
            let mut f = std::fs::File::open(&src).map_err(|e| ImportError::io(&src, e))?;
            f.read(&mut head).map_err(|e| ImportError::io(&src, e))?
        };
        let ty = sniff(&head[..n]).ok_or_else(|| {
            ImportError::Refused("not a supported raster image (magic bytes)".into())
        })?;
        entry.image_type = Some(ty);
        let dir = media_dir.join(&sha[..2]).join(sha);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| ImportError::io(&dir, e))?;
        }
        fsutil::create_private_dir(&dir)?;
        let (main, thumb, exif) = magick.process(&src, ty, &dir)?;
        entry.exif_date_time_original = exif;
        let stamp = sha;
        let mut objects = Vec::new();
        for (path, name, mime, is_gif) in [
            (
                &main,
                format!(
                    "{stamp}.{}",
                    if ty == ImageType::Gif { "gif" } else { "webp" }
                ),
                if ty == ImageType::Gif {
                    "image/gif"
                } else {
                    "image/webp"
                },
                ty == ImageType::Gif,
            ),
            (&thumb, format!("{stamp}_thumb.webp"), "image/webp", false),
        ] {
            let bytes = std::fs::read(path).map_err(|e| ImportError::io(path, e))?;
            let dirty = if is_gif {
                gif_has_metadata(&bytes)
            } else {
                webp_has_metadata(&bytes)
            };
            if dirty {
                return Err(ImportError::Refused("output still carries metadata".into()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            let rel = path
                .strip_prefix(media_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned();
            objects.push(StoredObject {
                name,
                mime: mime.into(),
                bytes: bytes.len() as u64,
                sha256: fsutil::sha256_hex(&bytes),
                file: rel,
            });
        }
        entry.thumb = objects.pop();
        entry.main = objects.pop();
        Ok(())
    })();
    match res {
        Ok(()) => entry.status = "ok".into(),
        Err(e) => {
            entry.reason = Some(e.to_string().chars().take(200).collect());
            entry.main = None;
            entry.thumb = None;
        }
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing_ignores_names_and_refuses_scripts() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\nxxxx"), Some(ImageType::Png));
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Some(ImageType::Jpeg));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some(ImageType::Webp));
        assert_eq!(sniff(b"\0\0\0\x18ftypheic"), Some(ImageType::Heic));
        assert_eq!(sniff(b"<svg xmlns="), None);
        assert_eq!(sniff(b"%!PS-Adobe"), None);
        assert_eq!(sniff(b"%PDF-1.7"), None);
    }

    #[test]
    fn webp_metadata_scan() {
        let mut w = b"RIFF\0\0\0\0WEBP".to_vec();
        w.extend_from_slice(b"VP8 \x02\0\0\0ab");
        assert!(!webp_has_metadata(&w));
        w.extend_from_slice(b"EXIF\x01\0\0\0x\0");
        assert!(webp_has_metadata(&w));
        assert!(webp_has_metadata(b"not webp"));
    }

    #[test]
    fn gif_metadata_walk() {
        // 1x1 GIF89a: header, screen descriptor (no table), image, trailer.
        let mut g = b"GIF89a\x01\0\x01\0\0\0\0".to_vec();
        let image = [0x2Cu8, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 0x01, 0];
        let mut clean = g.clone();
        clean.extend_from_slice(&image);
        clean.push(0x3B);
        assert!(!gif_has_metadata(&clean));
        g.extend_from_slice(&[0x21, 0xFE, 3, b'h', b'i', b'!', 0]);
        g.extend_from_slice(&image);
        g.push(0x3B);
        assert!(gif_has_metadata(&g));
        assert!(gif_has_metadata(b"GIF89a"));
    }

    #[test]
    fn exif_dates() {
        assert_eq!(
            parse_exif_date("2024:05:17 14:03:22\n").as_deref(),
            Some("2024-05-17T14:03:22")
        );
        assert_eq!(parse_exif_date(""), None);
        assert_eq!(parse_exif_date("2024:05:17"), None);
    }
}
