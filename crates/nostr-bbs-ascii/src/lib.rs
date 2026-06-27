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
/// Server-side only (preview/pod workers). Returns [`AsciiError`] on an
/// unsupported/corrupt image or one exceeding [`MAX_PIXELS`].
#[cfg(feature = "decode")]
pub fn render_bytes(bytes: &[u8], opts: &RenderOptions) -> Result<AsciiArt, AsciiError> {
    use image::GenericImageView as _;

    let img = image::load_from_memory(bytes).map_err(|_| AsciiError::Decode)?;
    let (w, h) = img.dimensions();
    if (w as u64) * (h as u64) > MAX_PIXELS {
        return Err(AsciiError::TooLarge);
    }
    let luma = img.to_luma8();
    Ok(render_luma(luma.as_raw(), w, h, opts))
}

/// Upper bound on decoded image area (megapixels) accepted by [`render_bytes`]
/// — a guard against decompression-bomb inputs within the worker's CPU budget.
#[cfg(feature = "decode")]
pub const MAX_PIXELS: u64 = 24_000_000;

/// Failure modes of [`render_bytes`].
#[cfg(feature = "decode")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsciiError {
    /// The bytes were not a decodable image in a supported format.
    Decode,
    /// The decoded image exceeded [`MAX_PIXELS`].
    TooLarge,
}

#[cfg(feature = "decode")]
impl core::fmt::Display for AsciiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AsciiError::Decode => f.write_str("unsupported or corrupt image"),
            AsciiError::TooLarge => f.write_str("image exceeds maximum pixel budget"),
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
