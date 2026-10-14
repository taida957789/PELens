//! Look & feel: dark / light palettes, compact list-view spacing and system fonts.

use crate::i18n::Lang;
use egui::{Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, FontTweak, Stroke, TextStyle};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Colours used by the custom drawing (tree, table headers, flags, links).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub dark: bool,
    pub panel: Color32,
    pub central: Color32,
    pub header: Color32,
    pub grid: Color32,
    pub stripe: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub flag: Color32,
    pub jump: Color32,
    pub link: Color32,
    pub accent: Color32,
    pub selection: Color32,
    pub tree_line: Color32,
}

impl Palette {
    pub fn dark() -> Self {
        Palette {
            dark: true,
            panel: Color32::from_rgb(30, 31, 34),
            central: Color32::from_rgb(37, 38, 42),
            header: Color32::from_rgb(48, 50, 56),
            grid: Color32::from_rgb(58, 60, 66),
            stripe: Color32::from_rgb(42, 43, 48),
            text: Color32::from_rgb(220, 222, 226),
            muted: Color32::from_rgb(140, 145, 155),
            flag: Color32::from_rgb(255, 107, 107),
            jump: Color32::from_rgb(138, 180, 248),
            link: Color32::from_rgb(120, 170, 235),
            accent: Color32::from_rgb(86, 156, 214),
            selection: Color32::from_rgb(38, 79, 120),
            tree_line: Color32::from_rgb(80, 83, 90),
        }
    }

    pub fn light() -> Self {
        Palette {
            dark: false,
            panel: Color32::from_rgb(243, 243, 243),
            central: Color32::from_rgb(255, 255, 255),
            header: Color32::from_rgb(232, 234, 237),
            grid: Color32::from_rgb(214, 216, 220),
            stripe: Color32::from_rgb(247, 248, 250),
            text: Color32::from_rgb(30, 30, 30),
            muted: Color32::from_rgb(110, 110, 118),
            flag: Color32::from_rgb(168, 0, 0),
            jump: Color32::from_rgb(0, 0, 149),
            link: Color32::from_rgb(0, 84, 166),
            accent: Color32::from_rgb(0, 120, 215),
            selection: Color32::from_rgb(204, 228, 247),
            tree_line: Color32::from_rgb(190, 190, 196),
        }
    }

    pub fn for_mode(dark: bool) -> Self {
        if dark { Self::dark() } else { Self::light() }
    }
}

/// Apply visuals and spacing for a palette (cheap; only call when the mode changes).
pub fn apply(ctx: &egui::Context, p: &Palette) {
    let mut v = if p.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = p.panel;
    v.window_fill = p.central;
    v.extreme_bg_color = if p.dark { Color32::from_rgb(26, 27, 30) } else { Color32::WHITE };
    v.faint_bg_color = p.stripe;
    v.selection.bg_fill = p.selection;
    v.selection.stroke = Stroke::new(1.0, p.text);
    v.hyperlink_color = p.link;
    v.override_text_color = Some(p.text);
    v.window_corner_radius = CornerRadius::same(6);
    v.menu_corner_radius = CornerRadius::same(4);
    for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        w.corner_radius = CornerRadius::same(3);
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.grid);
    v.striped = true;
    let theme = if p.dark { egui::Theme::Dark } else { egui::Theme::Light };
    ctx.set_theme(theme);
    ctx.set_visuals_of(theme, v);
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(6.0, 3.0);
        s.spacing.button_padding = egui::vec2(7.0, 2.0);
        s.spacing.menu_margin = egui::Margin::same(6);
        s.spacing.interact_size.y = 20.0;
        s.text_styles = [
            (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
            (TextStyle::Heading, FontId::new(17.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into();
    });
}

/// Candidate font files: (family, files tried in order). CJK fonts are used as fallbacks so that
/// Chinese/Japanese/Korean text (interface and sample strings) renders instead of showing boxes.
/// The interface language picks the first CJK font (its glyph shapes win); Malgun Gothic is
/// always added for Hangul, which the Chinese and Japanese fonts lack.
pub fn font_candidates(fonts_dir: &Path, lang: Lang) -> Vec<(FontFamily, Vec<PathBuf>)> {
    let f = |n: &str| fonts_dir.join(n);
    let cjk = |files: &[&str]| files.iter().map(|n| f(n)).collect::<Vec<_>>();
    let primary = match lang {
        Lang::ZhCn => cjk(&["msyh.ttc", "msjh.ttc"]),
        Lang::Ja => cjk(&["YuGothR.ttc", "meiryo.ttc", "msgothic.ttc", "msjh.ttc"]),
        Lang::Ko => cjk(&["malgun.ttf", "msjh.ttc"]),
        _ => cjk(&["msjh.ttc", "msyh.ttc", "YuGothR.ttc"]),
    };
    let mut v = vec![
        (FontFamily::Proportional, vec![f("segoeui.ttf"), f("arial.ttf")]),
        (FontFamily::Monospace, vec![f("consola.ttf"), f("cour.ttf")]),
        // fallbacks shared by both families, in this order
        (FontFamily::Name("cjk".into()), primary),
        (FontFamily::Name("hangul".into()), vec![f("malgun.ttf")]),
    ];
    if lang == Lang::Ko {
        // Hanja: Malgun Gothic has none
        v[3] = (FontFamily::Name("hanja".into()), vec![f("msjh.ttc"), f("msyh.ttc")]);
    }
    v
}

/// Build font definitions from system fonts, keeping egui's built-in fonts (emoji icons) as fallbacks.
/// Returns the definitions and the names of the fonts that were loaded.
pub fn font_definitions(fonts_dir: &Path, lang: Lang) -> (FontDefinitions, Vec<String>) {
    let mut defs = FontDefinitions::default();
    let mut loaded: Vec<String> = Vec::new();
    let mut fallbacks: Vec<String> = Vec::new();
    // vertical metrics of the main interface font, to align the fallbacks on it
    let mut primary: Option<(f32, f32)> = None;
    for (family, files) in font_candidates(fonts_dir, lang) {
        let Some(path) = files.iter().find(|p| p.is_file()) else { continue };
        let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        if !loaded.contains(&name) {
            let Ok(bytes) = std::fs::read(path) else { continue };
            let mut data = FontData::from_owned(bytes);
            match (&family, primary) {
                (FontFamily::Proportional, _) => primary = em_metrics(&data.font),
                (FontFamily::Name(_), Some(pm)) => {
                    let dy = em_metrics(&data.font).map(|fm| baseline_offset(pm, fm)).unwrap_or(0.0);
                    if dy.abs() > 0.02 {
                        data = data.tweak(FontTweak { y_offset_factor: dy, ..Default::default() });
                    }
                }
                _ => {}
            }
            defs.font_data.insert(name.clone(), Arc::new(data));
            loaded.push(name.clone());
        }
        match family {
            FontFamily::Name(_) => {
                if !fallbacks.contains(&name) {
                    fallbacks.push(name)
                }
            }
            fam => defs.families.entry(fam).or_default().insert(0, name),
        }
    }
    for fam in [FontFamily::Proportional, FontFamily::Monospace] {
        let list = defs.families.entry(fam).or_default();
        // after the primary font, before egui's emoji fonts
        let pos = list.len().min(1);
        for (i, c) in fallbacks.iter().enumerate() {
            list.insert(pos + i, c.clone());
        }
    }
    (defs, loaded)
}

/// (ascent, row height) in em, from the metrics epaint uses (skrifa, default location).
pub fn em_metrics(font: &[u8]) -> Option<(f32, f32)> {
    use skrifa::MetadataProvider;
    let f = skrifa::FontRef::from_index(font, 0).ok()?;
    let m = f.metrics(skrifa::instance::Size::unscaled(), skrifa::instance::LocationRef::default());
    let upem = f32::from(m.units_per_em);
    (upem > 0.0).then(|| (m.ascent / upem, (m.ascent - m.descent + m.leading) / upem))
}

/// Downward shift (in em) that puts a fallback font's baseline on the primary font's baseline.
/// epaint centres a fallback glyph on the row by the difference of the two row heights, so a
/// font with a small ascent and a large line gap (Yu Gothic, MS Gothic) would sit too high.
pub fn baseline_offset(primary: (f32, f32), fallback: (f32, f32)) -> f32 {
    primary.0 - (fallback.0 + 0.5 * (primary.1 - fallback.1))
}

pub fn windows_fonts_dir() -> PathBuf {
    std::env::var_os("WINDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows")).join("Fonts")
}

pub fn install_fonts(ctx: &egui::Context, lang: Lang) -> Vec<String> {
    let (defs, loaded) = font_definitions(&windows_fonts_dir(), lang);
    ctx.set_fonts(defs);
    loaded
}

/// Columns rendered with the monospace font (hashes, offsets, hex dumps).
pub fn is_mono_column(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "md5",
        "sha",
        "hash",
        "footprint",
        "address",
        "offset",
        "first-bytes",
        "raw-",
        "virtual-",
        "characteristics",
        "thunk",
        "ordinal",
        "rva",
        "size",
        "entropy",
        "file-ratio",
        "id",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// Icon glyph (from egui's bundled emoji font) for a tree node.
pub fn icon(item: pe_analysis::model::ItemType) -> &'static str {
    use pe_analysis::model::ItemType::*;
    match item {
        Image => "🖹",
        Footprints => "🔑",
        Groups => "📊",
        Indicators => "⚠",
        Mitre => "🎯",
        Score => "🛡",
        DosStub | DosHeader | RichHeader | FileHeader | OptionalHeader => "📑",
        Directories => "📁",
        Sections => "📦",
        Libraries => "📚",
        Imports => "⬇",
        Exports => "⬆",
        Exceptions => "⚡",
        Certificate => "🔏",
        Relocations => "↔",
        Tls => "⏱",
        DotNet => "🔷",
        Resources => "🖼",
        Version => "🏷",
        Debug => "🐞",
        Strings => "🔤",
        Manifest => "📜",
        Overlay => "📎",
        Yara => "🔍",
    }
}

/// Initial column width estimated from the header and a sample of cells (egui's auto sizing
/// only measures the rows visible in the first frame).
pub fn estimate_width(header: &str, cells: impl Iterator<Item = usize>, mono: bool) -> f32 {
    let per_char = if mono { 7.4 } else { 7.0 };
    let longest = cells.take(300).max().unwrap_or(0).max(header.chars().count() + 2);
    (longest as f32 * per_char + 18.0).clamp(44.0, 520.0)
}
