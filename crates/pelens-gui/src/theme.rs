//! Look & feel: dark / light palettes, compact list-view spacing and system fonts.

use crate::i18n::Lang;
use egui::{Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, FontTweak, Stroke, TextStyle};
use std::path::PathBuf;
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

/// Candidate font files per family, by file name, tried in order. CJK fonts are fallbacks so
/// that Chinese/Japanese/Korean text (interface and sample strings) renders instead of boxes.
/// The interface language picks the first CJK font (its glyph shapes win); a Hangul font is
/// always added, the Chinese and Japanese fonts lack Hangul.
pub fn font_candidates(lang: Lang) -> Vec<(FontFamily, Vec<&'static str>)> {
    let (prop, mono, cjk, hangul, hanja) = platform_fonts(lang);
    let mut v = vec![(FontFamily::Proportional, prop), (FontFamily::Monospace, mono), (FontFamily::Name("cjk".into()), cjk)];
    if lang == Lang::Ko {
        v.push((FontFamily::Name("hanja".into()), hanja));
    } else {
        v.push((FontFamily::Name("hangul".into()), hangul));
    }
    v
}

type FontLists = (Vec<&'static str>, Vec<&'static str>, Vec<&'static str>, Vec<&'static str>, Vec<&'static str>);

/// (proportional, monospace, CJK for the language, Hangul, Hanja) font files of the platform.
#[cfg(windows)]
fn platform_fonts(lang: Lang) -> FontLists {
    let cjk = match lang {
        Lang::ZhCn => vec!["msyh.ttc", "msjh.ttc"],
        Lang::Ja => vec!["YuGothR.ttc", "meiryo.ttc", "msgothic.ttc", "msjh.ttc"],
        Lang::Ko => vec!["malgun.ttf", "msjh.ttc"],
        _ => vec!["msjh.ttc", "msyh.ttc", "YuGothR.ttc"],
    };
    (vec!["segoeui.ttf", "arial.ttf"], vec!["consola.ttf", "cour.ttf"], cjk, vec!["malgun.ttf"], vec!["msjh.ttc", "msyh.ttc"])
}

#[cfg(target_os = "macos")]
fn platform_fonts(lang: Lang) -> FontLists {
    let cjk = match lang {
        Lang::Ja => vec!["ヒラギノ角ゴシック W3.ttc", "Hiragino Sans GB.ttc", "PingFang.ttc", "STHeiti Light.ttc"],
        Lang::Ko => vec!["AppleSDGothicNeo.ttc", "PingFang.ttc"],
        Lang::ZhCn => vec!["PingFang.ttc", "Hiragino Sans GB.ttc", "STHeiti Light.ttc"],
        _ => vec!["PingFang.ttc", "STHeiti Light.ttc", "Hiragino Sans GB.ttc"],
    };
    (
        vec!["SFNS.ttf", "SFNSText.ttf", "HelveticaNeue.ttc", "Helvetica.ttc", "Arial.ttf"],
        vec!["SFNSMono.ttf", "Menlo.ttc", "Monaco.ttf", "Courier New.ttf"],
        cjk,
        vec!["AppleSDGothicNeo.ttc"],
        vec!["PingFang.ttc", "STHeiti Light.ttc"],
    )
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_fonts(lang: Lang) -> FontLists {
    const TC: [&str; 3] = ["NotoSansCJKtc-Regular.otf", "NotoSansTC-Regular.otf", "NotoSansCJKtc-Regular.ttc"];
    const SC: [&str; 3] = ["NotoSansCJKsc-Regular.otf", "NotoSansSC-Regular.otf", "NotoSansCJKsc-Regular.ttc"];
    const JP: [&str; 3] = ["NotoSansCJKjp-Regular.otf", "NotoSansJP-Regular.otf", "NotoSansCJKjp-Regular.ttc"];
    const KR: [&str; 4] = ["NotoSansCJKkr-Regular.otf", "NotoSansKR-Regular.otf", "NotoSansCJKkr-Regular.ttc", "NanumGothic.ttf"];
    // the multi-language collections and the common fallbacks of the distributions
    const ANY: [&str; 5] =
        ["NotoSansCJK-Regular.ttc", "wqy-microhei.ttc", "wqy-zenhei.ttc", "DroidSansFallbackFull.ttf", "DroidSansFallback.ttf"];
    let order: Vec<&[&'static str]> = match lang {
        Lang::ZhCn => vec![&SC, &TC, &ANY],
        Lang::Ja => vec![&JP, &ANY, &TC],
        Lang::Ko => vec![&KR, &ANY],
        _ => vec![&TC, &SC, &ANY],
    };
    (
        vec![
            "NotoSans-Regular.ttf",
            "DejaVuSans.ttf",
            "LiberationSans-Regular.ttf",
            "Ubuntu-R.ttf",
            "Cantarell-Regular.otf",
            "FreeSans.ttf",
        ],
        vec!["NotoSansMono-Regular.ttf", "DejaVuSansMono.ttf", "LiberationMono-Regular.ttf", "UbuntuMono-R.ttf", "FreeMono.ttf"],
        order.concat(),
        [&KR[..], &ANY[..]].concat(),
        [&TC[..], &SC[..], &ANY[..]].concat(),
    )
}

/// Folders holding the fonts of the platform (searched recursively).
pub fn font_dirs() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut v: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        v.push(std::env::var_os("WINDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows")).join("Fonts"));
        if let Some(l) = std::env::var_os("LOCALAPPDATA") {
            v.push(PathBuf::from(l).join("Microsoft").join("Windows").join("Fonts"));
        }
    } else if cfg!(target_os = "macos") {
        v.extend(["/System/Library/Fonts", "/Library/Fonts", "/System/Library/AssetsV2"].map(PathBuf::from));
        v.extend(home.map(|h| h.join("Library/Fonts")));
    } else {
        let data = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
        v.extend(data.split(':').filter(|d| !d.is_empty()).map(|d| PathBuf::from(d).join("fonts")));
        if let Some(h) = home {
            v.push(h.join(".local/share/fonts"));
            v.push(h.join(".fonts"));
        }
    }
    v
}

/// Font files under `dirs` by lower-case file name (first found wins).
pub fn index_fonts(dirs: &[PathBuf]) -> std::collections::HashMap<String, PathBuf> {
    let mut out = std::collections::HashMap::new();
    let mut stack: Vec<(PathBuf, usize)> = dirs.iter().map(|d| (d.clone(), 0)).collect();
    let mut seen = 0usize;
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > 200_000 {
                return out;
            }
            let p = e.path();
            if p.is_dir() {
                if depth < 8 {
                    stack.push((p, depth + 1));
                }
            } else if let Some(name) = p.file_name().map(|n| n.to_string_lossy().to_lowercase())
                && (name.ends_with(".ttf") || name.ends_with(".ttc") || name.ends_with(".otf"))
            {
                out.entry(name).or_insert(p);
            }
        }
    }
    out
}

/// Build font definitions from the fonts found under `dirs`, keeping egui's built-in fonts (emoji
/// icons, and the text fonts when nothing is found) as fallbacks. Returns the definitions and the
/// names of the fonts that were loaded.
pub fn font_definitions(dirs: &[PathBuf], lang: Lang) -> (FontDefinitions, Vec<String>) {
    let index = index_fonts(dirs);
    let mut defs = FontDefinitions::default();
    let mut loaded: Vec<String> = Vec::new();
    let mut fallbacks: Vec<String> = Vec::new();
    // vertical metrics of the main interface font, to align the fallbacks on it
    let mut primary: Option<(f32, f32)> = None;
    for (family, files) in font_candidates(lang) {
        let Some(path) = files.iter().find_map(|f| index.get(&f.to_lowercase())) else { continue };
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

pub fn install_fonts(ctx: &egui::Context, lang: Lang) -> Vec<String> {
    let (defs, loaded) = font_definitions(&font_dirs(), lang);
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
        Disassembly => "🔧",
    }
}

/// Initial column width estimated from the header and a sample of cells (egui's auto sizing
/// only measures the rows visible in the first frame).
pub fn estimate_width(header: &str, cells: impl Iterator<Item = usize>, mono: bool) -> f32 {
    let per_char = if mono { 7.4 } else { 7.0 };
    let longest = cells.take(300).max().unwrap_or(0).max(header.chars().count() + 2);
    (longest as f32 * per_char + 18.0).clamp(44.0, 520.0)
}
