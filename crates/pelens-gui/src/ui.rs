//! egui rendering of the pestudio main window: toolbar, tree-view, list-view, dialogs.

use crate::i18n::{self, Lang};
use crate::model::*;
use crate::theme::{self, Palette};
use egui::{Align, Color32, FontId, Key, Layout, Modifiers, RichText, Sense, Stroke, TextStyle};
use egui_extras::{Column, TableBuilder};
use pe_analysis::model::ItemType;
use pe_analysis::view::Table;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Default)]
pub struct RfdHost {
    pub lang: Lang,
}

impl Host for RfdHost {
    fn pick_open(&mut self) -> Option<std::path::PathBuf> {
        let t = |k| i18n::translate(self.lang, k);
        rfd::FileDialog::new()
            .set_title(t("Select file to open"))
            .add_filter(t("Exe files (*.exe)"), &["exe"])
            .add_filter(t("Dll files (*.dll)"), &["dll"])
            .add_filter(t("Sys files (*.sys)"), &["sys"])
            .add_filter(t("All Files (*.*)"), &["*"])
            .pick_file()
    }

    fn pick_save(&mut self, default_name: &str, filter: (&str, &[&str])) -> Option<std::path::PathBuf> {
        let t = |k| i18n::translate(self.lang, k);
        rfd::FileDialog::new()
            .set_title(t("save to file"))
            .set_file_name(default_name)
            .add_filter(filter.0, filter.1)
            .add_filter(t("All Files (*.*)"), &["*"])
            .save_file()
    }

    fn set_lang(&mut self, lang: Lang) {
        self.lang = lang;
    }
}

const TREE_ROW: f32 = 21.0;
const TREE_INDENT: f32 = 16.0;
const ROW_H: f32 = 20.0;
/// Settings with more choices than this use a drop-down list.
const COMBO_CHOICES: usize = 6;

type LocationMap = Vec<(String, usize, (u8, u8, u8))>;

pub struct PeLensApp {
    pub state: State,
    pub host: Box<dyn Host>,
    /// Actions collected while drawing, applied after the frame.
    pending: Vec<Action>,
    settings_tab: &'static str,
    key_buffer: String,
    pub watchdog_every: std::time::Duration,
    /// Set once the window was asked to close.
    pub exit_requested: bool,
    pub palette: Palette,
    applied_dark: Option<bool>,
    /// Load Segoe UI / Consolas / CJK fonts from the Windows font folder on the first frame.
    pub load_system_fonts: bool,
    pub fonts_loaded: Vec<String>,
    /// Language the fonts were installed for (the CJK fallback order depends on it).
    fonts_lang: Option<Lang>,
    /// Expanded tree nodes ("root" and view names).
    pub expanded: HashSet<String>,
    loc_cache: Option<(std::path::PathBuf, u64, Arc<LocationMap>)>,
    res_cache: Option<(std::path::PathBuf, u64, usize, Arc<Vec<String>>)>,
}

fn rgb(c: (u8, u8, u8)) -> Color32 {
    Color32::from_rgb(c.0, c.1, c.2)
}

impl PeLensApp {
    pub fn new(state: State, host: Box<dyn Host>) -> Self {
        let key_buffer = state.knowledge.settings.get("score", "key").unwrap_or("").to_string();
        let palette = Palette::for_mode(state.dark_mode());
        let mut expanded = HashSet::new();
        expanded.insert("root".to_string());
        PeLensApp {
            state,
            host,
            pending: Vec::new(),
            settings_tab: "General",
            key_buffer,
            watchdog_every: std::time::Duration::from_secs(30),
            exit_requested: false,
            palette,
            applied_dark: None,
            load_system_fonts: true,
            fonts_loaded: Vec::new(),
            fonts_lang: None,
            expanded,
            loc_cache: None,
            res_cache: None,
        }
    }

    pub fn push(&mut self, a: Action) {
        self.pending.push(a);
    }

    /// Colour for flagged items: the settings colour in light mode, a readable variant in dark mode.
    fn flag_color(&self) -> Color32 {
        if self.palette.dark { self.palette.flag } else { self.color_setting("flags", "color_text", self.palette.flag) }
    }

    fn color_setting(&self, elem: &str, attr: &str, def: Color32) -> Color32 {
        let k = &self.state.knowledge;
        k.settings.get(elem, attr).and_then(|v| v.parse::<u8>().ok()).and_then(|id| k.settings.color(id)).map(rgb).unwrap_or(def)
    }

    fn sync_theme(&mut self, ctx: &egui::Context) {
        let lang = self.state.lang;
        if self.load_system_fonts && self.fonts_lang != Some(lang) {
            self.fonts_loaded = theme::install_fonts(ctx, lang);
            if self.fonts_loaded.is_empty() {
                self.fonts_loaded.push("egui-default".into());
            }
            self.fonts_lang = Some(lang);
        }
        let dark = self.state.dark_mode();
        if self.applied_dark != Some(dark) {
            self.palette = Palette::for_mode(dark);
            theme::apply(ctx, &self.palette);
            self.applied_dark = Some(dark);
        }
    }

    /// Draw one frame. Called by eframe and by the headless tests.
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.sync_theme(&ctx);
        self.host.set_lang(self.state.lang);
        // background jobs
        if self.state.poll() {
            ctx.request_repaint();
        }
        self.state.watchdog(std::time::Instant::now(), self.watchdog_every);
        if self.state.busy.is_some() || self.state.score_rx.is_some() || self.state.update_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        // drag & drop
        let dropped: Vec<std::path::PathBuf> =
            ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
        if let Some(p) = dropped.into_iter().next() {
            self.push(Action::Open(p));
        }
        self.shortcuts(&ctx);

        let p = self.palette;
        egui::Panel::top("menu").frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(6, 2))).show(ui, |ui| {
            self.menu(ui);
            self.toolbar(ui);
        });
        egui::Panel::bottom("status")
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(8, 3)))
            .show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("tree")
            .resizable(true)
            .default_size(250.0)
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(4, 6)))
            .show(ui, |ui| self.tree(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.central).inner_margin(egui::Margin::symmetric(10, 8)))
            .show(ui, |ui| self.central(ui));
        self.dialogs(&ctx);

        let tree_nav = self.pending.iter().any(|a| matches!(a, Action::SelectNext | Action::SelectPrevious));
        if tree_nav {
            // Tab is used for tree navigation: do not let egui's focus traversal keep a widget focused.
            ctx.memory_mut(|m| {
                if let Some(id) = m.focused() {
                    m.surrender_focus(id);
                }
            });
        }
        for a in std::mem::take(&mut self.pending) {
            self.state.apply_with(a, self.host.as_mut());
        }
        let fx = std::mem::take(&mut self.state.effects);
        for t in fx.copied {
            ctx.copy_text(t);
        }
        for u in fx.urls {
            ctx.open_url(egui::OpenUrl::new_tab(u));
        }
        if let Some(t) = fx.title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(t));
        }
        if fx.exit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            self.exit_requested = true;
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let typing = ctx.egui_wants_keyboard_input();
        let mut acts = Vec::new();
        ctx.input_mut(|i| {
            if i.consume_key(Modifiers::COMMAND, Key::O) {
                acts.push(Action::OpenDialog);
            }
            if i.consume_key(Modifiers::COMMAND, Key::S) {
                acts.push(Action::Save);
            }
            if i.consume_key(Modifiers::COMMAND, Key::E) {
                acts.push(Action::Close);
            }
            if i.consume_key(Modifiers::COMMAND, Key::R) {
                acts.push(Action::CreateReport);
            }
            if i.consume_key(Modifiers::COMMAND, Key::X) && !typing {
                acts.push(Action::Exit);
            }
            if !typing {
                if i.consume_key(Modifiers::SHIFT, Key::Tab) {
                    acts.push(Action::SelectPrevious);
                }
                if i.consume_key(Modifiers::NONE, Key::Tab) {
                    acts.push(Action::SelectNext);
                }
            }
        });
        self.pending.extend(acts);
    }

    fn menu(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button(self.state.t("file"), |ui| {
                let has = self.state.doc.is_some();
                if ui.button(format!("{}\tCtrl+O", self.state.t("open file"))).clicked() {
                    self.push(Action::OpenDialog);
                    ui.close();
                }
                if ui.add_enabled(has, egui::Button::new(format!("{}\tCtrl+S", self.state.t("save file")))).clicked() {
                    self.push(Action::Save);
                    ui.close();
                }
                if ui.add_enabled(has, egui::Button::new(format!("{}\tCtrl+E", self.state.tr(607, "close file")))).clicked() {
                    self.push(Action::Close);
                    ui.close();
                }
                if ui.add_enabled(has, egui::Button::new(format!("{}\tCtrl+R", self.state.t("create report")))).clicked() {
                    self.push(Action::CreateReport);
                    ui.close();
                }
                ui.separator();
                if ui.button(format!("{}\tCtrl+X", self.state.t("exit PELens"))).clicked() {
                    self.push(Action::Exit);
                    ui.close();
                }
            });
            ui.menu_button(self.state.t("view"), |ui| {
                let dark = self.state.dark_mode();
                if ui.button(self.state.t(if dark { "light mode" } else { "dark mode" })).clicked() {
                    self.push(Action::ToggleDarkMode);
                    ui.close();
                }
                if ui.button(self.state.t("expand all")).clicked() {
                    self.expand_all(true);
                    ui.close();
                }
                if ui.button(self.state.t("collapse all")).clicked() {
                    self.expand_all(false);
                    ui.close();
                }
                ui.separator();
                ui.menu_button(self.state.t("language"), |ui| {
                    let cur = self.state.language_setting();
                    if ui.radio(cur.is_none(), self.state.t("auto (system)")).clicked() {
                        self.push(Action::SetLanguage(None));
                        ui.close();
                    }
                    for l in Lang::ALL {
                        if ui.radio(cur == Some(l), l.native_name()).clicked() {
                            self.push(Action::SetLanguage(Some(l)));
                            ui.close();
                        }
                    }
                });
            });
            if ui.button(self.state.tr(232, "settings")).clicked() {
                self.push(Action::ShowDialog(Dialog::Settings));
            }
            if ui.button(self.state.t("about")).clicked() {
                self.push(Action::ShowDialog(Dialog::About));
            }
        });
    }

    pub fn expand_all(&mut self, open: bool) {
        self.expanded.clear();
        self.expanded.insert("root".into());
        if open {
            for t in [ItemType::Indicators, ItemType::Sections, ItemType::Libraries, ItemType::Resources] {
                self.expanded.insert(t.name().into());
            }
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let has = self.state.doc.is_some();
        let dark = self.state.dark_mode();
        let tip = |k: &str, keys: &str| {
            let s = self.state.t(k);
            if keys.is_empty() { s.to_string() } else { format!("{s} ({keys})") }
        };
        let tips = [
            tip("open file", "Ctrl+O"),
            tip("save file", "Ctrl+S"),
            tip("close file", "Ctrl+E"),
            tip("create report", "Ctrl+R"),
            tip("query Virustotal score", ""),
            tip("settings", ""),
            tip(if dark { "light mode" } else { "dark mode" }, ""),
        ];
        ui.horizontal(|ui| {
            let b = |ui: &mut egui::Ui, icon: &str, tip: &str, enabled: bool| -> bool {
                ui.add_enabled(enabled, egui::Button::new(RichText::new(icon).size(15.0)).frame(false)).on_hover_text(tip).clicked()
            };
            if b(ui, "📂", &tips[0], true) {
                self.push(Action::OpenDialog);
            }
            if b(ui, "💾", &tips[1], has) {
                self.push(Action::Save);
            }
            if b(ui, "✖", &tips[2], has) {
                self.push(Action::Close);
            }
            if b(ui, "📝", &tips[3], has) {
                self.push(Action::CreateReport);
            }
            ui.separator();
            if b(ui, "🛡", &tips[4], has) {
                self.push(Action::QueryScore);
            }
            ui.separator();
            if b(ui, "⚙", &tips[5], true) {
                self.push(Action::ShowDialog(Dialog::Settings));
            }
            if b(ui, if dark { "☀" } else { "🌙" }, &tips[6], true) {
                self.push(Action::ToggleDarkMode);
            }
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let muted = self.palette.muted;
        ui.horizontal(|ui| {
            if self.state.busy.is_some() {
                ui.spinner();
            }
            ui.label(RichText::new(&self.state.status).small());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(d) = &self.state.doc {
                    ui.label(RichText::new(format!("sha256: {}", d.analysis.hashes.sha256)).small().monospace().color(muted));
                    ui.separator();
                    ui.label(
                        RichText::new(format!("{} | {} | {}", d.analysis.cpu, d.analysis.file_type, d.analysis.subsystem))
                            .small()
                            .color(muted),
                    );
                    if d.dirty {
                        ui.separator();
                        ui.label(RichText::new(self.state.t("modified")).small().color(self.flag_color()));
                    }
                }
            });
        });
    }

    // ------------------------------------------------------------------ tree-view

    /// Draw one tree row with guide lines; returns (row response, expander clicked).
    #[allow(clippy::too_many_arguments)]
    fn tree_row(
        &self,
        ui: &mut egui::Ui,
        depth: usize,
        last: bool,
        parent_lines: &[bool],
        has_children: bool,
        open: bool,
        icon: &str,
        label: &str,
        color: Color32,
        selected: bool,
        strong: bool,
    ) -> (egui::Response, bool) {
        let p = &self.palette;
        let width = ui.available_width().max(120.0);
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, TREE_ROW), Sense::click());
        let mut expander_clicked = false;
        if ui.is_rect_visible(rect) {
            let painter = ui.painter_at(rect.expand(1.0));
            if selected {
                painter.rect_filled(rect, 3.0, p.selection);
            } else if resp.hovered() {
                painter.rect_filled(rect, 3.0, p.selection.gamma_multiply(0.45));
            }
            let stroke = Stroke::new(1.0, p.tree_line);
            let cy = rect.center().y;
            // ancestors' vertical lines
            for (lvl, &cont) in parent_lines.iter().enumerate() {
                if cont {
                    let x = rect.left() + 8.0 + lvl as f32 * TREE_INDENT;
                    painter.line_segment([egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())], stroke);
                }
            }
            if depth > 0 {
                let x = rect.left() + 8.0 + (depth - 1) as f32 * TREE_INDENT;
                let bottom = if last { cy } else { rect.bottom() };
                painter.line_segment([egui::pos2(x, rect.top()), egui::pos2(x, bottom)], stroke);
                painter.line_segment([egui::pos2(x, cy), egui::pos2(x + TREE_INDENT - 4.0, cy)], stroke);
            }
            let mut x = rect.left() + 4.0 + depth as f32 * TREE_INDENT;
            if has_children {
                let er = egui::Rect::from_center_size(egui::pos2(x + 5.0, cy), egui::vec2(10.0, 10.0));
                painter.rect_filled(er, 2.0, p.central);
                painter.rect_stroke(er, 2.0, stroke, egui::StrokeKind::Inside);
                painter.line_segment([egui::pos2(er.left() + 2.5, cy), egui::pos2(er.right() - 2.5, cy)], Stroke::new(1.2, p.text));
                if !open {
                    painter.line_segment(
                        [egui::pos2(er.center().x, er.top() + 2.5), egui::pos2(er.center().x, er.bottom() - 2.5)],
                        Stroke::new(1.2, p.text),
                    );
                }
                if resp.clicked() && resp.interact_pointer_pos().is_some_and(|pp| er.expand(3.0).contains(pp)) {
                    expander_clicked = true;
                }
            }
            x += 14.0;
            painter.text(egui::pos2(x, cy), egui::Align2::LEFT_CENTER, icon, FontId::proportional(13.0), color);
            x += 20.0;
            let font = if strong { FontId::new(13.5, egui::FontFamily::Proportional) } else { TextStyle::Body.resolve(ui.style()) };
            let galley = painter.layout_no_wrap(label.to_string(), font, color);
            if strong {
                painter.galley(egui::pos2(x + 0.4, cy - galley.size().y / 2.0), galley.clone(), color);
            }
            painter.galley(egui::pos2(x, cy - galley.size().y / 2.0), galley, color);
        }
        resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, label));
        (resp, expander_clicked)
    }

    fn tree(&mut self, ui: &mut egui::Ui) {
        if self.state.doc.is_none() {
            ui.add_space(8.0);
            ui.label(RichText::new(self.state.t(IDLE)).color(self.palette.muted));
            return;
        }
        let flag_color = self.flag_color();
        let text = self.palette.text;
        let nodes = self.state.nodes();
        let name = self.state.doc.as_ref().map(|d| d.path.display().to_string()).unwrap_or_default();
        let counts: Vec<usize> = {
            let doc = self.state.doc.as_mut().expect("doc");
            nodes.iter().map(|&t| doc.flagged(t)).collect()
        };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let root_open = self.expanded.contains("root");
            let (r, exp) = self.tree_row(ui, 0, true, &[], true, root_open, "🖹", &name, text, false, true);
            if exp || r.double_clicked() {
                self.toggle("root");
            }
            if !root_open {
                return;
            }
            for (i, &t) in nodes.iter().enumerate() {
                let last = i + 1 == nodes.len();
                let children = self.state.tree_children(t);
                let open = self.expanded.contains(t.name());
                let flagged = counts[i];
                let name = self.state.t(t.name());
                let label = if flagged > 0 { format!("{name} ({flagged})") } else { name.to_string() };
                let color = if flagged > 0 { flag_color } else { text };
                let selected = self.state.selected == t && self.state.filter.is_empty();
                let (r, exp) =
                    self.tree_row(ui, 1, last, &[false], !children.is_empty(), open, theme::icon(t), &label, color, selected, false);
                if exp {
                    self.toggle(t.name());
                } else if r.clicked() {
                    self.push(Action::Select(t));
                }
                if r.double_clicked() && !children.is_empty() {
                    self.toggle(t.name());
                }
                if open {
                    let n = children.len();
                    for (ci, (lab, filter, fl)) in children.into_iter().enumerate() {
                        let sel = self.state.selected == t && self.state.filter == filter;
                        let (cr, _) = self.tree_row(
                            ui,
                            2,
                            ci + 1 == n,
                            &[false, !last],
                            false,
                            false,
                            "•",
                            &lab,
                            if fl { flag_color } else { text },
                            sel,
                            false,
                        );
                        if cr.clicked() {
                            self.push(Action::SelectFiltered(t, filter));
                        }
                    }
                }
            }
        });
    }

    pub fn toggle(&mut self, key: &str) {
        if !self.expanded.remove(key) {
            self.expanded.insert(key.to_string());
        }
    }

    // ------------------------------------------------------------------ list-view

    fn location_map(&mut self) -> Option<Arc<LocationMap>> {
        let d = self.state.doc.as_ref()?;
        if let Some((p, g, m)) = &self.loc_cache
            && *p == d.path
            && *g == d.generation
        {
            return Some(m.clone());
        }
        let m = Arc::new(pe_analysis::view::location_map(&d.analysis, &self.state.knowledge));
        self.loc_cache = Some((d.path.clone(), d.generation, m.clone()));
        Some(m)
    }

    fn resource_lines(&mut self, idx: usize) -> Option<Arc<Vec<String>>> {
        let d = self.state.doc.as_ref()?;
        if let Some((p, g, i, l)) = &self.res_cache
            && *p == d.path
            && *g == d.generation
            && *i == idx
        {
            return Some(l.clone());
        }
        let l = Arc::new(pe_analysis::view::resource_content(&d.analysis, &d.data, idx));
        self.res_cache = Some((d.path.clone(), d.generation, idx, l.clone()));
        Some(l)
    }

    fn central(&mut self, ui: &mut egui::Ui) {
        let Some(table) = self.state.visible_table() else {
            ui.centered_and_justified(|ui| ui.label(RichText::new(self.state.t(IDLE)).size(18.0).color(self.palette.muted)));
            return;
        };
        let item = self.state.selected;
        let p = self.palette;
        let file = self.state.doc.as_ref().map(|d| d.file_name()).unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label(RichText::new(theme::icon(item)).size(18.0));
            let name = self.state.t(item.name());
            ui.label(RichText::new(name).heading().strong());
            let count = self.state.tf("{0} items", &[&table.rows.len()]);
            ui.label(RichText::new(format!("{file}  ›  {name}  ·  {count}")).color(p.muted));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button(self.state.tr(590, "save to file")).clicked() {
                    let sep = self.state.knowledge.settings.get("indicators", "separator").unwrap_or("|").to_string();
                    self.pending
                        .push(Action::SaveText { name: item.name().to_string(), text: pe_analysis::view::table_text(&table, &sep) });
                }
                ui.menu_button(self.state.t("column"), |ui| {
                    for (i, c) in table.columns.iter().enumerate() {
                        let mut vis = self.state.column_visible(item, i);
                        if ui.checkbox(&mut vis, self.state.t(c)).changed() {
                            self.state.toggle_column(item, i, table.columns.len());
                        }
                    }
                });
                let (dups, clear, search) =
                    (self.state.t("show duplicates"), self.state.t("clear search"), format!("🔍 {}", self.state.t("search")));
                ui.checkbox(&mut self.state.show_duplicates, dups);
                if !self.state.filter.is_empty() && ui.small_button("⌫").on_hover_text(clear).clicked() {
                    self.state.filter.clear();
                }
                ui.add(egui::TextEdit::singleline(&mut self.state.filter).hint_text(search).desired_width(220.0));
            });
        });
        ui.add_space(4.0);
        if item == ItemType::Strings
            && let Some(map) = self.location_map()
        {
            let total: usize = map.iter().map(|m| m.1).sum::<usize>().max(1);
            let w = ui.available_width();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for (name, n, c) in map.iter() {
                    let width = (w * *n as f32 / total as f32).max(2.0);
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, 8.0), Sense::hover());
                    ui.painter().rect_filled(rect, 1.0, rgb(*c));
                    resp.on_hover_text(self.state.tf("{0}: {1} strings", &[name, n]));
                }
            });
            ui.add_space(4.0);
        }
        if let Some(n) = &table.note {
            ui.label(RichText::new(n).italics().color(p.muted));
        }
        let show_content = item == ItemType::Resources && self.state.selected_row.is_some();
        let avail = ui.available_height();
        let table_h = if show_content { avail * 0.62 } else { avail };
        ui.allocate_ui(egui::vec2(ui.available_width(), table_h), |ui| self.table(ui, item, &table));
        if show_content {
            ui.add_space(6.0);
            let idx = self
                .state
                .selected_row
                .and_then(|r| table.rows.get(r))
                .and_then(|r| r.key.strip_prefix("resource:").and_then(|s| s.parse::<usize>().ok()));
            if let Some(lines) = idx.and_then(|i| self.resource_lines(i)) {
                egui::Frame::new().fill(p.panel).stroke(Stroke::new(1.0, p.grid)).corner_radius(4.0).inner_margin(6.0).show(ui, |ui| {
                    egui::ScrollArea::vertical().id_salt("rescontent").auto_shrink([false, false]).show_rows(
                        ui,
                        16.0,
                        lines.len(),
                        |ui, range| {
                            for l in &lines[range] {
                                ui.monospace(l);
                            }
                        },
                    );
                });
            }
        }
    }

    fn table(&mut self, ui: &mut egui::Ui, item: ItemType, table: &Table) {
        let cols: Vec<usize> = (0..table.columns.len()).filter(|&c| self.state.column_visible(item, c)).collect();
        if cols.is_empty() {
            return;
        }
        let p = self.palette;
        let st = &self.state;
        let k = &st.knowledge;
        let headers: Vec<&str> = table.columns.iter().map(|c| st.t(c)).collect();
        let groups_color = k.settings.get_bool("groups", "color", true) && k.settings.get_bool("groups", "enable", true);
        let tooltips = k.settings.get_bool("tooltips", "enable", true);
        let flag_color = self.flag_color();
        let (jump_color, ext_color) = if p.dark {
            (p.jump, p.link)
        } else {
            (self.color_setting("jumps", "color_int", p.jump), self.color_setting("jumps", "color_ext", p.link))
        };
        let sep = k.settings.get("indicators", "separator").unwrap_or("|").to_string();
        let group_rgb = |g: u8| k.translations.group(g).filter(|d| d.level < 3).map(|d| rgb(d.rgb));
        let mono: Vec<bool> = table.columns.iter().map(|c| theme::is_mono_column(c)).collect();
        let mut tb =
            TableBuilder::new(ui).striped(true).resizable(true).sense(Sense::click()).cell_layout(Layout::left_to_right(Align::Center));
        for (i, &c) in cols.iter().enumerate() {
            tb = tb.column(if i + 1 == cols.len() {
                Column::remainder().at_least(60.0).clip(true)
            } else {
                let w = theme::estimate_width(
                    headers[c],
                    table.rows.iter().map(|r| r.cells.get(c).map(|x| x.chars().count()).unwrap_or(0)),
                    mono[c],
                );
                Column::initial(w).at_least(40.0).clip(true)
            });
        }
        let mut clicked_sort = None;
        let mut actions: Vec<Action> = Vec::new();
        let mut new_selected = None;
        let sel = self.state.selected_row;
        let sort = self.state.sort;
        tb.header(22.0, |mut h| {
            for &c in &cols {
                h.col(|ui| {
                    ui.painter().rect_filled(ui.max_rect().expand2(egui::vec2(4.0, 1.0)), 0.0, p.header);
                    let marker = match sort {
                        Some((sc, true)) if sc == c => " ▲",
                        Some((sc, false)) if sc == c => " ▼",
                        _ => "",
                    };
                    let r = ui.add(egui::Button::new(RichText::new(format!("{}{marker}", headers[c])).strong()).frame(false));
                    if r.clicked() {
                        clicked_sort = Some(c);
                    }
                });
            }
        })
        .body(|body| {
            body.rows(ROW_H, table.rows.len(), |mut row| {
                let ri = row.index();
                let r = &table.rows[ri];
                row.set_selected(sel == Some(ri));
                for &c in &cols {
                    let text = r.cells.get(c).map(String::as_str).unwrap_or("");
                    row.col(|ui| {
                        let mut rt = RichText::new(text);
                        if mono[c] {
                            rt = rt.monospace();
                        }
                        if r.flag || r.severity == Some(1) {
                            rt = rt.color(flag_color);
                        } else if c == 0 && r.jump.is_some() {
                            rt = rt.color(jump_color);
                        } else if c == 0 && r.url.is_some() {
                            rt = rt.color(ext_color);
                        }
                        if groups_color
                            && c == 0
                            && let Some(col) = r.group.and_then(group_rgb)
                        {
                            let rect = ui.max_rect();
                            ui.painter().rect_filled(egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())), 0.0, col);
                            ui.add_space(4.0);
                        }
                        let resp = ui.add(egui::Label::new(rt).selectable(false));
                        if tooltips && resp.hovered() {
                            let mut tip = Vec::new();
                            if r.flag {
                                tip.push(st.t("flag").to_string());
                            }
                            if let Some(g) = r.group {
                                tip.push(st.tf("group: {0}", &[&k.group_name(g)]));
                            }
                            if let Some(ti) = &r.ti {
                                tip.push(st.tf("technique: {0}", &[&format!("T{}", ti.trim_start_matches('T'))]));
                            }
                            if let Some(u) = &r.url {
                                tip.push(st.tf("url: {0}", &[u]));
                            }
                            if let Some(j) = r.jump {
                                tip.push(st.tf("double click > {0}", &[&st.t(j.name())]));
                            }
                            if !tip.is_empty() {
                                resp.on_hover_text(tip.join("\n"));
                            }
                        }
                    });
                }
                let resp = row.response();
                if resp.clicked() {
                    new_selected = Some(ri);
                }
                if resp.double_clicked() {
                    if let Some(j) = r.jump {
                        actions.push(Action::Select(j));
                    } else if let Some(u) = &r.url {
                        actions.push(Action::OpenUrl(u.clone()));
                    }
                }
                resp.context_menu(|ui| {
                    for (label, a) in st.context_actions(item, r, &table.columns, &sep) {
                        if ui.button(label).clicked() {
                            actions.push(a);
                            ui.close();
                        }
                    }
                });
            });
        });
        if let Some(c) = clicked_sort {
            self.state.sort_column(c);
        }
        if let Some(s) = new_selected {
            self.state.selected_row = Some(s);
        }
        self.pending.extend(actions);
    }

    // ------------------------------------------------------------------ dialogs

    fn dialogs(&mut self, ctx: &egui::Context) {
        match self.state.dialog.clone() {
            Dialog::None => {}
            Dialog::Settings => self.settings_window(ctx),
            Dialog::About => self.about_window(ctx),
            Dialog::ConfirmDiscard(_) => {
                let (title, text) = (self.state.t("save changes ?"), self.state.t("discard the modifications and proceed?"));
                self.confirm(ctx, title, text)
            }
            Dialog::ConfirmOverwrite(p) => self.confirm(ctx, self.state.t("overwrite the file?"), &p.display().to_string()),
            Dialog::Message(m) => {
                egui::Modal::new(egui::Id::new("message")).show(ctx, |ui| {
                    ui.set_max_width(520.0);
                    ui.label(m);
                    ui.add_space(6.0);
                    if ui.button(self.state.t("OK")).clicked() {
                        self.push(Action::Cancel);
                    }
                });
            }
            Dialog::EntryPoint(mut s) => {
                egui::Modal::new(egui::Id::new("ep")).show(ctx, |ui| {
                    ui.label(RichText::new(self.state.tr(603, "set entry-point")).strong());
                    ui.label(self.state.t("RVA, e.g. 0x1000"));
                    if ui.text_edit_singleline(&mut s).changed() {
                        self.state.dialog = Dialog::EntryPoint(s.clone());
                    }
                    ui.horizontal(|ui| {
                        if ui.button(self.state.t("proceed")).clicked() {
                            self.push(Action::Confirm);
                        }
                        if ui.button(self.state.t("Cancel")).clicked() {
                            self.push(Action::Cancel);
                        }
                    });
                });
            }
        }
    }

    fn confirm(&mut self, ctx: &egui::Context, title: &str, text: &str) {
        egui::Modal::new(egui::Id::new("confirm")).show(ctx, |ui| {
            ui.label(RichText::new(title).heading());
            ui.label(text);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(self.state.t("proceed")).clicked() {
                    self.push(Action::Confirm);
                }
                if ui.button(self.state.t("Cancel")).clicked() {
                    self.push(Action::Cancel);
                }
            });
        });
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let title = format!("PELens | {}", self.state.t("about"));
        egui::Window::new(title).id(egui::Id::new("about")).open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
            let t = |k| self.state.t(k);
            ui.heading(format!("PELens {VERSION}"));
            ui.label(t("Malware Initial Assessment (Rust remake of pestudio 9.61)"));
            ui.small(t("This software is provided 'as-is', without any expressed or implied warranty."));
            ui.small(t("When retrieving the online score of a file, the file itself is not submitted, only its hash is sent."));
            ui.separator();
            ui.label(t("Knowledge base: pestudio XML files from your own installation"));
            if let Some(d) = &self.state.knowledge.dir {
                ui.label(RichText::new(format!("xml: {}", d.display())).monospace());
            }
            let k = &self.state.knowledge;
            ui.label(self.state.tf("loaded: {0} | errors: {1}", &[&k.loaded.len(), &k.errors.len()]));
            if !self.fonts_loaded.is_empty() {
                ui.small(self.state.tf("fonts: {0}", &[&self.fonts_loaded.join(", ")]));
            }
            ui.separator();
            if ui.button(self.state.t("Check online for an update")).clicked() {
                self.push(Action::CheckUpdate);
            }
            if self.state.update_rx.is_some() {
                ui.spinner();
            }
            if let Some(r) = &self.state.update_result {
                ui.label(r);
            }
        });
        if !open {
            self.push(Action::Cancel);
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let title = format!("PELens > {}", self.state.t("settings"));
        egui::Window::new(title).id(egui::Id::new("settings")).open(&mut open).collapsible(false).default_width(460.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                for t in setting_tabs() {
                    if ui.selectable_label(self.settings_tab == t, self.state.t(t)).clicked() {
                        self.settings_tab = t;
                    }
                }
            });
            ui.separator();
            let mut changes: Vec<(&str, &str, String)> = Vec::new();
            egui::Grid::new("settings-grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                for f in SETTING_FIELDS.iter().filter(|f| f.tab == self.settings_tab) {
                    let cur = self.state.knowledge.settings.get(f.elem, f.attr).unwrap_or(setting_default(f)).to_string();
                    let label = self.state.t(f.label);
                    if f.choices.is_empty() {
                        let mut b = cur != "0";
                        if ui.checkbox(&mut b, label).changed() {
                            changes.push((f.elem, f.attr, if b { "1".into() } else { "0".into() }));
                        }
                        ui.label("");
                    } else if f.choices[0].0 == "*" {
                        ui.label(label);
                        let mut v = if f.attr == "key" { self.key_buffer.clone() } else { cur.clone() };
                        let r = if f.attr == "key" {
                            ui.add(egui::TextEdit::singleline(&mut v).password(true))
                        } else {
                            ui.text_edit_singleline(&mut v)
                        };
                        if f.attr == "key" {
                            self.key_buffer = v.clone();
                            r.clone().on_hover_text(self.state.t("Your own Virustotal key used to perform queries."));
                        }
                        if r.lost_focus() && v != cur {
                            changes.push((f.elem, f.attr, v));
                        }
                    } else if f.choices.len() > COMBO_CHOICES {
                        ui.label(label);
                        let shown = f.choices.iter().find(|c| c.0.eq_ignore_ascii_case(&cur)).map_or(cur.as_str(), |c| c.1);
                        egui::ComboBox::from_id_salt(f.label).selected_text(self.state.t(shown)).show_ui(ui, |ui| {
                            for (val, lab) in f.choices {
                                if ui.selectable_label(cur.eq_ignore_ascii_case(val), self.state.t(lab)).clicked() && cur != *val {
                                    changes.push((f.elem, f.attr, val.to_string()));
                                }
                            }
                        });
                    } else {
                        ui.label(label);
                        ui.horizontal(|ui| {
                            for (val, lab) in f.choices {
                                if ui.selectable_label(cur == *val, self.state.t(lab)).clicked() && cur != *val {
                                    changes.push((f.elem, f.attr, val.to_string()));
                                }
                            }
                        });
                    }
                    ui.end_row();
                }
            });
            for (e, a, v) in changes {
                self.state.set_setting(e, a, &v);
            }
        });
        if !open {
            self.push(Action::Cancel);
        }
    }
}
