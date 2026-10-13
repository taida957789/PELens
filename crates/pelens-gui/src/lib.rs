//! PELens graphical user interface.

pub mod model;
pub mod theme;
pub mod ui;

pub use model::{Action, Dialog, Document, Host, State};
pub use ui::{PeLensApp, RfdHost};

impl eframe::App for ui::PeLensApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

/// Parse `pelens [file] [-xml:dir]` command line arguments.
pub fn parse_cli(args: &[String]) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    let mut file = None;
    let mut xml = None;
    for a in args {
        let t = a.trim_start_matches(['-', '/']);
        if let Some(v) = t.strip_prefix("xml:").or_else(|| t.strip_prefix("xml=")) {
            xml = Some(std::path::PathBuf::from(v));
        } else if let Some(v) = t.strip_prefix("file:").or_else(|| t.strip_prefix("file=")) {
            file = Some(std::path::PathBuf::from(v));
        } else if ["renderer:", "view:", "theme:", "expand"].iter().any(|p| t.to_ascii_lowercase().starts_with(p)) {
            // handled by main / parse_startup
        } else if !a.starts_with('-') {
            file = Some(std::path::PathBuf::from(a));
        }
    }
    (file, xml)
}

/// The PELens icon (assets/pelens.png) as window icon data.
pub fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/pelens.png")).unwrap_or_default()
}

/// Optional start-up state: `-view:<name>`, `-theme:dark|light`, `-expand`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Startup {
    pub view: Option<pe_analysis::model::ItemType>,
    pub dark: Option<bool>,
    pub expand: bool,
}

pub fn parse_startup(args: &[String]) -> Startup {
    let mut s = Startup::default();
    for a in args {
        let t = a.trim_start_matches(['-', '/']).to_ascii_lowercase();
        if let Some(v) = t.strip_prefix("view:") {
            s.view = pe_analysis::model::ItemType::ALL.iter().copied().find(|i| i.name() == v || (v == "tls" && *i == pe_analysis::model::ItemType::Tls));
        } else if let Some(v) = t.strip_prefix("theme:") {
            s.dark = match v {
                "dark" => Some(true),
                "light" => Some(false),
                _ => None,
            };
        } else if t == "expand" {
            s.expand = true;
        }
    }
    s
}

impl Startup {
    pub fn apply(&self, app: &mut ui::PeLensApp) {
        if let Some(v) = self.view {
            app.state.apply(Action::Select(v));
        }
        if let Some(d) = self.dark {
            app.state.knowledge.settings.set("theme", "dark", if d { "1" } else { "0" });
        }
        if self.expand {
            app.expand_all(true);
        }
    }
}
