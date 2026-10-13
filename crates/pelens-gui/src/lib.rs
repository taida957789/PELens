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

const VALUE_OPTIONS: [&str; 5] = ["xml", "file", "renderer", "view", "theme"];
const FLAG_OPTIONS: [&str; 1] = ["expand"];

/// The option text of an argument (`-name:value`, `--name=value`, `/name:value`), or None when the
/// argument is a file name. A leading `/` only counts for a known option, so absolute Unix paths
/// and file names such as `expand.exe` are never mistaken for options.
pub fn option_body(a: &str) -> Option<&str> {
    let known = |b: &str| {
        let name = b.split([':', '=']).next().unwrap_or("").to_ascii_lowercase();
        let has_value = b.len() > name.len();
        (has_value && VALUE_OPTIONS.contains(&name.as_str())) || (!has_value && FLAG_OPTIONS.contains(&name.as_str()))
    };
    if a.starts_with('-') {
        return Some(a.trim_start_matches('-'));
    }
    a.strip_prefix('/').filter(|b| known(b))
}

/// Parse `pelens [file] [-xml:dir]` command line arguments.
pub fn parse_cli(args: &[String]) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    let mut file = None;
    let mut xml = None;
    for a in args {
        match option_body(a) {
            Some(t) => {
                if let Some(v) = t.strip_prefix("xml:").or_else(|| t.strip_prefix("xml=")) {
                    xml = Some(std::path::PathBuf::from(v));
                } else if let Some(v) = t.strip_prefix("file:").or_else(|| t.strip_prefix("file=")) {
                    file = Some(std::path::PathBuf::from(v));
                }
                // other options are handled by main / parse_startup
            }
            None => file = Some(std::path::PathBuf::from(a)),
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
        let Some(t) = option_body(a) else { continue };
        let t = t.to_ascii_lowercase();
        if let Some(v) = t.strip_prefix("view:") {
            s.view = pe_analysis::model::ItemType::ALL
                .iter()
                .copied()
                .find(|i| i.name() == v || (v == "tls" && *i == pe_analysis::model::ItemType::Tls));
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
