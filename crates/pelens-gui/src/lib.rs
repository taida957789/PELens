//! pestudio-rs graphical user interface.

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

/// Parse `pestudio [file] [-xml:dir]` command line arguments.
pub fn parse_cli(args: &[String]) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    let mut file = None;
    let mut xml = None;
    for a in args {
        let t = a.trim_start_matches(['-', '/']);
        if let Some(v) = t.strip_prefix("xml:").or_else(|| t.strip_prefix("xml=")) {
            xml = Some(std::path::PathBuf::from(v));
        } else if let Some(v) = t.strip_prefix("file:").or_else(|| t.strip_prefix("file=")) {
            file = Some(std::path::PathBuf::from(v));
        } else if t.to_ascii_lowercase().starts_with("renderer:") {
            // handled by main
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
