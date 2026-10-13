#![windows_subsystem = "windows"]

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (file, xml) = pelens_gui::parse_cli(&args);
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let k = pelens_gui::model::load_knowledge(xml.as_deref(), exe_dir.as_deref());
    let mut state = pelens_gui::State::new(k);
    if let Some(f) = file {
        state.apply(pelens_gui::Action::Open(f));
    }
    let startup = pelens_gui::parse_startup(&args);
    let title = state.title();
    let wgpu = args.iter().any(|a| a.trim_start_matches(['-', '/']).eq_ignore_ascii_case("renderer:wgpu"))
        || std::env::var("PELENS_RENDERER").is_ok_and(|v| v.eq_ignore_ascii_case("wgpu"));
    let opts = eframe::NativeOptions {
        renderer: if wgpu { eframe::Renderer::Wgpu } else { eframe::Renderer::Glow },
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_app_id("pelens")
            .with_icon(std::sync::Arc::new(pelens_gui::app_icon()))
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "pelens",
        opts,
        Box::new(move |_cc| {
            let mut app = pelens_gui::PeLensApp::new(state, Box::new(pelens_gui::RfdHost));
            startup.apply(&mut app);
            Ok(Box::new(app))
        }),
    )
}
