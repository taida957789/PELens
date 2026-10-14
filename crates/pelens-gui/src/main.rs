#![windows_subsystem = "windows"]

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (file, xml) = pelens_gui::parse_cli(&args);
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let mut k = pelens_gui::model::load_knowledge(xml.as_deref(), exe_dir.as_deref());
    let store = std::sync::Arc::new(pe_online::secret::CredentialStore::vt());
    // a key from an older settings.xml moves to the Credential Manager (stays if that fails)
    let _ = pe_online::secret::migrate_plaintext_key(&mut k, store.as_ref());
    let mut state = pelens_gui::State::new(k);
    state.key_store = store;
    state.set_system_lang(pelens_gui::i18n::system_lang());
    let startup = pelens_gui::parse_startup(&args);
    startup.apply_lang(&mut state);
    if let Some(f) = file {
        state.apply(pelens_gui::Action::Open(f));
    }
    let title = state.title();
    let wgpu = args.iter().any(|a| pelens_gui::option_body(a).is_some_and(|b| b.eq_ignore_ascii_case("renderer:wgpu")))
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
            let mut app = pelens_gui::PeLensApp::new(state, Box::new(pelens_gui::RfdHost::default()));
            startup.apply(&mut app);
            Ok(Box::new(app))
        }),
    )
}
