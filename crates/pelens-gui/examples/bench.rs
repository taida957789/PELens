use pe_analysis::model::ItemType;
fn main() {
    let k = pelens_gui::model::load_knowledge(Some(std::path::Path::new("../xml")), None);
    let mut s = pelens_gui::State::new(k);
    s.synchronous = true;
    s.apply(pelens_gui::Action::Open("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/System.Web.dll".into()));
    let mut app = pelens_gui::PeLensApp::new(s, Box::new(pelens_gui::RfdHost::default()));
    let ctx = egui::Context::default();
    for item in [ItemType::Indicators, ItemType::Imports, ItemType::Strings] {
        app.state.apply(pelens_gui::Action::Select(item));
        let mut times = Vec::new();
        for _ in 0..30 {
            let mut input = egui::RawInput::default();
            input.screen_rect = Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0)));
            let t = std::time::Instant::now();
            let out = ctx.run_ui(input, |ui| app.draw(ui));
            let _ = ctx.tessellate(out.shapes, out.pixels_per_point);
            times.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{:?}: median frame {:.1} ms (max {:.1})", item, times[15], times[29]);
    }
}
