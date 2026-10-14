//! GUI frame times: `cargo run --release -p pelens-gui --example bench -- [file] [xml-dir]`
//! (default: a .NET framework DLL and ../xml). The first frame of each view includes building
//! its table; the median is the steady state while scrolling or hovering.
use pe_analysis::model::ItemType;
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let file = args.first().cloned().unwrap_or_else(|| "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/System.Web.dll".into());
    let xml = args.get(1).cloned().unwrap_or_else(|| "../xml".into());
    let k = pelens_gui::model::load_knowledge(Some(std::path::Path::new(&xml)), None);
    let mut s = pelens_gui::State::new(k);
    s.synchronous = true;
    let t = std::time::Instant::now();
    s.apply(pelens_gui::Action::Open(file.clone().into()));
    println!("{file}: open + analysis {:.0} ms", t.elapsed().as_secs_f64() * 1000.0);
    let mut app = pelens_gui::PeLensApp::new(s, Box::new(pelens_gui::RfdHost::default()));
    app.load_system_fonts = false;
    let ctx = egui::Context::default();
    for item in [ItemType::Indicators, ItemType::Imports, ItemType::Sections, ItemType::Overlay, ItemType::Strings] {
        app.state.apply(pelens_gui::Action::Select(item));
        let mut times = Vec::new();
        for _ in 0..30 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0))),
                ..Default::default()
            };
            let t = std::time::Instant::now();
            let out = ctx.run_ui(input, |ui| app.draw(ui));
            let _ = ctx.tessellate(out.shapes, out.pixels_per_point);
            times.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let first = times[0];
        times.sort_by(|a, b| a.total_cmp(b));
        println!("{item:?}: first frame {first:.1} ms, median {:.1} ms, max {:.1} ms", times[15], times[29]);
    }
}
