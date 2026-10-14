//! Render the main window off-screen (wgpu, no desktop needed) to a PNG:
//! `cargo run -p pelens-gui --example render -- <sample> <view> <out.png> [lang] [hex]`
use egui_kittest::Harness;
use pe_analysis::model::ItemType;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (sample, view, out) = (&a[0], &a[1], &a[2]);
    let mut s = pelens_gui::State::new(pe_db::Knowledge::builtin());
    s.synchronous = true;
    if let Some(l) = a.get(3).and_then(|c| pelens_gui::i18n::Lang::from_code(c)) {
        s.knowledge.settings.set("language", "code", l.code());
        s.refresh_lang();
    }
    s.apply(pelens_gui::Action::Open(sample.into()));
    let item = ItemType::ALL.iter().copied().find(|i| i.name() == view).expect("view name");
    s.apply(pelens_gui::Action::Select(item));
    if a.get(4).is_some_and(|h| h == "hex") {
        // the hex view on the range of the first row that has one
        let range = s.visible_table().and_then(|t| t.rows.iter().find_map(|r| r.dump));
        match range {
            Some((off, size)) => {
                s.apply(pelens_gui::Action::ShowHex(off, size));
                s.selected_row = Some(0);
            }
            None => s.apply(pelens_gui::Action::ToggleHex),
        }
    }
    let mut app = pelens_gui::PeLensApp::new(s, Box::new(pelens_gui::RfdHost::default()));
    app.expand_all(true);
    let mut h = Harness::builder()
        .with_size(egui::vec2(1280.0, 820.0))
        .wgpu()
        .build_ui_state(|ui, app: &mut pelens_gui::PeLensApp| app.draw(ui), app);
    h.run();
    h.run();
    let img = h.render().expect("render");
    img.save(out).expect("save png");
    println!("{out}");
}
