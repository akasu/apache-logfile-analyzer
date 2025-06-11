
mod app;
mod parser;

use app::MyApp;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 768.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Apache Log Analyzer",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::default()))),
    )
}