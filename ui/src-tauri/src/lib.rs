#[tauri::command]
fn core_status() -> &'static str {
    "framework-ready"
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![core_status])
        .run(tauri::generate_context!())
        .expect("error while running TraceLens desktop application");
}
