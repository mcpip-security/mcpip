//! MCPIP Operator Console — native shell.
//!
//! Deliberately inert: it renders the bundled operator frontend and nothing else.
//! No shell / filesystem / process / HTTP plugins are registered — the frontend
//! reaches the MCPIP gateway itself over HTTPS/WSS (same token/mTLS standards as the
//! web portal), so the native layer grants no additional capability an attacker could
//! pivot through. This is the Tier-1 minimal-surface posture.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running the MCPIP operator console");
}
