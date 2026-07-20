// MCPIP Operator Console — native desktop entry point.
// Suppress the extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    mcpip_operator_lib::run();
}
