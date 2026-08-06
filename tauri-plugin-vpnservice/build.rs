const COMMANDS: &[&str] = &[
    "ping",
    "prepare_vpn",
    "start_vpn",
    "stop_vpn",
    "get_vpn_status",
    "consume_tile_toggle",
    "complete_tile_toggle",
    "save_headless_profile",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
