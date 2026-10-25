//! In-app sign-in window for gateways that answer the WebSocket upgrade with a
//! 302 to an identity provider (`account.aliyun.com`, `login.microsoftonline.com`,
//! a self-hosted `/login` page, ...).
//!
//! The connector in `easytier` recognises login redirects and asks a registered
//! handler for cookies. Here we open the redirect target in a Tauri webview,
//! wait for the flow to leave the sign-in page, and read the cookies straight
//! from the webview cookie store.

use std::sync::Arc;
use std::time::{Duration, Instant};

use easytier::tunnel::websocket::{LoginHandler, set_login_handler};
use tauri::{AppHandle, WebviewUrl, WebviewWindowBuilder};

/// How long the login window stays open before giving up.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
/// How often the window URL and cookie store are sampled.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Number of consecutive identical samples before the cookie store is
/// considered settled (the callback may still be writing cookies right after
/// the page loads).
const STABLE_SAMPLES: u32 = 3;

/// Register the handler with the easytier connector. Must be called once, from
/// the Tauri setup hook, before any network instance connects.
pub fn install(app: AppHandle) {
    let handler: LoginHandler = Arc::new(move |login_url: String| {
        let app = app.clone();
        Box::pin(async move { open_login_window(app, login_url).await })
    });
    set_login_handler(handler);
}

/// Whether a URL still looks like a sign-in page. Identity providers usually
/// live on a login-looking host or path; a query carrying an OAuth/OIDC
/// callback parameter (`code`, `state`, `ticket`, ...) means the flow already
/// came back and must not be treated as the login page itself.
fn is_login_page(url: &url::Url) -> bool {
    if url.query_pairs().any(|(key, _)| {
        matches!(
            key.as_ref(),
            "code" | "state" | "ticket" | "assertion" | "token" | "session_state"
        )
    }) {
        return false;
    }

    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = url.path().to_ascii_lowercase();

    [
        "login", "signin", "signon", "sso", "passport", "account", "auth", "cas",
    ]
    .iter()
    .any(|marker| host.contains(marker))
        || [
            "/login",
            "/signin",
            "/signon",
            "/sso",
            "/auth",
            "/cas",
            "/authorize",
        ]
        .iter()
        .any(|marker| path.contains(marker))
}

async fn open_login_window(
    app: AppHandle,
    login_url: String,
) -> Result<Vec<(String, String)>, String> {
    let url = url::Url::parse(&login_url).map_err(|e| e.to_string())?;

    // The Tauri window and cookie APIs block on the main thread, so everything
    // happens on a blocking thread: the main thread must stay free to serve the
    // dispatcher calls (reading cookies on the main thread deadlocks on
    // Windows, see the wry issue referenced by `Webview::cookies`).
    tokio::task::spawn_blocking(move || run_login_window(app, url))
        .await
        .map_err(|e| e.to_string())?
}

fn run_login_window(app: AppHandle, url: url::Url) -> Result<Vec<(String, String)>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let app_for_main = app.clone();
    app.run_on_main_thread(move || {
        let built = WebviewWindowBuilder::new(&app_for_main, "login", WebviewUrl::External(url))
            .title("Sign in")
            .inner_size(620.0, 820.0)
            .build()
            .map_err(|e| e.to_string());
        let _ = tx.send(built);
    })
    .map_err(|e| e.to_string())?;

    let window = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "the login window could not be created".to_string())??;

    let deadline = Instant::now() + LOGIN_TIMEOUT;
    let mut last_cookies: Vec<(String, String)> = Vec::new();
    let mut collected: Vec<(String, String)> = Vec::new();
    let mut stable_samples = 0;

    loop {
        if Instant::now() >= deadline {
            let _ = window.destroy();
            return Err("the login timed out".to_string());
        }

        std::thread::sleep(POLL_INTERVAL);

        let Ok(current) = window.url() else {
            // The user closed the window: keep whatever the flow has written so
            // far, so a provider whose callback never leaves the sign-in path
            // can still be finished by closing the window after signing in.
            let _ = window.destroy();
            return if collected.is_empty() {
                Err("the login window was closed before signing in".to_string())
            } else {
                Ok(collected)
            };
        };

        let Ok(current) = url::Url::parse(current.as_str()) else {
            continue;
        };

        let fresh: Vec<(String, String)> = match window.cookies() {
            Ok(cookies) => cookies
                .iter()
                .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
                .collect(),
            Err(_) => continue,
        };

        if fresh.is_empty() {
            continue;
        }

        let mut fingerprint = fresh.clone();
        fingerprint.sort();
        if fingerprint == last_cookies {
            stable_samples += 1;
        } else {
            last_cookies = fingerprint;
            stable_samples = 0;
        }
        collected = fresh;

        if stable_samples >= STABLE_SAMPLES && !is_login_page(&current) {
            let _ = window.destroy();
            return Ok(collected);
        }
    }
}
