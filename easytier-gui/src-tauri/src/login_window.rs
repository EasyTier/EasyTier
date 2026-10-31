//! In-app sign-in window for gateways that answer the WebSocket upgrade with a
//! 302 to an identity provider (`account.aliyun.com`, `login.microsoftonline.com`,
//! a self-hosted `/login` page, ...).
//!
//! The connector in `easytier` recognises login redirects and asks a registered
//! handler for cookies. Here we open the redirect target in a Tauri webview,
//! wait for the flow to come back to the gateway host (or settle on the SSO
//! callback), and read the cookies straight from the webview cookie store.

use std::sync::Arc;
use std::time::{Duration, Instant};

use easytier::tunnel::websocket::{set_login_handler, LoginHandler};
use tauri::{AppHandle, WebviewUrl, WebviewWindowBuilder};

/// How long the login window stays open before giving up.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(240);
/// How often the window URL and cookie store are sampled.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Number of consecutive identical samples before the cookie store is
/// considered settled (the callback may still be writing cookies right after
/// the page loads).
const STABLE_SAMPLES: u32 = 3;
/// How long the browser may stay on a third-party host (the SSO callback, e.g.
/// `modelscope.cn`) once that page stopped looking like a sign-in page, before
/// the cookies are handed over anyway.
const FOREIGN_GRACE: Duration = Duration::from_secs(20);
/// How long a third-party page of the flow may stay open before the window
/// returns to the gateway. Long enough to finish a manual sign-in (password,
/// SMS or SSO confirmation) and any extra provider page it leads to.
const BACK_TO_GATEWAY_GRACE: Duration = Duration::from_secs(120);

/// A modelscope sign-in is the one flow that needs extra steps: modelscope is a
/// second provider in the chain, and the gateway only mints its session token
/// (`custom_dsw_gateway_token`) once the workspace page has been opened.
const WORKSPACE_URL: &str = "https://www.modelscope.cn/code/workspace";
/// How long modelscope pages are left open before the next step.
const WORKSPACE_GRACE: Duration = Duration::from_secs(10);

/// Whether a URL belongs to modelscope, which marks the flow as the special one.
fn is_modelscope(url: &url::Url) -> bool {
    url.host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("modelscope")
}

/// Whether a URL is an identity provider error page, e.g.
/// `https://modelscope.cn/error?request_id=...&code=-30`.
fn is_error_page(url: &url::Url) -> bool {
    url.path_segments()
        .and_then(|mut segments| segments.next_back())
        .is_some_and(|last| last == "error" || last.starts_with("error."))
        || url
            .query_pairs()
            .any(|(key, value)| key == "error" || (key == "code" && value.starts_with('-')))
}

/// Register the handler with the easytier connector. Must be called once, from
/// the Tauri setup hook, before any network instance connects.
pub fn install(app: AppHandle) {
    let handler: LoginHandler = Arc::new(move |login_url: String, gateway_url: String| {
        let app = app.clone();
        Box::pin(async move { open_login_window(app, login_url, gateway_url).await })
    });
    set_login_handler(handler);
}

/// Whether a URL still looks like a sign-in page (its own provider login page,
/// e.g. `modelscope.cn/login`). A query carrying an OAuth/OIDC callback
/// parameter (`code`, `state`, `ticket`, ...) means the provider already handed
/// the browser back.
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

/// The login window runs in the GUI process, which has no console on Windows,
/// so the flow is traced to a file next to the system temp directory as well.
fn log_note(message: &str) {
    let path = std::env::temp_dir().join("easytier-login-window.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write as _;
        let _ = writeln!(file, "{message}");
    }
    eprintln!("{message}");
}

fn describe_cookies(window: &tauri::WebviewWindow<tauri::Wry>) -> String {
    match window.cookies() {
        Ok(cookies) => cookies
            .iter()
            .map(|cookie| format!("{}={}", cookie.domain().unwrap_or("<host>"), cookie.name()))
            .collect::<Vec<_>>()
            .join(", "),
        Err(_) => "<unreadable>".to_string(),
    }
}

async fn open_login_window(
    app: AppHandle,
    login_url: String,
    gateway_url: String,
) -> Result<Vec<(String, String)>, String> {
    let url = url::Url::parse(&login_url).map_err(|e| e.to_string())?;
    let gateway = url::Url::parse(&gateway_url).map_err(|e| e.to_string())?;

    // The Tauri window and cookie APIs block on the main thread, so everything
    // happens on a blocking thread: the main thread must stay free to serve the
    // dispatcher calls (reading cookies on the main thread deadlocks on
    // Windows, see the wry issue referenced by `Webview::cookies`).
    tokio::task::spawn_blocking(move || run_login_window(app, url, gateway))
        .await
        .map_err(|e| e.to_string())?
}

/// This build supports exactly one sign-in chain: an Alibaba Cloud DSW gateway
/// that hands the browser to aliyun (and, for VS Code workspaces, modelscope).
/// Anything else fails immediately instead of leaving the user in a window that
/// cannot succeed.
fn supported_gateway(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.contains(".dsw-gateway-") && host.ends_with(".data.aliyun.com")
}

fn supported_provider(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.contains("aliyun") || host.contains("modelscope")
}

fn run_login_window(
    app: AppHandle,
    url: url::Url,
    gateway: url::Url,
) -> Result<Vec<(String, String)>, String> {
    let gateway_host = gateway.host_str().unwrap_or_default().to_owned();
    if !supported_gateway(&gateway_host) {
        return Err(format!(
            "unsupported gateway `{gateway_host}`: this build only signs in to Alibaba Cloud \
             DSW gateways (`…dsw-gateway-….data.aliyun.com`)"
        ));
    }
    if !supported_provider(url.host_str().unwrap_or_default()) {
        return Err(format!(
            "unsupported sign-in flow at {url}: only the aliyun/modelscope providers used by \
             DSW gateways are supported"
        ));
    }
    log_note(&format!(
        "login window opening at {url} (gateway host {gateway_host})"
    ));
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
    let mut last_sample: Vec<(String, String)> = Vec::new();
    let mut collected: Vec<(String, String)> = Vec::new();
    let mut stable_samples = 0;
    let mut foreign_since: Option<Instant> = None;
    let mut last_url = String::new();
    let mut navigated_back = false;
    let mut navigating_from: Option<String> = None;
    let mut modelscope_flow = false;
    let mut workspace_visited = false;
    let mut recoveries = 0u32;

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

        if current.as_str() != last_url {
            log_note(&format!("login window url: {current}"));
            last_url = current.as_str().to_owned();
        }

        // Marker for the one provider that needs more than "sign in and return":
        // the flow is a modelscope one as soon as a modelscope page shows up.
        if !modelscope_flow && is_modelscope(&current) {
            modelscope_flow = true;
            log_note("login window detected a modelscope flow: it needs the workspace step");
        }

        // v1 only follows the DSW chain (gateway -> aliyun -> modelscope). A hop
        // anywhere else fails at once instead of waiting for the timeout.
        let current_host = current.host_str().unwrap_or_default();
        if current_host != gateway_host && !supported_provider(current_host) {
            let _ = window.destroy();
            return Err(format!(
                "unsupported sign-in flow: the window was sent to `{current}`, which is neither \
                 the DSW gateway nor an aliyun/modelscope provider"
            ));
        }

        // `navigate` returns before the new document is committed, so the URL
        // still reads as the old page for a poll or two. Without this guard the
        // same error page would be seen again right after the recovery
        // navigation and the recovery budget would be used up instantly.
        if let Some(stale) = navigating_from.clone() {
            if stale == current.as_str() {
                continue;
            }
            navigating_from = None;
        }

        // modelscope reports a rejected sign-in by landing on its own error page
        // (`https://modelscope.cn/error?...&code=-30`): its session is missing, so
        // give the user one chance to sign in there before giving up. Other
        // providers are left alone.
        if modelscope_flow && is_error_page(&current) {
            let on_gateway = current.host_str().unwrap_or_default() == gateway_host;
            if !on_gateway && recoveries < 2 {
                recoveries += 1;
                workspace_visited = false;
                let mut root = current.clone();
                root.set_path("/");
                root.set_query(None);
                root.set_fragment(None);
                log_note(&format!(
                    "login window hit {current}, opening {root} to sign in"
                ));
                navigating_from = Some(current.as_str().to_owned());
                let _ = window.navigate(root);
                foreign_since = None;
                stable_samples = 0;
                last_sample.clear();
                continue;
            }
            let _ = window.destroy();
            return Err(format!(
                "the sign-in flow ended on an error page: {current}"
            ));
        }

        let Ok(cookies) = window.cookies() else {
            continue;
        };

        let fresh: Vec<(String, String)> = cookies
            .iter()
            .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
            .collect();
        if fresh.is_empty() {
            continue;
        }
        collected = fresh;

        // The gateways this flow runs into set their session cookie on their own
        // host: the WebSocket upgrade is accepted only with that cookie. Wait for
        // the browser to be back there (the sign-in redirect carries the gateway
        // as its callback), but do not wait forever: a provider that hands the
        // browser back to its own site instead is harvested from there.
        if current.host_str().unwrap_or_default() != gateway_host {
            stable_samples = 0;
            last_sample.clear();
            if is_login_page(&current) {
                // Still on a provider login page: the user has not finished yet.
                foreign_since = None;
            } else {
                match foreign_since {
                    None => foreign_since = Some(Instant::now()),
                    Some(since)
                        if modelscope_flow
                            && !workspace_visited
                            && since.elapsed() >= WORKSPACE_GRACE =>
                    {
                        // modelscope only hands out the gateway token after its
                        // workspace page has been opened with a signed-in session.
                        workspace_visited = true;
                        foreign_since = None;
                        log_note(&format!(
                            "login window signed in on {current}, opening {WORKSPACE_URL}"
                        ));
                        navigating_from = Some(current.as_str().to_owned());
                        if let Ok(workspace) = url::Url::parse(WORKSPACE_URL) {
                            let _ = window.navigate(workspace);
                        }
                    }
                    Some(since)
                        if !navigated_back
                            && since.elapsed()
                                >= if modelscope_flow {
                                    WORKSPACE_GRACE
                                } else {
                                    BACK_TO_GATEWAY_GRACE
                                } =>
                    {
                        // Signed in: return to the gateway so it can set the
                        // session cookie the tunnel needs.
                        navigated_back = true;
                        foreign_since = None;
                        log_note(&format!(
                            "login window done with {current}, going back to the gateway"
                        ));
                        navigating_from = Some(current.as_str().to_owned());
                        let _ = window.navigate(gateway.clone());
                    }
                    Some(since) if navigated_back && since.elapsed() >= FOREIGN_GRACE => {
                        log_note(&format!(
                            "login window settled on {current}: {}",
                            describe_cookies(&window)
                        ));
                        let _ = window.destroy();
                        return Ok(collected);
                    }
                    Some(_) => {}
                }
            }
            continue;
        }
        foreign_since = None;

        let mut fingerprint = collected.clone();
        fingerprint.push((current.as_str().to_owned(), String::new()));
        fingerprint.sort();
        if fingerprint == last_sample {
            stable_samples += 1;
        } else {
            last_sample = fingerprint;
            stable_samples = 0;
        }

        if stable_samples >= STABLE_SAMPLES {
            log_note(&format!(
                "login window came back to the gateway: {}",
                describe_cookies(&window)
            ));
            let _ = window.destroy();
            return Ok(collected);
        }
    }
}
