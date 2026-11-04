//! Google 登录（OAuth 2.0 → IMAP/SMTP XOAUTH2）。
//!
//! **对齐 wyemail**：不是外部浏览器，而是**应用内 webview 窗口「跳转 Google」授权** ——
//! 开一个 `WebviewWindow` 导航到 Google 授权页（同 wyemail 的 `InAppBrowserWindow`/`DoShowOauthWnd`），
//! 用户在里面登录授权；导航回调 `http://localhost/?code=…` 时用 `on_navigation` **拦截**取 `code`
//! （无需真 HTTP 服务器），再 POST `oauth2.googleapis.com/token` 换令牌。
//!
//! 令牌（含 `refresh_token`）只存 keyring（同密码槽），不进 settings/日志。
//! `client_id`/`client_secret` 是**用户自己的**（Google Cloud 控制台建「桌面应用」OAuth 客户端，
//! 放设置里），本应用不硬编码第三方凭据。
//!
//! 授权端点 / 令牌端点 / `scope=https://mail.google.com/` 是 Google 公开标准，自建复现；
//! 不引用 wyemail 的 `client_id=321133…`（那是网易的）。

use base64::Engine;
use std::sync::mpsc;
use std::time::Duration;

/// 授权端点（Google 公开）。
pub const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// 令牌端点（Google 公开）。
pub const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// 回调地址（loopback，同 wyemail 用 `http://localhost`）——webview 拦截即可，无需真监听。
pub const REDIRECT_URI: &str = "http://localhost";

/// Google OAuth 客户端凭据（编译期从环境注入，**代码里不放真实密钥**）。
/// 真实值在 gitignored 的 `.cargo/config.toml` 的 `[env]` 里（`cargo build` 时嵌入）；
/// 克隆者自建 Google 桌面 OAuth 客户端后自行填入。桌面 secret 不算秘密，但公开仓库存它不合适。
pub const CLIENT_ID: &str = match option_env!("MAILWAY_GOOGLE_CLIENT_ID") {
    Some(s) if !s.is_empty() => s,
    _ => "",
};
pub const CLIENT_SECRET: &str = match option_env!("MAILWAY_GOOGLE_CLIENT_SECRET") {
    Some(s) if !s.is_empty() => s,
    _ => "",
};

/// 令牌响应（`client_secret` 是可选的；桌面应用一般都带）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: i64,
    #[serde(default)]
    pub token_type: String,
}

/// 从回调 URL 里取授权码。兼容 Google 2023 起加的 `iss`（RFC 9207，会插在 `code` 前）——
/// 只按 `code=` 解析 query，不受参数顺序影响。`state` 是防 CSRF 的，这里一并核对。
pub fn extract_code(url: &str, expect_state: &str) -> Option<String> {
    let parsed = tauri::Url::parse(url).ok()?;
    let mut code = None;
    let mut state_ok = expect_state.is_empty();
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.to_string()),
            "state" if v == expect_state => state_ok = true,
            _ => {}
        }
    }
    if state_ok {
        code
    } else {
        None
    }
}

/// 用授权码换令牌（`application/x-www-form-urlencoded`）。桌面客户端用 **PKCE**
/// （`code_verifier`），不强依赖 `client_secret`（wyemail 的 secret 在服务端、二进制里没有）。
pub fn exchange_code(
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
) -> Result<Token, String> {
    let mut form = vec![
        ("code", code.to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("grant_type", "authorization_code".to_string()),
        ("code_verifier", code_verifier.to_string()),
    ];
    if let Some(s) = client_secret {
        form.push(("client_secret", s.to_string()));
    }
    post_token_form(&form)
}

/// 用 `refresh_token` 续期（令牌过期后拿新的 `access_token`）。
pub fn refresh_access_token(
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<Token, String> {
    let mut form = vec![
        ("refresh_token", refresh_token.to_string()),
        ("client_id", client_id.to_string()),
        ("grant_type", "refresh_token".to_string()),
    ];
    if let Some(s) = client_secret {
        form.push(("client_secret", s.to_string()));
    }
    post_token_form(&form)
}

fn post_token_form(form: &[(&str, String)]) -> Result<Token, String> {
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = ureq::post(TOKEN_ENDPOINT)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body);
    match resp {
        Ok(r) => {
            let text = r.into_string().map_err(|e| e.to_string())?;
            serde_json::from_str(&text).map_err(|e| format!("解析令牌响应失败：{e}"))
        }
        // 把 Google 的错误体带出来（如 invalid_client / invalid_grant），别只丢个 status code。
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(format!("换令牌失败 HTTP {code}：{text}"))
        }
        Err(e) => Err(format!("换令牌请求失败：{e}")),
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// XOAUTH2 的 SASL 串（`user=…\x01auth=Bearer …\x01\x01`）；IMAP/SMTP 登录用。
pub fn xoauth2_sasl(user: &str, token: &str) -> String {
    let raw = format!("user={user}\x01auth=Bearer {token}\x01\x01");
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// **应用内 webview 跳 Google 授权**（对齐 wyemail 的 `InAppBrowserWindow`）：开一个
/// `WebviewWindow` 导航到授权页；`on_navigation` 拦截 `http://localhost/?code=…` 提取 code
/// （无需真 HTTP 服务器），然后换令牌。用户关窗即取消。
pub fn run_in_window(app: &tauri::AppHandle) -> Result<Token, String> {
    use tauri::Manager;
    let state = random_state();
    let verifier = make_code_verifier();
    let challenge = code_challenge_s256(&verifier);
    let (tx, rx) = mpsc::channel::<String>();

    // **关键**：WebviewWindow 的 `build()` 必须在主线程跑（WebKitGTK 要求），
    // 在命令线程建会卡死/闪退——所以建窗经 `run_on_main_thread` 派发。这里的
    // `tx` 一路传进窗口的 `on_navigation`，把取到的 code 送回本函数。
    let app2 = app.clone();
    let st = state.clone();
    let ch = challenge.clone();
    app.run_on_main_thread(move || {
        let _ = build_oauth_window(&app2, &st, &ch, tx);
    })
    .map_err(|e| e.to_string())?;

    // 等 code（每秒醒一次，好在用户关窗时及时返回「已取消」）。
    let label = "google-oauth";
    let code = loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(c) => break c,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if app.get_webview_window(label).is_none() {
                    return Err("已取消 Google 登录".to_string());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("Google 登录失败".to_string()),
        }
    };
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.close();
    }
    exchange_code(CLIENT_ID, Some(CLIENT_SECRET), &code, &verifier)
}

/// 在**主线程**建 OAuth webview 窗口（`tx` 把取到的 code 送回命令线程）。
fn build_oauth_window(
    app: &tauri::AppHandle,
    state: &str,
    challenge: &str,
    tx: mpsc::Sender<String>,
) -> Result<(), String> {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
    let label = "google-oauth";
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.close(); // 关掉可能残留的旧窗
    }
    let expect_state = state.to_string();
    let _win = WebviewWindowBuilder::new(
        app,
        label,
        WebviewUrl::External(
            auth_url_with_challenge(CLIENT_ID, state, challenge)
                .parse::<tauri::Url>()
                .map_err(|e| e.to_string())?,
        ),
    )
    .title("Google 登录")
    .inner_size(560.0, 720.0)
    .center()
    .on_navigation(move |url| {
        // 只拦回调（host 是 localhost）且取到 code；Google 授权页的正常导航放行。
        let host = url.host_str().unwrap_or("");
        if host == "localhost" || host == "127.0.0.1" {
            if let Some(code) = extract_code(url.as_str(), &expect_state) {
                let _ = tx.send(code);
                return false; // 拦下，不真去连 localhost
            }
        }
        true
    })
    .build()
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 带 `state`（防 CSRF）+ PKCE `code_challenge` 的授权 URL。
fn auth_url_with_challenge(client_id: &str, state: &str, code_challenge: &str) -> String {
    let scope = "https://mail.google.com/";
    let mut url = tauri::Url::parse(AUTH_ENDPOINT).expect("AUTH_ENDPOINT 是合法 URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", REDIRECT_URI);
        q.append_pair("response_type", "code");
        q.append_pair("scope", scope);
        q.append_pair("access_type", "offline");
        q.append_pair("prompt", "consent");
        q.append_pair("state", state);
        q.append_pair("code_challenge", code_challenge);
        q.append_pair("code_challenge_method", "S256");
    }
    url.into()
}

/// PKCE `code_verifier`（43~128 字符，`[A-Za-z0-9-._~]`）。
fn make_code_verifier() -> String {
    let mut buf = [0u8; 32];
    getrandom_fill(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf) // 43 字符
}

/// PKCE `code_challenge = BASE64URL(SHA256(verifier))`。
fn code_challenge_s256(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// 随机 `state`（防 CSRF）。
fn random_state() -> String {
    let mut buf = [0u8; 16];
    getrandom_fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn getrandom_fill(buf: &mut [u8]) {
    // 用时间+地址的弱随机也够（state 只需本次会话唯一）；不引额外依赖。
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((t >> (i * 4)) as u8) ^ (i as u8).wrapping_mul(37);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_url_points_at_google_with_client_id() {
        let u = auth_url_with_challenge("cid.apps.googleusercontent.com", "st", "ch");
        assert!(u.contains("accounts.google.com"));
        assert!(u.contains("client_id=cid.apps.googleusercontent.com"));
        assert!(u.contains("mail.google.com")); // scope（值被 URL 编码）
        assert!(u.contains("state=st"));
    }

    #[test]
    fn extract_code_tolerates_iss_before_code() {
        // Google 2023+ 按 RFC 9207 把 iss 插在最前（此处不考 state，只验 iss 不影响取 code）。
        assert_eq!(
            extract_code("http://localhost/?iss=https://accounts.google.com&code=abc123", ""),
            Some("abc123".into()),
        );
    }

    #[test]
    fn extract_code_plain() {
        assert_eq!(
            extract_code("http://localhost/?code=xyz&state=st", "st"),
            Some("xyz".into()),
        );
    }

    #[test]
    fn extract_code_rejects_wrong_state() {
        assert_eq!(extract_code("http://localhost/?code=abc&state=bad", "st"), None);
    }

    #[test]
    fn xoauth2_sasl_is_base64() {
        use base64::Engine;
        let b64 = xoauth2_sasl("u@e.com", "tok");
        let raw = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        assert_eq!(raw, b"user=u@e.com\x01auth=Bearer tok\x01\x01");
    }
}
