//! OAuth 令牌的「取现用值」层。
//!
//! xoauth2 账号的 keyring 条目里存的是**令牌包** JSON：
//! `{"access":"…","refresh":"…","exp":<unix 秒>}`（前端「Google 登录」写入）。
//! 这层负责：取用时如果 access_token 快过期/已过期，就用 refresh_token
//! 换新的、写回 keyring，把现成的 access_token 交给调用方。
//!
//! 为什么不在 [`crate::secrets`] 里做：那边是**凭据的唯一出口**，存取的是
//! 不透明字节串，三条规矩（不进库/不进日志/不进 Config）与令牌语义无关；
//! 「过期了要刷新」是 OAuth 的事，放这里各管一层。
//!
//! 兼容：老条目是裸 access_token（没有 JSON）—— 原样返回，登录失败后
//! 用户重新「Google 登录」一次就升级成令牌包（Google 的 refresh_token
//! 只在首次授权给，老条目里没有）。

use serde::{Deserialize, Serialize};

use mailway_core::error::Result;
use mailway_core::store::Store;
use mailway_core::types::Account;

use crate::google_oauth;
use crate::secrets;

/// 提前这么久就算过期（时钟偏移 + 换 token 的网络耗时）。
const EXPIRY_MARGIN_SECS: i64 = 120;

/// 换令牌**全局单飞锁**：同一时刻只许一个线程在刷。
///
/// 曾经每个调用方各自刷新 —— 收信线程、发信、一堆 IMAP 操作同时发现
/// token 过期，就会并发打出 8 次 refresh（日志里实测 30ms 内 8 条
/// 「令牌已刷新」）。Google 对同一 refresh_token 的并发/高频使用会
/// 报错甚至**吊销**它；之后每次刷新失败都拿旧 access_token 顶上，
/// 发信/收信就全是 401「invalid authentication credentials」。
static REFRESH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub access: String,
    #[serde(default)]
    pub refresh: String,
    /// access_token 失效时刻（unix 秒）
    #[serde(default)]
    pub exp: i64,
}

/// 取这个账号连接时该用的「密码」：password 账号是授权码原样；
/// xoauth2 账号是**刷新后**的 access_token。没存过返回 `None`。
pub fn effective_secret(store: &Store, account: &Account) -> Result<Option<String>> {
    let Some(stored) = read_stored(store, account)? else {
        return Ok(None);
    };
    let now = now_secs();
    if !expired(&stored, now) || stored.refresh.is_empty() {
        return Ok(Some(stored.access));
    }
    refresh_singleflight(store, account)
}

/// 从钥匙串读并解析令牌包。非 xoauth2 / 老格式（裸 token）返回 `None`
/// 表示「没有可刷新的东西」，调用方按原样用。
fn read_stored(store: &Store, account: &Account) -> Result<Option<StoredToken>> {
    let Some(raw) = secrets::get(store, account)? else {
        return Ok(None);
    };
    if account.auth_type != "xoauth2" {
        // 调用方要的是原样字符串，包一层「无 refresh」的壳即可
        return Ok(Some(StoredToken {
            access: raw,
            refresh: String::new(),
            exp: 0,
        }));
    }
    let Ok(stored) = serde_json::from_str::<StoredToken>(&raw) else {
        // 老格式（裸 access_token）：拿不出 refresh_token，只能原样用。
        // 过期了登录会失败，提示重新「Google 登录」升级成令牌包。
        return Ok(Some(StoredToken {
            access: raw,
            refresh: String::new(),
            exp: 0,
        }));
    };
    Ok(Some(stored))
}

/// 过期后的刷新路径：全局锁内**双检** —— 可能拿到锁时别的线程已经刷过，
/// 直接用它写回的新 token，不再重复请求 Google。
fn refresh_singleflight(store: &Store, account: &Account) -> Result<Option<String>> {
    let _guard = REFRESH_LOCK
        .lock()
        .map_err(|_| mailway_core::error::Error::Other(anyhow::anyhow!("刷新锁被毒化")))?;

    // 双检：锁内再读一次
    let Some(stored) = read_stored(store, account)? else {
        return Ok(None);
    };
    let now = now_secs();
    if !expired(&stored, now) {
        return Ok(Some(stored.access)); // 别人刚刷好
    }
    if stored.refresh.is_empty() {
        return Ok(Some(stored.access));
    }

    match google_oauth::refresh_access_token(
        google_oauth::CLIENT_ID,
        (!google_oauth::CLIENT_SECRET.is_empty()).then_some(google_oauth::CLIENT_SECRET),
        &stored.refresh,
    ) {
        Ok(fresh) => {
            let merged = StoredToken {
                access: fresh.access_token.clone(),
                // Google 的刷新响应常常不带 refresh_token —— 留用旧的
                refresh: if fresh.refresh_token.is_empty() {
                    stored.refresh.clone()
                } else {
                    fresh.refresh_token.clone()
                },
                exp: now + fresh.expires_in.max(60) - EXPIRY_MARGIN_SECS,
            };
            if let Ok(json) = serde_json::to_string(&merged) {
                // 写回失败不影响本次连接（旧 token 照用），下轮再试写
                if let Err(e) = secrets::set(store, account, &json) {
                    tracing::warn!(account = %account.email, "刷新后的令牌写回失败: {}", e.user_message());
                }
            }
            tracing::info!(account = %account.email, "OAuth 令牌已刷新");
            Ok(Some(merged.access))
        }
        Err(e) => {
            // refresh_token 被 Google 吊销/失效（并发滥用、用户撤销、密码改动）——
            // 旧 access_token 顶上去也必是 401，不如直说，让发信/收信把
            // 「重新 Google 登录」的指引带给用户。
            if e.contains("invalid_grant") {
                return Err(mailway_core::error::Error::Other(anyhow::anyhow!(
                    "Google 授权已失效（{e}）。请删除该账号重新「Google 登录」，或在账号编辑页重走授权。"
                )));
            }
            // 其它失败（网络抖动/限流）先拿旧 token 顶一次。
            tracing::warn!(account = %account.email, "刷新 OAuth 令牌失败: {e}");
            Ok(Some(stored.access))
        }
    }
}

/// 打包成 keyring 里存的 JSON（前端「Google 登录」也按这个格式写）。
pub fn pack(access: &str, refresh: &str, expires_in: i64) -> String {
    let now = now_secs();
    serde_json::to_string(&StoredToken {
        access: access.to_string(),
        refresh: refresh.to_string(),
        exp: now + expires_in.max(60) - EXPIRY_MARGIN_SECS,
    })
    .unwrap_or_else(|_| access.to_string())
}

fn expired(t: &StoredToken, now: i64) -> bool {
    t.exp == 0 || t.exp <= now
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_roundtrip_and_expiry() {
        let json = pack("acc", "ref", 3600);
        let t: StoredToken = serde_json::from_str(&json).unwrap();
        assert_eq!(t.access, "acc");
        assert_eq!(t.refresh, "ref");
        assert!(!expired(&t, now_secs()), "刚打的包不该过期");
        assert!(expired(&t, now_secs() + 3600), "一小时后该过期");
    }

    #[test]
    fn bare_legacy_token_is_not_json() {
        assert!(serde_json::from_str::<StoredToken>("ya29.legacy").is_err());
    }

    #[test]
    fn missing_refresh_and_exp_default() {
        let t: StoredToken = serde_json::from_str(r#"{"access":"a"}"#).unwrap();
        assert!(t.refresh.is_empty());
        assert!(expired(&t, 1), "没写 exp 就当过期（宁可刷一次）");
    }
}

