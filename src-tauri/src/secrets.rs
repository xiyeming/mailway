//! 授权码存取 —— 凭据的唯一出口
//!
//! 三条规矩，谁也别绕：
//!
//! 1. **密码不进 SQLite。**库里只存一个 `keyring_key`（「去哪取」），不存值。
//!    见 [`Store::secret_ref`] / [`Store::set_secret_ref`]。
//! 2. **密码不进日志。**下面所有日志只说「取到了 / 没取到 / 失败」，永远不打值。
//! 3. **密码不进 [`imap::Config`]。**它是每次连接时现取现用的参数，用完即弃
//!    （见 [`Conn::connect`]）。
//!
//! 底层是 freedesktop Secret Service（`org.freedesktop.secrets`），Linux 桌面
//! 通常由 gnome-keyring 或 KWallet 提供。条目按 `(service, key)` 定位：service
//! 固定 `org.mailway.app`（和 bundle id 一致），key 用 `account_secrets.keyring_key`，
//! 没存过就退回邮箱地址 —— 这样老账号不用迁移也能取到。
//!
//! keyring 返回的错误里是**条目和服务的元信息**，不含密码值，所以可以进
//! [`Error::Secret`]；但 [`Error::Secret`] 的 `user_message()` 是固定的一句话，
//! 不把内部细节甩给用户。

use keyring::Entry;

use mailway_core::error::{Error, Result};
use mailway_core::store::Store;
use mailway_core::types::Account;

const SERVICE: &str = "org.mailway.app";

/// 取某个账号的授权码。
///
/// **没存过返回 `Ok(None)`** —— 那不是错误，是「用户还没填」。调用方据此
/// 提示去设置，而不是报错。
pub fn get(store: &Store, account: &Account) -> Result<Option<String>> {
    let key = key(store, account)?;
    match Entry::new(SERVICE, &key).and_then(|e| e.get_password()) {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::Secret(format!("钥匙串读取失败: {e}"))),
    }
}

/// 写入（或覆盖）授权码，并把 `keyring_key` 记进库里。
///
/// 覆盖是幂等的：同一个 key 再写一次就是换密码，不会多出条目。
pub fn set(store: &Store, account: &Account, password: &str) -> Result<()> {
    let key = key(store, account)?;
    Entry::new(SERVICE, &key)
        .and_then(|e| e.set_password(password))
        .map_err(|e| Error::Secret(format!("钥匙串写入失败: {e}")))?;
    store.set_secret_ref(account.id, &key)?;
    Ok(())
}

/// 删掉授权码。删账号时调用，别把别人的密码留在别人的钥匙串里。
pub fn delete(store: &Store, account: &Account) -> Result<()> {
    let key = key(store, account)?;
    match Entry::new(SERVICE, &key).and_then(|e| e.delete_credential()) {
        Ok(()) => Ok(()),
        // 删一个不存在的条目算成功 —— 目的达到了
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::Secret(format!("钥匙串删除失败: {e}"))),
    }
}

/// 条目的定位名。库里有 `keyring_key` 就用它，没有就退回邮箱地址。
fn key(store: &Store, account: &Account) -> Result<String> {
    Ok(store
        .secret_ref(account.id)?
        .unwrap_or_else(|| account.email.clone()))
}
