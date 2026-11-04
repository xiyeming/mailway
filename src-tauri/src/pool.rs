//! IMAP 连接复用池 —— 同账号的连续操作共用一条已登录连接。
//!
//! 背景：每个文件夹/标志操作都新建整条连接（TCP+TLS 握手 + LOGIN + 往返），
//! 慢网/代理下每趟 2~5 秒，连着点「新建→改名→删除」就是 10+ 秒。复用后
//! 只有第一趟付握手钱，后面只付操作本身的往返。
//!
//! 三条规矩：
//!
//! 1. **用后归还**：操作成功 → 连接回池；失败 → 丢弃（状态未知，宁可重连）。
//! 2. **出池必探活**：取出时先 `NOOP`，僵尸直接换新。探活只是一个极小的
//!    来回（比重连的 TLS+LOGIN 快一个量级）——「刚用过就不用探」的捷径
//!    不要：服务器随时可能踢线（Gmail 很凶），30 秒内死掉的连接一样会
//!    被递出去坑用户。
//! 3. **不自动重试**：操作可能是非幂等的（CREATE 走到一半断线），失败就报错，
//!    让用户决定 —— 静默重试可能把「建了一半」变成「报错但其实建好了」。
//!
//! 每账号**至多闲置一条**连接（`HashMap<i64, _>` 单槽）：并发操作各自建连，
//! 谁后归还谁留下，多余的直接丢 —— 简单、有界。
//!
//! 存活上限 [`IDLE_TTL`]：太久的连接不进池，直接丢，避免服务器端超时后
//! 我们还攥着一条死连接（探活也救不了所有场景，比如 NAT 黑洞）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mailway_core::error::Result as CoreResult;

/// 闲置超过这么久直接丢弃重建。服务器（Gmail ~30 分钟）和 NAT 都可能先掐。
const IDLE_TTL: Duration = Duration::from_secs(5 * 60);

/// 泛型连接池。`T` 一般是 [`mailway_core::imap::Conn`]，测试里用假的。
pub struct ConnPool<T> {
    idle: Mutex<HashMap<i64, (T, Instant)>>,
    connect: Box<dyn Fn(i64) -> CoreResult<T> + Send + Sync>,
    /// 探活：返回 false = 这条连接是僵尸，别用。
    probe: Box<dyn Fn(&mut T) -> bool + Send + Sync>,
}

impl<T> ConnPool<T> {
    pub fn new(
        connect: impl Fn(i64) -> CoreResult<T> + Send + Sync + 'static,
        probe: impl Fn(&mut T) -> bool + Send + Sync + 'static,
    ) -> Self {
        ConnPool {
            idle: Mutex::new(HashMap::new()),
            connect: Box::new(connect),
            probe: Box::new(probe),
        }
    }

    /// 借一条连接跑 `f`：成功归还（供下趟复用），失败丢弃。
    ///
    /// 池空/超时/僵尸 → 现建新连接。`f` **只跑一次**（见模块头规矩 3）。
    pub fn with<R>(&self, account_id: i64, f: impl FnOnce(&mut T) -> CoreResult<R>) -> CoreResult<R> {
        let mut conn = match self.take(account_id) {
            Some(c) => c,
            None => (self.connect)(account_id)?,
        };
        let out = f(&mut conn);
        if out.is_ok() {
            self.give_back(account_id, conn);
        }
        // 失败的连接不回池（状态未知：可能半死、可能 SELECT 在奇怪的箱子上）
        out
    }

    /// 取出闲置连接（按规矩 2 探活淘汰）。
    fn take(&self, account_id: i64) -> Option<T> {
        let (mut conn, at) = self.idle.lock().ok()?.remove(&account_id)?;
        if at.elapsed() > IDLE_TTL {
            return None; // 太老，丢
        }
        if !(self.probe)(&mut conn) {
            return None; // 僵尸，丢
        }
        Some(conn)
    }

    fn give_back(&self, account_id: i64, conn: T) {
        if let Ok(mut map) = self.idle.lock() {
            map.insert(account_id, (conn, Instant::now()));
        }
    }

    /// 丢掉某账号的闲置连接（删账号/改凭据时调用）。
    pub fn invalidate(&self, account_id: i64) {
        if let Ok(mut map) = self.idle.lock() {
            map.remove(&account_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// 假连接：一个序号 + 一个「坏没坏」标志。
    struct Fake {
        id: usize,
        alive: bool,
    }

    fn pool(connects: &Arc<AtomicUsize>) -> ConnPool<Fake> {
        let connects = Arc::clone(connects);
        ConnPool::new(
            move |_account_id| {
                let id = connects.fetch_add(1, Ordering::SeqCst);
                Ok(Fake { id, alive: true })
            },
            |c| c.alive,
        )
    }

    #[test]
    fn consecutive_ops_reuse_one_connection() {
        let connects = Arc::new(AtomicUsize::new(0));
        let pool = pool(&connects);
        let seen = |c: &mut Fake| Ok(c.id);
        let a = pool.with(1, seen).unwrap();
        let b = pool.with(1, seen).unwrap();
        assert_eq!(a, b, "两条操作该用同一条连接");
        assert_eq!(connects.load(Ordering::SeqCst), 1, "只该建一次连");
    }

    #[test]
    fn failed_op_discards_connection() {
        let connects = Arc::new(AtomicUsize::new(0));
        let pool = pool(&connects);
        let err: CoreResult<()> = Err(mailway_core::error::Error::Config("boom".into()));
        assert!(pool.with(1, |_| err).is_err());
        // 失败的连接不回池 —— 下一趟要新建
        pool.with(1, |_| Ok(())).unwrap();
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dead_connection_is_replaced() {
        let connects = Arc::new(AtomicUsize::new(0));
        let pool = pool(&connects);
        // 第一趟把连接弄死再归还
        pool.with(1, |c| {
            c.alive = false;
            Ok(())
        })
        .unwrap();
        // 第二趟探活发现僵尸 → 新建
        let id = pool.with(1, |c| Ok(c.id)).unwrap();
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        assert_eq!(id, 1, "第二条连接是新建的");
    }

    #[test]
    fn invalidate_drops_idle_connection() {
        let connects = Arc::new(AtomicUsize::new(0));
        let pool = pool(&connects);
        pool.with(1, |_| Ok(())).unwrap();
        pool.invalidate(1);
        pool.with(1, |_| Ok(())).unwrap();
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn accounts_do_not_share_connections() {
        let connects = Arc::new(AtomicUsize::new(0));
        let pool = pool(&connects);
        pool.with(1, |_| Ok(())).unwrap();
        pool.with(2, |_| Ok(())).unwrap();
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }
}
