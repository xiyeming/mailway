//! mailway-core —— 协议与数据层
//!
//! 这个 crate 是纯 Rust、不依赖任何 GUI，所有东西都可以用单元测试验。
//! Tauri 壳（`src-tauri`）只做 IPC 转发，不放业务逻辑。
//!
//! 模块划分：
//!   `error`   统一错误类型
//!   `types`   账号 / 邮件 / 文件夹等领域类型
//!   `store`   SQLite 元数据 + 原文落盘
//!   `rules`   来信分类规则 —— 条件 → 动作（纯匹配，网络动作在 `sync`）
//!   `mime`    MIME 解析
//!   `compose` MIME 构造（撰写 → RFC 5322 原文）
//!   `sanitize` HTML 净化（**安全边界**）
//!   `imap`    IMAP 连接池 / 文件夹 / 取信
//!   `smtp`    SMTP 发信
//!   `sync`    同步引擎 —— 把服务器上的信搬进本地库
//!   `send`    发信编排 —— 送出去 + APPEND 回「已发送」
//!   `thread`  会话/主题聚合的分组键（主题归一）
//!   `autoconfig` 域名自动配置（邮箱域名 → IMAP/SMTP 服务器）

pub mod autoconfig;
pub mod compose;
pub mod error;
pub mod imap;
pub mod mime;
pub mod pop3;
pub mod rules;
pub mod sanitize;
pub mod send;
pub mod smtp;
pub mod store;
pub mod sync;
pub mod thread;
pub mod types;

pub use error::{Error, Result};
pub use store::Store;
