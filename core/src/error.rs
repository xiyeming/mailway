//! 统一错误类型
//!
//! 这里刻意不把第三方 crate 的 error 类型直接 `#[from]` 进来——IMAP/解析类库的
//! error 经常不满足 `Send + Sync`，而我们整个协议层要跑在 tokio 任务里。
//! 统一转成 `String` 载荷，代价是丢失一点类型信息，换来的是调度自由。

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // ---------------------------------------------------------------- 协议层
    #[error("IMAP 错误: {0}")]
    Imap(String),

    #[error("IMAP 连接失败: {0}")]
    ImapConnect(String),

    #[error("IMAP 认证失败: {0}")]
    ImapAuth(String),

    // POP3 三条，和 IMAP 的一一对应（连不上 / 认证失败 / 协议错）。
    #[error("POP3 错误: {0}")]
    Pop3(String),

    #[error("POP3 连接失败: {0}")]
    Pop3Connect(String),

    #[error("POP3 认证失败: {0}")]
    Pop3Auth(String),

    // 发信三类，和收信的三条一一对应。「授权码不对」和「服务器连不上」
    // 对用户是两件事，提示也该不一样。
    #[error("SMTP 错误: {0}")]
    Smtp(String),

    #[error("SMTP 连接失败: {0}")]
    SmtpConnect(String),

    #[error("SMTP 认证失败: {0}")]
    SmtpAuth(String),

    #[error("MIME 解析失败: {0}")]
    Mime(String),

    /// 撰写时构造报文失败（边界撞车之类）。和 [`Error::Mime`] 分开是因为
    /// 一个说的是「别人发来的信坏了」，一个说的是「我们自己拼不出来了」，
    /// 提示也该不一样。
    #[error("MIME 构造失败: {0}")]
    Compose(String),

    // ---------------------------------------------------------------- 凭据
    // 单列一类：「取不到授权码」和「服务器连不上」对用户是两件事，提示也该
    // 不一样。**这一类的错误串绝不能带上密码本身**，调用方负责。
    #[error("读取授权码失败: {0}")]
    Secret(String),

    // ---------------------------------------------------------------- 数据层
    #[error("数据库错误: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON 错误: {0}")]
    Json(#[from] serde_json::Error),

    // ---------------------------------------------------------------- 其它
    #[error("配置错误: {0}")]
    Config(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// 给前端看的短消息。不要把堆栈或 SQL 甩给用户。
    pub fn user_message(&self) -> String {
        match self {
            Error::ImapConnect(_) => "连不上邮件服务器，检查网络和服务器地址".into(),
            Error::ImapAuth(_) => "登录失败，检查账号和密码（或授权码）".into(),
            Error::Imap(_) => "邮件服务返回了异常".into(),
            Error::SmtpConnect(_) => "连不上发信服务器，检查网络和服务器地址".into(),
            Error::SmtpAuth(_) => "发信登录失败，检查账号和授权码".into(),
            Error::Smtp(_) => "发信服务器拒绝了这封信".into(),
            Error::Mime(_) => "这封邮件的格式有问题，解析失败".into(),
            Error::Compose(_) => "这封信拼不出来，去掉附件再试一次".into(),
            Error::Secret(_) => "读不到这个账号的授权码，去账号设置里重新填一次".into(),
            Error::Db(_) => "本地数据出错".into(),
            Error::Io(_) => "本地文件读写失败".into(),
            Error::Config(m) => format!("配置有误：{m}"),
            _ => "出了点问题".into(),
        }
    }
}
