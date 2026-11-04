//! 域名自动配置（ISPDB 风格）—— 邮箱域名 → IMAP/SMTP 服务器。
//!
//! 加账号时填个邮箱，这里按域名把服务器/端口/加密方式补上，省得手抄。
//! 反编译里原版有 `data/server.cfg`（域名→服务器的纯数据表）；按 IP 红线，
//! 我们**不碰原文件**，而是按**公开的 ISPDB / Thunderbird autoconfig / 各家
//! 官方文档**里的标准配置自己写一张表 —— 服务器主机名和端口是事实数据。
//!
//! 查不到的域名给一个通用兜底（`imap.<域名>` / `smtp.<域名>`），用户可手改。

use crate::types::Security;

/// 一个域名的收发服务器配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
    /// POP3 收信（可选协议用）。域名惯例是 `imap.` → `pop.`，不适用就同 IMAP 主机。
    pub pop3_host: String,
    pub pop3_port: u16,
    pub pop3_security: Security,
}

/// 按域名惯例推 POP3 主机：`imap.example.com` → `pop.example.com`。
/// 没有 `imap.` 前缀的（如 outlook.office365.com）就用同一个主机，
/// 它们多服务口都收 POP3。
fn pop3_for(imap_host: &str) -> String {
    match imap_host.strip_prefix("imap.") {
        Some(rest) => format!("pop.{rest}"),
        None => imap_host.to_string(),
    }
}

/// 隐式 TLS 的常用端口（IMAP 993 / SMTP 465 / POP3 995）。
fn ssl(imap_host: &str, smtp_host: &str) -> ServerConfig {
    ServerConfig {
        imap_host: imap_host.into(),
        imap_port: 993,
        imap_security: Security::Ssl,
        smtp_host: smtp_host.into(),
        smtp_port: 465,
        smtp_security: Security::Ssl,
        pop3_host: pop3_for(imap_host),
        pop3_port: 995,
        pop3_security: Security::Ssl,
    }
}

/// STARTTLS 的常见形态（IMAP 993 仍可隐式 TLS；SMTP 587 走 STARTTLS）。
fn starttls(imap_host: &str, smtp_host: &str) -> ServerConfig {
    ServerConfig {
        imap_host: imap_host.into(),
        imap_port: 993,
        imap_security: Security::Ssl,
        smtp_host: smtp_host.into(),
        smtp_port: 587,
        smtp_security: Security::StartTls,
        pop3_host: pop3_for(imap_host),
        pop3_port: 995,
        pop3_security: Security::Ssl,
    }
}

/// 邮箱域名 → 收发服务器。键是小写域名。
///
/// 数据来自各家**公开文档 / ISPDB**（163/126/qq/gmail/outlook/…），
/// 不是从原版 `server.cfg` 抄的。
pub fn lookup(email: &str) -> Option<ServerConfig> {
    let domain = email.rsplit('@').next()?.trim().to_ascii_lowercase();
    // —— Yahoo 系按品牌/后缀通用（含 ymail/rocketmail）
    if domain == "ymail.com" || domain == "rocketmail.com" {
        return Some(ssl("imap.mail.yahoo.com", "smtp.mail.yahoo.com"));
    }
    if let Some(tld) = domain.strip_prefix("yahoo.") {
        // yahoo.com / yahoo.cn / yahoo.co.jp / yahoo.co.uk / yahoo.de …
        let host = format!("mail.yahoo.{tld}");
        return Some(ssl(&format!("imap.{host}"), &format!("smtp.{host}")));
    }

    let cfg = match domain.as_str() {
        // —— 网易系
        "163.com" | "126.com" | "yeah.net" | "vip.163.com" | "vip.126.com" | "188.com" => {
            let base = domain.trim_start_matches("vip.");
            let host = if domain == "yeah.net" { "yeah.net" } else { base };
            ssl(&format!("imap.{host}"), &format!("smtp.{host}"))
        }
        // —— 网易企业邮 / 企业邮
        "qiye.163.com" | "corp.netease.com" | "163.net" => {
            ssl("imap.qiye.163.com", "smtp.qiye.163.com")
        }
        // —— 腾讯系
        "qq.com" | "foxmail.com" | "vip.qq.com" => ssl("imap.qq.com", "smtp.qq.com"),
        // —— Google
        "gmail.com" | "googlemail.com" => ssl("imap.gmail.com", "smtp.gmail.com"),
        // —— 微软系（Office 365 / Outlook）
        "outlook.com" | "hotmail.com" | "live.com" | "live.cn" | "msn.com" => {
            starttls("outlook.office365.com", "smtp.office365.com")
        }
        // —— Apple
        "icloud.com" | "me.com" | "mac.com" => starttls("imap.mail.me.com", "smtp.mail.me.com"),
        // —— 新浪
        "sina.com" | "sina.cn" | "vip.sina.com" => ssl("imap.sina.com", "smtp.sina.com"),
        // —— 移动 / 电信
        "139.com" => ssl("imap.10086.cn", "smtp.10086.cn"),
        "189.cn" => ssl("imap.189.cn", "smtp.189.cn"),
        // —— 其它国内主流
        "sohu.com" => ssl("imap.sohu.com", "smtp.sohu.com"),
        "aliyun.com" | "aliyun.cn" => ssl("imap.aliyun.com", "smtp.aliyun.com"),
        "tom.com" => ssl("imap.tom.com", "smtp.tom.com"),
        "138.com" => ssl("imap.138.com", "smtp.138.com"),
        "263.net" | "263.com.cn" | "x263.net" => ssl("imap.263.net", "smtp.263.net"),
        "21cn.com" | "21cn.net" => ssl("imap.21cn.com", "smtp.21cn.com"),
        "china.com" => ssl("imap.china.com", "smtp.china.com"),
        "wo.cn" | "wo.com.cn" => ssl("imap.wo.cn", "smtp.wo.cn"),
        // —— 国外主流
        "aol.com" => ssl("imap.aol.com", "smtp.aol.com"),
        "zoho.com" | "zoho.eu" | "zoho.com.cn" | "zohomail.com" => {
            let h = if domain == "zohomail.com" { "zoho.com" } else { &domain };
            ssl(&format!("imap.{h}"), &format!("smtp.{h}"))
        }
        "gmx.com" | "gmx.net" | "gmx.de" | "gmx.at" | "gmx.ch" | "gmx.es" | "gmx.fr" => {
            ssl(&format!("imap.{domain}"), &format!("smtp.{domain}"))
        }
        "mail.ru" | "inbox.ru" | "list.ru" | "bk.ru" => ssl("imap.mail.ru", "smtp.mail.ru"),
        "yandex.com" | "yandex.ru" | "ya.ru" | "yandex.by" | "yandex.kz" => {
            ssl(&format!("imap.{domain}"), &format!("smtp.{domain}"))
        }
        "fastmail.com" | "fastmail.fm" => ssl("imap.fastmail.com", "smtp.fastmail.com"),
        "hushmail.com" => ssl("imap.hushmail.com", "smtp.hushmail.com"),
        "runbox.com" | "runbox.no" => ssl("imap.runbox.com", "smtp.runbox.com"),
        "gandi.net" => ssl("imap.gandi.net", "smtp.gandi.net"),
        "mail.com" | "email.com" => ssl("imap.mail.com", "smtp.mail.com"),
        "lycos.com" | "lycosmail.com" => ssl("imap.lycos.com", "smtp.lycos.com"),
        // —— 无标准 IMAP（需专属客户端/桥），返回 None 让用户手填
        "protonmail.com" | "proton.me" | "pm.me" | "tutanota.com" | "tutamail.com" => return None,
        _ => return None,
    };
    Some(cfg)
}

/// 兜底：查不到就猜 `imap.<域名>` / `smtp.<域名>`（隐式 TLS）。用户可手改。
pub fn guess(email: &str) -> Option<ServerConfig> {
    lookup(email).or_else(|| {
        let domain = email.rsplit('@').next()?.trim().to_ascii_lowercase();
        if domain.is_empty() || !domain.contains('.') {
            return None;
        }
        Some(ssl(&format!("imap.{domain}"), &format!("smtp.{domain}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_domains() {
        let g = lookup("someone@gmail.com").unwrap();
        assert_eq!(g.imap_host, "imap.gmail.com");
        assert_eq!(g.imap_port, 993);
        assert_eq!(g.smtp_host, "smtp.gmail.com");
        assert_eq!(g.smtp_port, 465);
        // POP3 按 imap. → pop. 惯例推导
        assert_eq!(g.pop3_host, "pop.gmail.com");
        assert_eq!(g.pop3_port, 995);

        let q = lookup("a@qq.com").unwrap();
        assert_eq!(q.imap_host, "imap.qq.com");

        let o = lookup("x@outlook.com").unwrap();
        assert_eq!(o.smtp_port, 587);
        assert_eq!(o.smtp_security, Security::StartTls);

        let n = lookup("me@163.com").unwrap();
        assert_eq!(n.imap_host, "imap.163.com");
    }

    #[test]
    fn international_providers() {
        // Yahoo 系（含不同后缀/别名）
        assert_eq!(lookup("a@yahoo.com").unwrap().imap_host, "imap.mail.yahoo.com");
        assert_eq!(lookup("a@yahoo.co.jp").unwrap().imap_host, "imap.mail.yahoo.co.jp");
        assert_eq!(lookup("a@ymail.com").unwrap().imap_host, "imap.mail.yahoo.com");
        // 其它国外主流
        assert_eq!(lookup("a@aol.com").unwrap().imap_host, "imap.aol.com");
        assert_eq!(lookup("a@zoho.com").unwrap().imap_host, "imap.zoho.com");
        assert_eq!(lookup("a@gmx.de").unwrap().imap_host, "imap.gmx.de");
        assert_eq!(lookup("a@mail.ru").unwrap().smtp_host, "smtp.mail.ru");
        assert_eq!(lookup("a@yandex.ru").unwrap().imap_host, "imap.yandex.ru");
        assert_eq!(lookup("a@fastmail.com").unwrap().imap_host, "imap.fastmail.com");
    }

    #[test]
    fn domestic_providers() {
        assert_eq!(lookup("a@263.net").unwrap().imap_host, "imap.263.net");
        assert_eq!(lookup("a@21cn.com").unwrap().imap_host, "imap.21cn.com");
        assert_eq!(lookup("a@qiye.163.com").unwrap().imap_host, "imap.qiye.163.com");
        assert_eq!(lookup("a@aliyun.com").unwrap().imap_host, "imap.aliyun.com");
        assert_eq!(lookup("a@139.com").unwrap().smtp_host, "smtp.10086.cn");
    }

    #[test]
    fn no_standard_imap_returns_none() {
        // ProtonMail / Tutanota 需专属桥，不给假配置
        assert!(lookup("a@protonmail.com").is_none());
        assert!(lookup("a@tutanota.com").is_none());
    }

    #[test]
    fn domain_is_case_insensitive() {
        let a = lookup("A@GMAIL.COM").unwrap();
        let b = lookup("a@gmail.com").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn unknown_falls_back_in_guess() {
        assert!(lookup("a@unknown.example").is_none());
        let g = guess("a@unknown.example").unwrap();
        assert_eq!(g.imap_host, "imap.unknown.example");
    }
}
