//! GitHub Releases 更新检查 + AppImage 自更新。
//!
//! 检查走公开 API（`releases/latest`），无需鉴权。自更新只支持 **AppImage**
//! （`APPIMAGE` 环境变量指向自身文件，替换后重启）；deb/rpm/pkg/flatpak 的
//! 升级交给各自的包管理器，这里只提示去下载。

use serde::Serialize;

pub const REPO: &str = "xiyeming/mailway";

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UpdateInfo {
    /// 「0.0.2」
    pub version: String,
    /// 「v0.0.2」
    pub tag: String,
    pub notes: String,
    pub url: String,
    /// AppImage 资产直链（没有则 null）
    pub appimage_url: Option<String>,
}

/// `v0.0.2` / `0.0.2-1` → `(0,0,2)`。非数字尾巴直接忽略。
fn parse_ver(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.trim().trim_start_matches('v');
    let core = v.split('-').next()?;
    let mut it = core.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next().unwrap_or("0").parse().ok()?,
    ))
}

/// 有没有新版本。`current` 是当前版本（`CARGO_PKG_VERSION`）。
pub fn check(current: &str) -> Result<Option<UpdateInfo>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let resp = ureq::get(&url)
        .set("User-Agent", "mailway-updater")
        .set("Accept", "application/vnd.github+json")
        .call();
    let resp = match resp {
        Ok(r) => r,
        // 还没发过版 / 限流 —— 不是错误，安静地当作「没有更新」
        Err(ureq::Error::Status(404 | 403, _)) => return Ok(None),
        Err(ureq::Error::Status(code, _)) => return Err(format!("GitHub 返回 {code}")),
        Err(err) => return Err(format!("连不上 GitHub：{err}")),
    };
    let raw = resp
        .into_string()
        .map_err(|err| format!("读响应失败：{err}"))?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|err| format!("响应不是 JSON：{err}"))?;

    let tag = json["tag_name"].as_str().unwrap_or("");
    let Some((new_v, cur_v)) = parse_ver(tag).zip(parse_ver(current)) else {
        return Ok(None);
    };
    if new_v <= cur_v {
        return Ok(None);
    }
    let appimage_url = json["assets"]
        .as_array()
        .map(|assets| {
            assets
                .iter()
                .find(|a| {
                    a["name"]
                        .as_str()
                        .map(|n| n.ends_with(".AppImage"))
                        .unwrap_or(false)
                })
                .and_then(|a| a["browser_download_url"].as_str().map(String::from))
        })
        .flatten();
    Ok(Some(UpdateInfo {
        version: tag.trim_start_matches('v').to_string(),
        tag: tag.to_string(),
        notes: json["body"].as_str().unwrap_or("").to_string(),
        url: json["html_url"]
            .as_str()
            .unwrap_or(&format!("https://github.com/{REPO}/releases"))
            .to_string(),
        appimage_url,
    }))
}

/// 下载 AppImage 到当前 AppImage 同目录（跨盘 rename 会失败，必须同目录）。
/// 返回落盘路径。`download_update` 是命令层包装。
pub fn download_appimage(url: &str) -> Result<String, String> {
    let dir = std::env::var("APPIMAGE")
        .ok()
        .and_then(|p| std::path::Path::new(&p).parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(std::env::temp_dir);
    let dest = dir.join(".mailway-update.AppImage");
    let resp = ureq::get(url)
        .set("User-Agent", "mailway-updater")
        .call()
        .map_err(|err| format!("下载失败：{err}"))?;
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut buf)
        .map_err(|err| format!("下载中断：{err}"))?;
    if buf.len() < 1_000_000 {
        return Err("下载的文件太小，不像安装包（网络被劫持？）".into());
    }
    std::fs::write(&dest, &buf).map_err(|err| format!("写文件失败：{err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("加执行权限失败：{err}"))?;
    }
    Ok(dest.to_string_lossy().to_string())
}

/// 把下载好的 AppImage 替换到自身位置（`$APPIMAGE`），调用方随后重启。
/// 非 AppImage 安装返回 Err（提示手动升级）。
pub fn replace_self(new_path: &str) -> Result<(), String> {
    let target =
        std::env::var("APPIMAGE").map_err(|_| "当前安装方式不支持自更新（仅 AppImage），请到 GitHub 手动下载".to_string())?;
    std::fs::rename(new_path, &target).map_err(|err| format!("替换失败：{err}（可以手动下载安装）"))?;
    Ok(())
}
