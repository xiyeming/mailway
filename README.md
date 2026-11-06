<p align="center">
  <img src="src-tauri/icons/256x256.png" width="120" alt="Mailway">
</p>

<h1 align="center">Mailway</h1>

<p align="center">
  <strong>原生 Wayland 邮件客户端</strong> · Tauri 2 + Rust + 原生 JavaScript<br>
  本地优先 · 无前端框架 · 开箱即用
</p>

<p align="center">
  <b>简体中文</b> | <a href="README.en.md">English</a>
</p>

<p align="center">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="tests" src="https://img.shields.io/badge/tests-219%20passed-brightgreen">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Wayland-lightgrey">
  <img alt="rust" src="https://img.shields.io/badge/Rust-2021-orange">
  <img alt="tauri" src="https://img.shields.io/badge/Tauri-2-24c8db">
</p>

---

Mailway 是一款面向 Linux / Wayland 桌面的开源邮件客户端：Rust 写协议与数据层，
Tauri 2 做应用壳，前端是无框架的原生 JavaScript。全部数据留在本地，密码与令牌
只进系统密钥环，没有任何遥测。

## ✨ 功能特性

**邮件**
- IMAP / SMTP 收发，多账号，后台自动同步（增量抓取、旗标同步、损坏信重建）
- 三栏经典布局：快捷文件夹 + 账号树（未读计数）/ 邮件列表 / 阅读视图
- 会话聚合：同一主题的多封信折叠成一条，堆叠阅读
- 全文搜索（SQLite FTS）、标签、标星、置顶、两步确认删除
- 来信分类规则：按条件自动移动 / 标记
- 文件夹管理（新建 / 重命名 / 删除）

**撰写**
- 回复 / 转发 / 全部回复，签名，邮件模板，草稿自动保存
- 附件收发，通讯录自动补全

**通讯录与日历**
- 本地通讯录（增删改查 + 撰写补全）
- 日历事件、月视图

**账号与登录**
- 输入邮箱自动识别服务器配置（内置 ISP 表 → ISPDB → Autodiscover → RFC 6186 SRV 兜底）
- Gmail：**Google OAuth（XOAUTH2）**，应用内 Webview 授权（PKCE），免授权码
- 其他邮箱：授权码（密码）登录
- 停用 / 删除账号，账号改名

**外观与集成**
- 亮色 / 暗色主题、系统托盘、桌面通知（freedesktop）、打印

**安全与隐私**
- 邮件 HTML 统一经过 `ammonia` 净化后才渲染（唯一安全边界），严格 CSP
- 授权码 / OAuth 令牌只存系统密钥环（freedesktop Secret Service）：不进数据库、不进日志
- 数据全部落在本地 SQLite，无遥测、无第三方统计

## 📥 快速开始

### 环境要求

- Linux 桌面（Wayland；X11 亦可）
- [Rust](https://rustup.rs/)（stable，Edition 2021）
- WebKitGTK 等 Tauri 2 系统依赖

**Debian / Ubuntu**

```bash
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
# 密钥环（二选一，桌面环境一般已自带）
sudo apt install gnome-keyring   # 或 kwalletmanager
```

**Arch Linux**

```bash
sudo pacman -S --needed webkit2gtk-4.1 base-devel curl wget file \
  xdotool openssl libayatana-appindicator librsvg
```

### 构建与运行

```bash
git clone https://github.com/xiyeming/mailway.git
cd mailway

# 开发运行
cargo run -p mailway

# 发布构建
cargo build -p mailway --release
./target/release/mailway
```

> 前端 `src/` 在编译期嵌入二进制（`frontendDist: "../src"`），改前端后需重新构建。

### 测试

```bash
cargo test --workspace   # 219 个测试，10 个套件
```

测试内含假 IMAP / 假 SMTP 服务器，覆盖 TLS 握手、存储迁移、MIME 解析、净化、会话聚合等。

## 🔐 Google 登录（Gmail）

Gmail 走 OAuth（XOAUTH2），需要你自己的 Google OAuth 客户端（免费）：

1. 在 [Google Cloud Console → 凭据](https://console.cloud.google.com/apis/credentials)
   创建 **OAuth 客户端 ID**，应用类型选 **桌面应用（Desktop app）**
2. 把 `Client ID` / `Client Secret` 放进 `mailway/.cargo/config.toml`（已被
   `.gitignore` 排除，不会入库）：

```toml
[env]
MAILWAY_GOOGLE_CLIENT_ID = "xxxx.apps.googleusercontent.com"
MAILWAY_GOOGLE_CLIENT_SECRET = "GOCSPX-..."
```

3. 重新 `cargo build`（凭据在编译期嵌入），启动后在添加账号里点「使用 Google 登录」

## 🗂 项目结构

```
mailway/
├── core/            # mailway-core：协议与数据层（纯 Rust，无 GUI 依赖，可单测）
│   └── src/         #   IMAP / SMTP / MIME / 净化 / SQLite 存储 / 同步 / 会话 / 规则 / 模板
├── src-tauri/       # Tauri 2 应用壳
│   └── src/         #   IPC 命令 / 后台同步 worker / 托盘 / 通知 / Google OAuth
├── src/             # 前端：原生 JS + CSS（无框架）
├── design/          # 图标源（SVG）
├── Cargo.toml       # Cargo workspace
└── LICENSE          # MIT
```

## 🏗 架构

| 层 | 位置 | 职责 |
|---|---|---|
| 协议与数据层 | `core/`（`mailway-core`） | IMAP/SMTP、MIME 解析、HTML 净化、SQLite 存储、同步引擎、会话聚合 |
| 应用壳 | `src-tauri/`（`mailway`） | Tauri 命令、后台同步、托盘、通知、OAuth（应用内 Webview + PKCE） |
| 界面 | `src/` | 原生 JavaScript 三栏 UI，编译期嵌入二进制 |

安全要点：邮件正文是不可信输入——`core/src/sanitize.rs` 是**唯一**净化边界，
净化后的 HTML 只注入固定容器；密码与令牌只进系统密钥环。

## 📍 数据与隐私

- 邮件与配置：`~/.local/share/org.mailway.app/`（本地 SQLite）
- 授权码 / 令牌：系统密钥环（gnome-keyring / KWallet）
- 无遥测、无统计上报；Google 凭据只在你本机编译期注入

## 🗺 路线图

- [ ] Microsoft / Outlook OAuth 登录
- [ ] CardDAV / CalDAV 同步（通讯录、日历跨设备）
- [ ] 已读回执（DSN）、邮件撤回
- [ ] 统一顶栏布局模式

## 🤝 贡献

欢迎 Issue 与 PR。提交前请确保：

```bash
cargo test --workspace   # 全绿
cargo fmt --check        # 格式
```

## 📄 许可证

[MIT](LICENSE) © 2026 XiYeMing

第三方组件（vendored `imap-proto` 等）保留各自许可，详见 [NOTICE](NOTICE)。

本项目是独立开发的开源软件，与任何第三方邮箱服务商无关；使用 Gmail 登录时
请遵守 Google API 服务条款，OAuth 凭据请使用你自己的。
