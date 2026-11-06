<p align="center">
  <img src="src-tauri/icons/256x256.png" width="120" alt="Mailway">
</p>

<h1 align="center">Mailway</h1>

<p align="center">
  <strong>A native Wayland email client</strong> · Tauri 2 + Rust + vanilla JavaScript<br>
  Local-first · No framework · Out of the box
</p>

<p align="center">
  <a href="README.md">简体中文</a> | <b>English</b>
</p>

<p align="center">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="tests" src="https://img.shields.io/badge/tests-219%20passed-brightgreen">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Wayland-lightgrey">
  <img alt="rust" src="https://img.shields.io/badge/Rust-2021-orange">
  <img alt="tauri" src="https://img.shields.io/badge/Tauri-2-24c8db">
</p>

---

Mailway is an open-source email client for the Linux / Wayland desktop: the protocol
and data layer is written in Rust, the shell is Tauri 2, and the UI is vanilla
JavaScript with no framework. All data stays on your machine; passwords and tokens
go only into the system keyring. No telemetry.

## ✨ Features

**Mail**
- IMAP / SMTP, multiple accounts, background sync (incremental fetch, flag sync, broken-message rebuild)
- Classic three-pane layout: quick folders + account tree (unread counts) / message list / reader
- Conversation threading: messages with the same subject collapse into one stack
- Full-text search (SQLite FTS), labels, starring, pinning, two-step delete
- Inbound filter rules: auto-move / auto-mark by conditions
- Folder management (create / rename / delete)

**Compose**
- Reply / reply-all / forward, signatures, mail templates, draft autosave
- Attachments, contact autocomplete

**Contacts & Calendar**
- Local address book (CRUD + compose autocomplete)
- Calendar events with month view

**Accounts & Sign-in**
- Automatic server configuration detection (built-in ISP table → ISPDB → Autodiscover → RFC 6186 SRV fallback)
- Gmail: **Google OAuth (XOAUTH2)** via an in-app webview (PKCE) — no app passwords
- Other providers: authorization-code (password) sign-in
- Disable / remove accounts, rename accounts

**Look & Integration**
- Light / dark theme, system tray, desktop notifications (freedesktop), printing

**Security & Privacy**
- Message HTML is sanitized with `ammonia` before rendering (single security boundary), strict CSP
- Passwords and OAuth tokens live only in the system keyring (freedesktop Secret Service)
- Everything is stored in a local SQLite database; no telemetry, no analytics

## 📥 Getting Started

### Requirements

- Linux desktop (Wayland; X11 works too)
- [Rust](https://rustup.rs/) (stable, Edition 2021)
- WebKitGTK and other Tauri 2 system dependencies

**Debian / Ubuntu**

```bash
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
# keyring backend (desktops usually ship one already)
sudo apt install gnome-keyring   # or kwalletmanager
```

**Arch Linux**

```bash
sudo pacman -S --needed webkit2gtk-4.1 base-devel curl wget file \
  xdotool openssl libayatana-appindicator librsvg
```

### Build & Run

```bash
git clone https://github.com/xiyeming/mailway.git
cd mailway

# development
cargo run -p mailway

# release build
cargo build -p mailway --release
./target/release/mailway
```

> The frontend in `src/` is embedded at compile time (`frontendDist: "../src"`),
> so rebuild after changing any frontend file.

### Tests

```bash
cargo test --workspace   # 219 tests across 10 suites
```

The suite includes fake IMAP / SMTP servers and covers TLS handshakes, storage
migrations, MIME parsing, HTML sanitizing and conversation threading.

## 🔐 Google Sign-In (Gmail)

Gmail uses OAuth (XOAUTH2) and requires your own Google OAuth client (free):

1. In [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials),
   create an **OAuth client ID** of type **Desktop app**
2. Put the `Client ID` / `Client Secret` into `mailway/.cargo/config.toml`
   (already git-ignored, never committed):

```toml
[env]
MAILWAY_GOOGLE_CLIENT_ID = "xxxx.apps.googleusercontent.com"
MAILWAY_GOOGLE_CLIENT_SECRET = "GOCSPX-..."
```

3. Rebuild with `cargo build` (credentials are embedded at compile time), then
   click “Sign in with Google” when adding an account

## 🗂 Project Structure

```
mailway/
├── core/            # mailway-core: protocol & data layer (pure Rust, no GUI, unit-testable)
│   └── src/         #   IMAP / SMTP / MIME / sanitizing / SQLite store / sync / threads / rules / templates
├── src-tauri/       # Tauri 2 application shell
│   └── src/         #   IPC commands / background sync worker / tray / notifications / Google OAuth
├── src/             # frontend: vanilla JS + CSS (no framework)
├── design/          # icon source (SVG)
├── Cargo.toml       # Cargo workspace
└── LICENSE          # MIT
```

## 🏗 Architecture

| Layer | Location | Responsibility |
|---|---|---|
| Protocol & data | `core/` (`mailway-core`) | IMAP/SMTP, MIME parsing, HTML sanitizing, SQLite store, sync engine, threading |
| Shell | `src-tauri/` (`mailway`) | Tauri commands, background sync, tray, notifications, OAuth (in-app webview + PKCE) |
| UI | `src/` | vanilla JavaScript three-pane interface, embedded at compile time |

Security note: message bodies are untrusted input — `core/src/sanitize.rs` is the
**only** sanitizing boundary, and cleaned HTML is injected into a fixed container.
Passwords and tokens go into the system keyring only.

## 📍 Data & Privacy

- Mail and configuration: `~/.local/share/org.mailway.app/` (local SQLite)
- Credentials / tokens: system keyring (gnome-keyring / KWallet)
- No telemetry; Google credentials are embedded locally at build time only

## 🗺 Roadmap

- [ ] Microsoft / Outlook OAuth sign-in
- [ ] CardDAV / CalDAV sync (contacts & calendar across devices)
- [ ] Read receipts (DSN), message recall
- [ ] Unified top-bar layout mode

## 🤝 Contributing

Issues and PRs are welcome. Before submitting, please make sure:

```bash
cargo test --workspace   # all green
cargo fmt --check        # formatting
```

## 📄 License

[MIT](LICENSE) © 2026 XiYeMing

Third-party components (vendored `imap-proto`, etc.) keep their own licenses. See [NOTICE](NOTICE).

This is an independently developed open-source project, not affiliated with any
email provider. When using Gmail sign-in, please follow the Google API Services
Policy and use your own OAuth credentials.
