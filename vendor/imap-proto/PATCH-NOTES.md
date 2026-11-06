# imap-proto 0.10.2（vendored + 补丁）

- **来源**：crates.io 的 `imap-proto` 0.10.2（`imap` 2.4.1 的传递依赖）。
- **许可**：MIT OR Apache-2.0（© rust-imap contributors），原始 license 文本随附在本目录（LICENSE-MIT / LICENSE-APACHE）。
- **许可证**：MIT / Apache-2.0（与上游一致）。
- **为什么 vendor**：上游 0.10.2 的响应解析器不认识**未知无标签扩展行**——
  典型是 RFC 2971 的 `* ID (...)`（163/126 邮箱要求客户端发 `ID` 声明身份，
  否则 `SELECT` 报「Unsafe Login」）。原版解析 `* ID (...)` 直接失败，
  `imap` crate 的 `read_response` 提前出错、把带标记的 `OK` 残留在连接里，
  下一条命令断言 `tag` 失败（panic）。真实服务器（imap.163.com）实测复现。

## 补丁内容（`src/parser/rfc3501.rs`）

`response_data` 的 `alt!` 末尾加一个兜底 `resp_any`：把无法识别的
`* <ATOM> [<rest>]` 行按 `Response::Data`（status=Ok，information=rest）吃掉，
让读循环继续消费后续的带标记响应。只影响「原本会硬失败」的扩展行，
所有已支持的响应解析路径不变。

对应地，`mailway` 在 IMAP 登录后发 `ID ("name" "Mailway" ...)`（RFC 2971）。
