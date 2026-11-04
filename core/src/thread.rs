//! 会话/主题聚合的分组键。
//!
//! 反编译（`libmastercore.so`）里有 `ConversationId` / `AggregationSubjectWindow`
//! —— 原版既按 References 链、也按**主题归一**聚合。我们的 messages 表不存
//! References（详情是打开时从原文重解析的），所以列表层最契合的是**主题聚合**：
//! `thread_key = 主题归一`。跨文件夹会话（收件 + 已发送同一话题）由
//! `Store::thread_messages` 按这个键取全。

/// 主题归一：去掉 `Re:` / `Fwd:` / `回复:` / `转发:` 等前缀 + 首尾空白，
/// 全小写。同一话题（`会议` / `Re: 会议` / `回复：会议`）归到一个键。
pub fn normalized_subject(subject: &str) -> String {
    let mut s = subject.trim().to_lowercase();
    // 前缀可能叠（`Re: Fwd: 会议`），循环剥到不动为止。
    loop {
        let before = s.clone();
        for p in [
            "re:", "fw:", "fwd:",
            "回复:", "回复：", "转发:", "转发：", "答复:", "答复：", "回复全部:", "回复全部：",
            "[回复]", "[转发]", "【回复】", "【转发】",
        ] {
            if let Some(rest) = s.strip_prefix(p) {
                s = rest.trim().to_string();
            }
        }
        if s == before {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::normalized_subject as ns;

    #[test]
    fn strips_reply_forward_prefixes() {
        assert_eq!(ns("会议"), ns("Re: 会议"));
        assert_eq!(ns("会议"), ns("re: Fwd: 会议"));
        assert_eq!(ns("会议"), ns("回复：会议"));
        assert_eq!(ns("会议"), ns("转发: 会议"));
        assert_eq!(ns("会议"), ns("【回复】会议"));
    }

    #[test]
    fn keeps_distinct_subjects_apart() {
        assert_ne!(ns("会议"), ns("周报"));
    }

    #[test]
    fn empty_and_whitespace() {
        assert_eq!(ns(""), "");
        assert_eq!(ns("   "), "");
        assert_eq!(ns(" Re:  会议  "), "会议");
    }
}
