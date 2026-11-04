//! 来信分类规则 —— 「条件 → 动作」
//!
//! 规则在**收信入库那一步**执行（[`crate::sync`] 的 ingest），只管**收件箱的
//! 新信**：服务器已经分好类的信不再动，已发送、草稿这些箱子不参与。为什么
//! 只管收件箱：「来信」分类说的就是新到的信；服务器端 Sieve 已经分过一遍的
//! 再分一遍，只会把人家分好的搅乱。
//!
//! 这一层只做**纯函数匹配**和规则的形状。网络动作（IMAP `UID MOVE` /
//! `UID STORE`）在 [`crate::sync`]，库的进出在 [`crate::store`]。

use serde::{Deserialize, Serialize};

use crate::types::Mailbox;

/// 条件看信的哪一块。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    From,
    To,
    Subject,
    Body,
}

/// 条件怎么比。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Contains,
    NotContains,
    Equals,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub field: Field,
    pub op: Op,
    pub value: String,
}

/// 匹配上了做什么。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// 挪到别的文件夹。走 IMAP `UID MOVE`（RFC 6851），不是本地换行了事 ——
    /// 只改本地的话服务器上信还在收件箱，下一轮同步又拉回来，裂成两份。
    Move { folder_id: i64 },
    /// 标记已读（`\Seen`）。**本地和服务器都改**：只改本地的话下一轮
    /// `refresh_flags` 就把未读刷回来了。
    MarkRead,
    /// 加星标（`\Flagged`）。同上，两头都改。
    MarkFlagged,
    /// 加标签。**纯本地** —— IMAP 没有这个概念（见 M3 记录 §2）。
    AddLabels { labels: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub enabled: bool,
    /// **全部**条件都得中（AND）。空条件列表不匹配任何信 ——「无条件 = 全部」
    /// 太危险：一条忘写条件的移动规则会把整箱信搬空。要「全部」就明写一个
    /// 肯中的条件（比如主题包含空格以外的常见字）。
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
}

/// 匹配用的文本。调用方从解析结果拼出来（地址合成一串，正文取纯文本），
/// 这一层不碰 MIME。
#[derive(Debug, Clone, Default)]
pub struct MailText<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
}

/// 一批规则匹配下来对一封信的**总效果**。规则按顺序全部生效（不是第一条
/// 命中就停）：「老板的信加星标」和「主题含周报的挪进周报箱」该同时成立。
/// 移动只有一个 —— 信只有一个去处，**第一条**移动赢。
#[derive(Debug, Default)]
pub struct Applied {
    pub move_to: Option<i64>,
    pub mark_read: bool,
    pub mark_flagged: bool,
    pub labels: Vec<String>,
}

impl Rule {
    /// 这封信该不该吃这条规则。停用的、没条件的都不匹配（理由见字段注释）。
    pub fn matches(&self, mail: &MailText<'_>) -> bool {
        self.enabled
            && !self.conditions.is_empty()
            && self.conditions.iter().all(|c| c.matches(mail))
    }
}

impl Condition {
    /// 大小写不敏感（ASCII 折小写再比，中文不受影响）；空值不匹配 ——
    /// 「包含空串」在字面上恒真，但那多半是用户忘了填，不该把整箱信吞进去。
    pub fn matches(&self, mail: &MailText<'_>) -> bool {
        let hay = match self.field {
            Field::From => mail.from,
            Field::To => mail.to,
            Field::Subject => mail.subject,
            Field::Body => mail.body,
        };
        let needle = self.value.trim().to_lowercase();
        if needle.is_empty() {
            return false;
        }
        let hay = hay.to_lowercase();
        match self.op {
            Op::Contains => hay.contains(&needle),
            Op::NotContains => !hay.contains(&needle),
            Op::Equals => hay == needle,
        }
    }
}

/// 对一封信跑一批规则（顺序就是给出的顺序），合成总效果。
pub fn apply_all(rules: &[Rule], mail: &MailText<'_>) -> Applied {
    let mut out = Applied::default();
    for rule in rules.iter().filter(|r| r.matches(mail)) {
        for action in &rule.actions {
            match action {
                Action::Move { folder_id } => {
                    out.move_to.get_or_insert(*folder_id);
                }
                Action::MarkRead => out.mark_read = true,
                Action::MarkFlagged => out.mark_flagged = true,
                Action::AddLabels { labels } => {
                    for l in labels {
                        if !out.labels.contains(l) {
                            out.labels.push(l.clone());
                        }
                    }
                }
            }
        }
    }
    out
}

/// 地址列表拼成一串供匹配：`张三 <a@b.com>、c@d.com`。
pub fn addrs_text(list: &[Mailbox]) -> String {
    list.iter()
        .map(|m| match (&m.display, m.address.is_empty()) {
            (Some(d), false) => format!("{d} <{}>", m.address),
            (_, _) => m.address.clone(),
        })
        .collect::<Vec<_>>()
        .join("、")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(conditions: Vec<Condition>, actions: Vec<Action>) -> Rule {
        Rule {
            id: 1,
            account_id: 1,
            name: "测试规则".into(),
            enabled: true,
            conditions,
            actions,
        }
    }

    fn cond(field: Field, op: Op, value: &str) -> Condition {
        Condition { field, op, value: value.into() }
    }

    fn mail<'a>(from: &'a str, subject: &'a str, body: &'a str) -> MailText<'a> {
        MailText { from, to: "me@example.com", subject, body }
    }

    #[test]
    fn contains_matches_on_the_right_field() {
        let r = rule(vec![cond(Field::From, Op::Contains, "boss")], vec![]);
        assert!(r.matches(&mail("boss@example.com", "开会", "")));
        assert!(!r.matches(&mail("colleague@example.com", "boss 说的", "")));

        let r = rule(vec![cond(Field::Subject, Op::Contains, "周报")], vec![]);
        assert!(r.matches(&mail("a@b.com", "第 12 周周报", "")));

        let r = rule(vec![cond(Field::Body, Op::Contains, "发票")], vec![]);
        assert!(r.matches(&mail("a@b.com", "附件", "请查收发票")));
    }

    #[test]
    fn matching_is_case_insensitive_for_ascii() {
        let r = rule(vec![cond(Field::From, Op::Contains, "BOSS")], vec![]);
        assert!(r.matches(&mail("Boss@Example.com", "", "")));
    }

    #[test]
    fn conditions_are_anded() {
        let r = rule(
            vec![
                cond(Field::From, Op::Contains, "boss"),
                cond(Field::Subject, Op::Contains, "周报"),
            ],
            vec![],
        );
        assert!(r.matches(&mail("boss@x.com", "周报", "")));
        assert!(!r.matches(&mail("boss@x.com", "开会", "")));
        assert!(!r.matches(&mail("a@x.com", "周报", "")));
    }

    #[test]
    fn not_contains_and_equals() {
        let r = rule(vec![cond(Field::Subject, Op::NotContains, "广告")], vec![]);
        assert!(r.matches(&mail("a@b.com", "开会通知", "")));
        assert!(!r.matches(&mail("a@b.com", "广告：大促", "")));

        let r = rule(vec![cond(Field::Subject, Op::Equals, "验证码")], vec![]);
        assert!(r.matches(&mail("a@b.com", "验证码", "")));
        assert!(!r.matches(&mail("a@b.com", "您的验证码", "")));
    }

    #[test]
    fn disabled_and_conditionless_rules_never_match() {
        let mut r = rule(vec![cond(Field::From, Op::Contains, "boss")], vec![]);
        r.enabled = false;
        assert!(!r.matches(&mail("boss@x.com", "", "")));

        let r = rule(vec![], vec![Action::MarkRead]);
        assert!(!r.matches(&mail("anyone@x.com", "", "")), "空条件不许匹配一切");
    }

    #[test]
    fn empty_value_never_matches() {
        let r = rule(vec![cond(Field::Subject, Op::Contains, "  ")], vec![]);
        assert!(!r.matches(&mail("a@b.com", "任何主题", "")));
    }

    #[test]
    fn apply_all_merges_and_first_move_wins() {
        let rules = vec![
            rule(
                vec![cond(Field::From, Op::Contains, "boss")],
                vec![
                    Action::Move { folder_id: 7 },
                    Action::MarkRead,
                    Action::AddLabels { labels: vec!["老板".into()] },
                ],
            ),
            rule(
                vec![cond(Field::Subject, Op::Contains, "周报")],
                vec![
                    Action::Move { folder_id: 9 }, // 第二条移动不生效
                    Action::MarkFlagged,
                    Action::AddLabels { labels: vec!["老板".into(), "周报".into()] },
                ],
            ),
        ];
        let got = apply_all(&rules, &mail("boss@x.com", "第 3 周周报", ""));
        assert_eq!(got.move_to, Some(7), "第一条移动赢");
        assert!(got.mark_read && got.mark_flagged);
        assert_eq!(got.labels, vec!["老板".to_string(), "周报".to_string()], "去重合并");

        // 只中第一条
        let got = apply_all(&rules, &mail("boss@x.com", "开会", ""));
        assert_eq!(got.move_to, Some(7));
        assert!(got.mark_read && !got.mark_flagged);
        assert_eq!(got.labels, vec!["老板".to_string()]);
    }

    #[test]
    fn addrs_text_joins_for_matching() {
        let list = vec![
            Mailbox { display: Some("张三".into()), address: "a@b.com".into() },
            Mailbox { display: None, address: "c@d.com".into() },
        ];
        assert_eq!(addrs_text(&list), "张三 <a@b.com>、c@d.com");
    }

    #[test]
    fn serde_shapes_are_the_frontend_contract() {
        // 前端 src/app.js 的 submitRule 就按这套拼 JSON。这里锁死它：
        // 改字段名/标签名 = 前端断线，得两头一起改。
        use serde_json::json;

        assert_eq!(
            serde_json::to_value(&cond(Field::From, Op::NotContains, "boss")).unwrap(),
            json!({"field": "from", "op": "not_contains", "value": "boss"})
        );
        assert_eq!(
            serde_json::to_value(&Action::Move { folder_id: 3 }).unwrap(),
            json!({"kind": "move", "folder_id": 3})
        );
        assert_eq!(
            serde_json::to_value(&Action::MarkRead).unwrap(),
            json!({"kind": "mark_read"})
        );
        assert_eq!(
            serde_json::to_value(&Action::MarkFlagged).unwrap(),
            json!({"kind": "mark_flagged"})
        );
        assert_eq!(
            serde_json::to_value(&Action::AddLabels { labels: vec!["工作".into()] }).unwrap(),
            json!({"kind": "add_labels", "labels": ["工作"]})
        );

        // 反方向也得通 —— 前端发过来的就是这种字面量
        let a: Action = serde_json::from_value(json!({"kind": "move", "folder_id": 3})).unwrap();
        assert_eq!(a, Action::Move { folder_id: 3 });
    }
}
