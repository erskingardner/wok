//! Transport-neutral Nostr command and response models.

use serde_json::{json, Value};
use wok_query::SubId;

#[derive(Debug, Clone)]
pub enum ClientCommand {
    Event(Value),
    Req {
        sub_id: String,
        filters: Vec<Value>,
    },
    Count {
        sub_id: String,
        filters: Vec<Value>,
    },
    Close {
        sub_id: String,
    },
    Auth(Value),
    NegOpen {
        sub_id: String,
        filter: Value,
        payload_hex: String,
    },
    NegMsg {
        sub_id: String,
        payload_hex: String,
    },
    NegClose {
        sub_id: String,
    },
    Newline,
}

#[derive(Debug, Clone)]
pub enum RelayMessage {
    Event {
        sub_id: String,
        event_json: String,
    },
    Eose {
        sub_id: String,
        hints: EoseHints,
    },
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Closed {
        sub_id: String,
        message: String,
    },
    Count {
        sub_id: String,
        count: u64,
        limited: bool,
        hll: Option<String>,
    },
    Notice {
        message: String,
    },
    Auth {
        challenge: String,
    },
    NegMsg {
        sub_id: String,
        payload_hex: String,
    },
    NegErr {
        sub_id: String,
        message: String,
        extra: Option<Value>,
    },
}

/// NIP-67 completeness hints, sent as EOSE's third element. A hint's presence
/// is definitive, so each is set only when it holds; with none set, EOSE has
/// its two NIP-01 elements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EoseHints {
    /// Authenticating may make more stored events readable. A NIP-42
    /// challenge was sent before this EOSE.
    pub auth: bool,
    /// Every stored event matching the filters that the connection may read
    /// was sent.
    pub finish: bool,
    /// More stored events matching the filters, that the connection may
    /// read, are held than were sent.
    pub more: bool,
}

impl EoseHints {
    fn names(self) -> Vec<&'static str> {
        [
            (self.auth, "auth"),
            (self.finish, "finish"),
            (self.more, "more"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect()
    }
}

/// How an inbound message failure maps to a reply, matching the catch sites
/// in C++ `RelayIngester.cpp`.
#[derive(Debug, Clone)]
pub enum ParseFailure {
    /// `bad msg: ...` -> NOTICE (envelope-level failures, unknown commands)
    BadMsg(String),
    /// `bad req: ...` -> NOTICE (REQ/COUNT whose sub id is not a string)
    BadReq(String),
    /// `bad close: ...` -> NOTICE
    BadClose(String),
    /// `negentropy error: ...` -> NOTICE
    Neg(String),
    /// Malformed NEG-OPEN / NEG-MSG that still names its subscription. The
    /// relay answers NIP-77 NEG-ERR `invalid:`; NOTICE is only the fallback.
    NegRequest { sub_id: String, reason: String },
}

/// A NEG-OPEN / NEG-MSG failure, addressed to its subscription when the id is
/// a string so the relay can reply with NEG-ERR instead of NOTICE.
fn neg_failure(sub_id: &Value, reason: &str) -> ParseFailure {
    match sub_id.as_str() {
        Some(sub_id) => ParseFailure::NegRequest {
            sub_id: sub_id.to_string(),
            reason: reason.to_string(),
        },
        None => ParseFailure::Neg(reason.to_string()),
    }
}

impl ParseFailure {
    pub fn into_message(self) -> RelayMessage {
        match self {
            Self::BadMsg(e) => RelayMessage::notice_error(format!("bad msg: {e}")),
            Self::BadReq(e) => RelayMessage::notice_error(format!("bad req: {e}")),
            Self::BadClose(e) => RelayMessage::notice_error(format!("bad close: {e}")),
            Self::Neg(e) | Self::NegRequest { reason: e, .. } => {
                RelayMessage::notice_error(format!("negentropy error: {e}"))
            }
        }
    }
}

impl ClientCommand {
    pub fn parse(text: &str) -> Result<Self, ParseFailure> {
        // C++ treats exactly "\n" as a no-op keepalive; anything else that is
        // not a JSON array is an error.
        if text == "\n" {
            return Ok(Self::Newline);
        }
        if !text.starts_with('[') {
            return Err(ParseFailure::BadMsg("unparseable message".into()));
        }
        let v: Value =
            wok_event::json::parse_strict(text).map_err(|e| ParseFailure::BadMsg(e.to_string()))?;
        let mut arr = match v {
            Value::Array(arr) => arr,
            _ => return Err(ParseFailure::BadMsg("message is not an array".into())),
        };
        if arr.len() < 2 {
            return Err(ParseFailure::BadMsg("too few array elements".into()));
        }
        let cmd = arr[0]
            .as_str()
            .ok_or_else(|| ParseFailure::BadMsg("first element not a command like REQ".into()))?;
        match cmd {
            // Move owned values out of the parsed envelope. Cloning an EVENT
            // here duplicated its content, tags, and every nested string on
            // every inbound publication.
            "EVENT" => Ok(Self::Event(arr.swap_remove(1))),
            "AUTH" => Ok(Self::Auth(arr.swap_remove(1))),
            "REQ" | "COUNT" => {
                let sub = arr[1]
                    .as_str()
                    .ok_or_else(|| ParseFailure::BadReq("subscription id was not a string".into()))?
                    .to_string();
                Ok(if cmd == "COUNT" {
                    Self::Count {
                        sub_id: sub,
                        filters: arr.drain(2..).collect(),
                    }
                } else {
                    Self::Req {
                        sub_id: sub,
                        filters: arr.drain(2..).collect(),
                    }
                })
            }
            "CLOSE" => {
                if arr.len() != 2 {
                    return Err(ParseFailure::BadClose("arr too small/big".into()));
                }
                Ok(Self::Close {
                    sub_id: arr[1]
                        .as_str()
                        .ok_or_else(|| {
                            ParseFailure::BadClose("CLOSE subscription id was not a string".into())
                        })?
                        .to_string(),
                })
            }
            "NEG-OPEN" => {
                if arr.len() < 4 {
                    return Err(neg_failure(&arr[1], "negentropy query missing elements"));
                }
                let sub_id = arr[1].as_str().ok_or_else(|| {
                    ParseFailure::Neg("NEG subscription id was not a string".into())
                })?;
                let payload_hex = arr[3]
                    .as_str()
                    .ok_or_else(|| neg_failure(&arr[1], "negentropy payload not a string"))?;
                let (sub_id, payload_hex) = (sub_id.to_string(), payload_hex.to_string());
                Ok(Self::NegOpen {
                    sub_id,
                    filter: std::mem::take(&mut arr[2]),
                    payload_hex,
                })
            }
            "NEG-MSG" => {
                if arr.len() < 3 {
                    return Err(neg_failure(&arr[1], "negentropy message missing elements"));
                }
                Ok(Self::NegMsg {
                    sub_id: arr[1]
                        .as_str()
                        .ok_or_else(|| {
                            ParseFailure::Neg("NEG subscription id was not a string".into())
                        })?
                        .to_string(),
                    payload_hex: arr[2]
                        .as_str()
                        .ok_or_else(|| neg_failure(&arr[1], "negentropy payload not a string"))?
                        .to_string(),
                })
            }
            "NEG-CLOSE" => Ok(Self::NegClose {
                sub_id: arr[1]
                    .as_str()
                    .ok_or_else(|| {
                        ParseFailure::Neg("NEG subscription id was not a string".into())
                    })?
                    .to_string(),
            }),
            _ => Err(ParseFailure::BadMsg("unknown cmd".into())),
        }
    }
}

impl RelayMessage {
    pub fn to_json(&self) -> String {
        fn encode<T: serde::Serialize>(value: &T) -> String {
            // Serialization of these in-memory relay models cannot fail.
            serde_json::to_string(value).expect("relay message serialization")
        }
        match self {
            Self::Event { sub_id, event_json } => {
                let mut frame = String::with_capacity(sub_id.len() + event_json.len() + 12);
                frame.push_str("[\"EVENT\",");
                push_json_str(&mut frame, sub_id);
                frame.push(',');
                frame.push_str(event_json);
                frame.push(']');
                frame
            }
            Self::Eose { sub_id, hints } => {
                let names = hints.names();
                if names.is_empty() {
                    encode(&("EOSE", sub_id))
                } else {
                    encode(&("EOSE", sub_id, names))
                }
            }
            Self::Ok {
                event_id,
                accepted,
                message,
            } => encode(&("OK", event_id, accepted, message)),
            Self::Closed { sub_id, message } => encode(&("CLOSED", sub_id, message)),
            Self::Count {
                sub_id,
                count,
                limited,
                hll,
            } => {
                let mut body = json!({ "count": count });
                if *limited {
                    body["limited"] = json!(true);
                }
                if let (false, Some(hll)) = (*limited, hll) {
                    body["hll"] = json!(hll);
                }
                json!(["COUNT", sub_id, body]).to_string()
            }
            Self::Notice { message } => encode(&("NOTICE", message)),
            Self::Auth { challenge } => encode(&("AUTH", challenge)),
            Self::NegMsg {
                sub_id,
                payload_hex,
            } => encode(&("NEG-MSG", sub_id, payload_hex)),
            Self::NegErr {
                sub_id,
                message,
                extra,
            } => {
                if let Some(extra) = extra {
                    encode(&("NEG-ERR", sub_id, message, extra))
                } else {
                    encode(&("NEG-ERR", sub_id, message))
                }
            }
        }
    }

    pub fn notice_error(payload: impl Into<String>) -> Self {
        Self::Notice {
            message: format!("ERROR: {}", payload.into()),
        }
    }

    pub fn closed_error(sub_id: impl Into<String>, payload: impl Into<String>) -> Self {
        Self::Closed {
            sub_id: sub_id.into(),
            message: payload.into(),
        }
    }
}

/// Machine-readable prefixes defined by NIP-01 (plus NIP-42's `auth-required`,
/// and `unsupported`, which NIP-01's CLOSED example uses) for OK, CLOSED and
/// NEG-ERR reasons.
const REASON_PREFIXES: &[&str] = &[
    "auth-required",
    "blocked",
    "duplicate",
    "error",
    "invalid",
    "mute",
    "pow",
    "rate-limited",
    "restricted",
    "unsupported",
];

/// OK reason for a replaceable or addressable event older than the version
/// already stored. `wok sync` counts an upload refused with it as superseded.
pub const SUPERSEDED_OK_REASON: &str = "blocked: have a newer version";

/// True when `reason` already starts with a standard `prefix: ` so it can be
/// sent as is.
pub fn has_reason_prefix(reason: &str) -> bool {
    reason
        .split_once(": ")
        .is_some_and(|(prefix, _)| REASON_PREFIXES.contains(&prefix))
}

/// Append `s` as a JSON string, quotes included. It is escaped as the frames
/// that serialize a sub id (EOSE, CLOSED, COUNT, NEG-*) escape it, so an id
/// reads the same in every frame. Most ids need no escaping and are copied
/// as they are.
pub fn push_json_str(out: &mut String, s: &str) {
    if s.bytes().any(|b| b < 0x20 || b == b'"' || b == b'\\') {
        out.push_str(&serde_json::to_string(s).expect("string serialization"));
    } else {
        out.push('"');
        out.push_str(s);
        out.push('"');
    }
}

pub fn parse_sub_id(s: &str) -> Result<SubId, String> {
    SubId::new(s).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_and_req() {
        let c = ClientCommand::parse(r#"["EVENT",{"id":"x"}]"#).unwrap();
        assert!(matches!(c, ClientCommand::Event(_)));
        let c = ClientCommand::parse(r#"["REQ","s",{"kinds":[1]}]"#).unwrap();
        assert!(matches!(c, ClientCommand::Req { .. }));
        let c = ClientCommand::parse("\n").unwrap();
        assert!(matches!(c, ClientCommand::Newline));
        assert!(ClientCommand::parse("hello").is_err());
    }

    #[test]
    fn sub_ids_are_escaped_alike_in_every_frame() {
        for id in [
            "s",
            "é",
            "😀",
            "a\"b",
            "a\\b",
            "line\nbreak",
            "nul\0",
            "del\u{7f}",
            "\u{2028}",
        ] {
            let escaped = serde_json::to_string(id).unwrap();
            let mut pushed = String::new();
            push_json_str(&mut pushed, id);
            assert_eq!(pushed, escaped, "{id:?}");
            let event = RelayMessage::Event {
                sub_id: id.into(),
                event_json: "{}".into(),
            }
            .to_json();
            assert_eq!(event, format!("[\"EVENT\",{escaped},{{}}]"));
            let eose = RelayMessage::Eose {
                sub_id: id.into(),
                hints: EoseHints::default(),
            }
            .to_json();
            assert_eq!(eose, format!("[\"EOSE\",{escaped}]"));
            for frame in [event, eose, RelayMessage::closed_error(id, "x").to_json()] {
                let parsed: Value = serde_json::from_str(&frame).unwrap();
                assert_eq!(parsed[1], id, "{frame}");
            }
        }
    }

    #[test]
    fn encode_ok() {
        let s = RelayMessage::Ok {
            event_id: "ab".into(),
            accepted: true,
            message: String::new(),
        }
        .to_json();
        assert_eq!(s, r#"["OK","ab",true,""]"#);
    }

    #[test]
    fn eose_carries_nip67_hints_only_when_set() {
        let eose = |hints| RelayMessage::Eose {
            sub_id: "s".into(),
            hints,
        };
        assert_eq!(eose(EoseHints::default()).to_json(), r#"["EOSE","s"]"#);
        let finish = EoseHints {
            finish: true,
            ..EoseHints::default()
        };
        assert_eq!(eose(finish).to_json(), r#"["EOSE","s",["finish"]]"#);
        let auth_more = EoseHints {
            auth: true,
            more: true,
            ..EoseHints::default()
        };
        assert_eq!(eose(auth_more).to_json(), r#"["EOSE","s",["auth","more"]]"#);
    }

    #[test]
    fn closed_reason_keeps_machine_readable_prefix_first() {
        let message = RelayMessage::closed_error("sub", "auth-required: authenticate first");
        assert_eq!(
            message.to_json(),
            r#"["CLOSED","sub","auth-required: authenticate first"]"#
        );
    }

    #[test]
    fn reason_prefix_detection_only_accepts_standard_words() {
        assert!(has_reason_prefix(
            "restricted: too many authenticated identities"
        ));
        assert!(has_reason_prefix("auth-required: authenticate first"));
        assert!(has_reason_prefix(
            "unsupported: filter contains unknown elements"
        ));
        assert!(!has_reason_prefix("challenge string mismatch"));
        assert!(!has_reason_prefix("Write error: disk full"));
        assert!(!has_reason_prefix("restricted:no space"));
    }
}
