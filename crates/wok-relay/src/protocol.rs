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

/// How an inbound message failure maps to a reply, matching the catch sites
/// in C++ `RelayIngester.cpp`.
#[derive(Debug, Clone)]
pub enum ParseFailure {
    /// `bad msg: ...` -> NOTICE (envelope-level failures, unknown commands)
    BadMsg(String),
    /// `bad req: ...` -> NOTICE (REQ/COUNT failures before the sub id is known)
    BadReq(String),
    /// `bad close: ...` -> NOTICE
    BadClose(String),
    /// `negentropy error: ...` -> NOTICE
    Neg(String),
}

impl ParseFailure {
    pub fn into_message(self) -> RelayMessage {
        match self {
            Self::BadMsg(e) => RelayMessage::notice_error(format!("bad msg: {e}")),
            Self::BadReq(e) => RelayMessage::notice_error(format!("bad req: {e}")),
            Self::BadClose(e) => RelayMessage::notice_error(format!("bad close: {e}")),
            Self::Neg(e) => RelayMessage::notice_error(format!("negentropy error: {e}")),
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
                    return Err(ParseFailure::Neg(
                        "negentropy query missing elements".into(),
                    ));
                }
                Ok(Self::NegOpen {
                    sub_id: arr[1]
                        .as_str()
                        .ok_or_else(|| {
                            ParseFailure::Neg("NEG subscription id was not a string".into())
                        })?
                        .to_string(),
                    filter: std::mem::take(&mut arr[2]),
                    payload_hex: arr[3]
                        .as_str()
                        .ok_or_else(|| ParseFailure::Neg("negentropy payload not a string".into()))?
                        .to_string(),
                })
            }
            "NEG-MSG" => {
                if arr.len() < 3 {
                    return Err(ParseFailure::Neg(
                        "negentropy message missing elements".into(),
                    ));
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
                        .ok_or_else(|| ParseFailure::Neg("negentropy payload not a string".into()))?
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
                format!("[\"EVENT\",\"{sub_id}\",{event_json}]")
            }
            Self::Eose { sub_id } => encode(&("EOSE", sub_id)),
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
    fn closed_reason_keeps_machine_readable_prefix_first() {
        let message = RelayMessage::closed_error("sub", "auth-required: authenticate first");
        assert_eq!(
            message.to_json(),
            r#"["CLOSED","sub","auth-required: authenticate first"]"#
        );
    }
}
