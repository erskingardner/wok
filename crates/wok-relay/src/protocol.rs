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

impl ClientCommand {
    pub fn parse(text: &str) -> Result<Self, String> {
        if text == "\n" || text.is_empty() {
            return Ok(Self::Newline);
        }
        if !text.starts_with('[') {
            return Err("unparseable message".into());
        }
        let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let arr = v.as_array().ok_or("message is not an array")?;
        if arr.len() < 2 {
            return Err("too few array elements".into());
        }
        let cmd = arr[0]
            .as_str()
            .ok_or("first element not a command like REQ")?;
        match cmd {
            "EVENT" => Ok(Self::Event(arr[1].clone())),
            "AUTH" => Ok(Self::Auth(arr[1].clone())),
            "REQ" | "COUNT" => {
                let sub = arr[1]
                    .as_str()
                    .ok_or("subscription id was not a string")?
                    .to_string();
                Ok(if cmd == "COUNT" {
                    Self::Count {
                        sub_id: sub,
                        filters: arr[2..].to_vec(),
                    }
                } else {
                    Self::Req {
                        sub_id: sub,
                        filters: arr[2..].to_vec(),
                    }
                })
            }
            "CLOSE" => {
                if arr.len() != 2 {
                    return Err("arr too small/big".into());
                }
                Ok(Self::Close {
                    sub_id: arr[1]
                        .as_str()
                        .ok_or("CLOSE subscription id was not a string")?
                        .to_string(),
                })
            }
            "NEG-OPEN" => {
                if arr.len() < 4 {
                    return Err("negentropy query missing elements".into());
                }
                Ok(Self::NegOpen {
                    sub_id: arr[1]
                        .as_str()
                        .ok_or("NEG subscription id was not a string")?
                        .to_string(),
                    filter: arr[2].clone(),
                    payload_hex: arr[3]
                        .as_str()
                        .ok_or("negentropy payload not a string")?
                        .to_string(),
                })
            }
            "NEG-MSG" => {
                if arr.len() < 3 {
                    return Err("negentropy message missing elements".into());
                }
                Ok(Self::NegMsg {
                    sub_id: arr[1]
                        .as_str()
                        .ok_or("NEG subscription id was not a string")?
                        .to_string(),
                    payload_hex: arr[2]
                        .as_str()
                        .ok_or("negentropy payload not a string")?
                        .to_string(),
                })
            }
            "NEG-CLOSE" => Ok(Self::NegClose {
                sub_id: arr[1]
                    .as_str()
                    .ok_or("NEG subscription id was not a string")?
                    .to_string(),
            }),
            _ => Err("unknown cmd".into()),
        }
    }
}

impl RelayMessage {
    pub fn to_json(&self) -> String {
        match self {
            Self::Event { sub_id, event_json } => {
                format!("[\"EVENT\",\"{sub_id}\",{event_json}]")
            }
            Self::Eose { sub_id } => json!(["EOSE", sub_id]).to_string(),
            Self::Ok {
                event_id,
                accepted,
                message,
            } => json!(["OK", event_id, accepted, message]).to_string(),
            Self::Closed { sub_id, message } => json!(["CLOSED", sub_id, message]).to_string(),
            Self::Count {
                sub_id,
                count,
                limited,
            } => {
                let mut body = json!({ "count": count });
                if *limited {
                    body["limited"] = json!(true);
                }
                json!(["COUNT", sub_id, body]).to_string()
            }
            Self::Notice { message } => json!(["NOTICE", message]).to_string(),
            Self::Auth { challenge } => json!(["AUTH", challenge]).to_string(),
            Self::NegMsg {
                sub_id,
                payload_hex,
            } => json!(["NEG-MSG", sub_id, payload_hex]).to_string(),
            Self::NegErr {
                sub_id,
                message,
                extra,
            } => {
                if let Some(extra) = extra {
                    json!(["NEG-ERR", sub_id, message, extra]).to_string()
                } else {
                    json!(["NEG-ERR", sub_id, message]).to_string()
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
            message: format!("ERROR: {}", payload.into()),
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
}
