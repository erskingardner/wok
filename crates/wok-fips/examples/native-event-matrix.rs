#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    platform::run()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn main() {
    eprintln!("the native FIPS event matrix is supported only on Linux, FreeBSD, and macOS");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod support;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod platform {
    use super::support::client::exchange;
    use fips::native::client::FipsAddr;
    use fips_message::HEADER_LEN;
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::io;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    const MAX_EVENT_SIZE: usize = 65_536;
    const EVENT_COMMAND_OVERHEAD: usize = r#"["EVENT",]"#.len();

    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let mut args = std::env::args().skip(1);
        let socket = args
            .next()
            .ok_or("usage: native-event-matrix SOCKET NPUB:PORT")?;
        let destination: FipsAddr = args
            .next()
            .ok_or("usage: native-event-matrix SOCKET NPUB:PORT")?
            .parse()?;
        if args.next().is_some() {
            return Err("usage: native-event-matrix SOCKET NPUB:PORT".into());
        }
        let socket = Path::new(&socket);

        let probe = exchange(
            socket,
            destination,
            r#"["REQ","fips-event-matrix-probe",{"limit":1}]"#,
            |reply| response_is(reply, "EOSE"),
        )?;
        require_eose(&probe.responses, "fips-event-matrix-probe")?;
        let chunk_payload = probe
            .max_datagram
            .checked_sub(HEADER_LEN)
            .ok_or("FIPS max datagram is smaller than the Wok framing header")?;

        let mut rng = rand::thread_rng();
        let keypair = Keypair::new(SECP256K1, &mut rng);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (_, minimum_json) = event_with_content(0, created_at, &keypair)?;

        let mut targets = BTreeSet::from([
            minimum_json.len(),
            512,
            4 * 1024,
            16 * 1024,
            32 * 1024,
            MAX_EVENT_SIZE,
        ]);
        for command_size in [
            chunk_payload.saturating_sub(1),
            chunk_payload,
            chunk_payload.saturating_add(1),
        ] {
            if let Some(event_size) = command_size.checked_sub(EVENT_COMMAND_OVERHEAD) {
                targets.insert(event_size);
            }
        }
        targets.retain(|target| *target >= minimum_json.len() && *target <= MAX_EVENT_SIZE);

        println!(
            "FIPS max_datagram={} Wok_chunk_payload={} cases={}",
            probe.max_datagram,
            chunk_payload,
            targets.len()
        );
        for (index, target) in targets.into_iter().enumerate() {
            let (event, event_json) = event_of_size(target, created_at, &keypair)?;
            let event_id = event["id"]
                .as_str()
                .ok_or("generated event id is not a string")?;
            let command = format!(r#"["EVENT",{event_json}]"#);
            let chunks = command.len().div_ceil(chunk_payload);

            let published = exchange(socket, destination, &command, |reply| {
                response_is(reply, "OK")
            })?;
            require_ok(&published.responses, event_id, true)?;

            let subscription = format!("fips-event-size-{index}");
            let request = json!(["REQ", subscription, {"ids": [event_id]}]).to_string();
            let queried = exchange(socket, destination, &request, |reply| {
                response_is_for_subscription(reply, "EOSE", &subscription)
            })?;
            require_eose(&queried.responses, &subscription)?;
            require_exact_event(&queried.responses, &subscription, &event_json)?;

            println!(
                "accepted event_json={target} command={} chunks={chunks} id={event_id}",
                command.len()
            );
        }

        let oversized_target = MAX_EVENT_SIZE + 1;
        let (oversized, oversized_json) = event_of_size(oversized_target, created_at, &keypair)?;
        let oversized_id = oversized["id"]
            .as_str()
            .ok_or("generated oversized event id is not a string")?;
        let command = format!(r#"["EVENT",{oversized_json}]"#);
        let rejected = exchange(socket, destination, &command, |reply| {
            response_is(reply, "OK")
        })?;
        require_ok(&rejected.responses, oversized_id, false)?;

        let subscription = "fips-event-oversized";
        let request = json!(["REQ", subscription, {"ids": [oversized_id]}]).to_string();
        let queried = exchange(socket, destination, &request, |reply| {
            response_is_for_subscription(reply, "EOSE", subscription)
        })?;
        require_eose(&queried.responses, subscription)?;
        require_no_event(&queried.responses, subscription)?;
        println!(
            "rejected event_json={oversized_target} command={} as expected",
            command.len()
        );
        println!("native FIPS signed-event size matrix passed");
        Ok(())
    }

    fn event_of_size(
        target: usize,
        created_at: u64,
        keypair: &Keypair,
    ) -> Result<(Value, String), Box<dyn Error>> {
        let (_, empty_json) = event_with_content(0, created_at, keypair)?;
        let content_len = target.checked_sub(empty_json.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "target event size {target} is below the minimum {}",
                    empty_json.len()
                ),
            )
        })?;
        let (event, encoded) = event_with_content(content_len, created_at, keypair)?;
        if encoded.len() != target {
            return Err(io::Error::other(format!(
                "generated event size {} did not equal target {target}",
                encoded.len()
            ))
            .into());
        }
        Ok((event, encoded))
    }

    fn event_with_content(
        content_len: usize,
        created_at: u64,
        keypair: &Keypair,
    ) -> Result<(Value, String), Box<dyn Error>> {
        let (public_key, _) = keypair.x_only_public_key();
        let mut event = json!({
            "pubkey": hex::encode(public_key.serialize()),
            "created_at": created_at,
            "kind": 1,
            "tags": [],
            "content": "x".repeat(content_len),
        });
        let id = wok_event::event_id_hash(&event)?;
        event["id"] = json!(hex::encode(id));
        let signature = SECP256K1.sign_schnorr(&id, keypair);
        event["sig"] = json!(hex::encode(signature.as_ref()));
        let encoded = wok_event::json::to_tao_string(&event);
        Ok((event, encoded))
    }

    fn response_is(reply: &str, expected: &str) -> bool {
        serde_json::from_str::<Value>(reply)
            .ok()
            .and_then(|value| value.as_array().cloned())
            .and_then(|items| items.first().cloned())
            .and_then(|kind| kind.as_str().map(str::to_owned))
            .is_some_and(|kind| kind == expected)
    }

    fn response_is_for_subscription(reply: &str, expected: &str, subscription: &str) -> bool {
        serde_json::from_str::<Value>(reply)
            .ok()
            .and_then(|value| value.as_array().cloned())
            .is_some_and(|items| {
                items.first().and_then(Value::as_str) == Some(expected)
                    && items.get(1).and_then(Value::as_str) == Some(subscription)
            })
    }

    fn require_ok(
        responses: &[String],
        event_id: &str,
        accepted: bool,
    ) -> Result<(), Box<dyn Error>> {
        let matched = responses.iter().any(|reply| {
            serde_json::from_str::<Value>(reply)
                .ok()
                .and_then(|value| value.as_array().cloned())
                .is_some_and(|items| {
                    items.first().and_then(Value::as_str) == Some("OK")
                        && items.get(1).and_then(Value::as_str) == Some(event_id)
                        && items.get(2).and_then(Value::as_bool) == Some(accepted)
                })
        });
        if !matched {
            return Err(io::Error::other(format!(
                "expected OK for event {event_id} with accepted={accepted}, got {responses:?}"
            ))
            .into());
        }
        Ok(())
    }

    fn require_eose(responses: &[String], subscription: &str) -> Result<(), Box<dyn Error>> {
        if !responses
            .iter()
            .any(|reply| response_is_for_subscription(reply, "EOSE", subscription))
        {
            return Err(io::Error::other(format!(
                "expected EOSE for {subscription}, got {responses:?}"
            ))
            .into());
        }
        Ok(())
    }

    fn require_exact_event(
        responses: &[String],
        subscription: &str,
        expected_json: &str,
    ) -> Result<(), Box<dyn Error>> {
        let events: Vec<String> = responses
            .iter()
            .filter_map(|reply| serde_json::from_str::<Value>(reply).ok())
            .filter_map(|value| {
                let items = value.as_array()?;
                (items.first()?.as_str()? == "EVENT" && items.get(1)?.as_str()? == subscription)
                    .then(|| items.get(2))
                    .flatten()
                    .map(wok_event::json::to_tao_string)
            })
            .collect();
        if events.as_slice() != [expected_json] {
            return Err(io::Error::other(format!(
                "expected one exact stored event for {subscription}, got {} event(s)",
                events.len()
            ))
            .into());
        }
        Ok(())
    }

    fn require_no_event(responses: &[String], subscription: &str) -> Result<(), Box<dyn Error>> {
        let found = responses.iter().any(|reply| {
            serde_json::from_str::<Value>(reply)
                .ok()
                .and_then(|value| value.as_array().cloned())
                .is_some_and(|items| {
                    items.first().and_then(Value::as_str) == Some("EVENT")
                        && items.get(1).and_then(Value::as_str) == Some(subscription)
                })
        });
        if found {
            return Err(io::Error::other(format!(
                "oversized event was unexpectedly stored for {subscription}"
            ))
            .into());
        }
        Ok(())
    }
}
