use proptest::prelude::*;
use wok_ws::frame::{DeflateCtx, InflateCtx, Role, WsEvent, WsParser};

fn event_len(event: &WsEvent) -> usize {
    match event {
        WsEvent::Message(_, bytes)
        | WsEvent::Ping(bytes)
        | WsEvent::Pong(bytes)
        | WsEvent::Close(bytes) => bytes.len(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_fragmented_wire_input_is_bounded(
        data in proptest::collection::vec(any::<u8>(), 0..32_769),
        chunk_size in 1usize..1025,
        max_message in 0usize..8193,
        compressed in any::<bool>(),
        server_role in any::<bool>(),
    ) {
        let inflater = compressed.then(|| InflateCtx::new(false));
        let role = if server_role { Role::Server } else { Role::Client };
        let mut parser = WsParser::with_role(max_message, inflater, role);
        for chunk in data.chunks(chunk_size) {
            match parser.feed(chunk) {
                Ok(events) => {
                    for event in events {
                        prop_assert!(event_len(&event) <= max_message.max(125));
                    }
                }
                Err(_) => break,
            }
        }
    }

    /// Releasing either side's idle compression state at any point leaves
    /// every message decoding to what was sent, with takeover on or off.
    #[test]
    fn release_points_do_not_change_what_decodes(
        messages in proptest::collection::vec(
            (proptest::collection::vec(0u8..8, 0..6_000), any::<bool>(), any::<bool>()),
            1..24,
        ),
        server_takeover in any::<bool>(),
        client_takeover in any::<bool>(),
    ) {
        let mut relay_out = DeflateCtx::new(server_takeover);
        let mut client_in = InflateCtx::new(server_takeover);
        let mut client_out = DeflateCtx::new(client_takeover);
        let mut relay_in = InflateCtx::new(client_takeover);
        for (msg, release_relay, release_client) in &messages {
            // Few distinct bytes so messages refer back into earlier ones.
            let down = relay_out.compress(msg).unwrap();
            prop_assert_eq!(&client_in.decompress(&down, 1 << 20).unwrap(), msg);
            let up = client_out.compress(msg).unwrap();
            prop_assert_eq!(&relay_in.decompress(&up, 1 << 20).unwrap(), msg);
            if *release_relay {
                // Two checks without use in between: the state is dropped.
                relay_out.release_idle();
                relay_out.release_idle();
                relay_in.release_idle();
                relay_in.release_idle();
            }
            if *release_client {
                client_out.release_idle();
                client_out.release_idle();
            }
        }
    }

    #[test]
    fn arbitrary_deflate_payload_is_bounded(
        data in proptest::collection::vec(any::<u8>(), 0..32_769),
        max_output in 0usize..8193,
        sliding in any::<bool>(),
    ) {
        if let Ok(output) = InflateCtx::new(sliding).decompress(&data, max_output) {
            prop_assert!(output.len() <= max_output);
        }
    }
}
