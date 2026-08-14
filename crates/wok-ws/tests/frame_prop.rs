use proptest::prelude::*;
use wok_ws::frame::{InflateCtx, Role, WsEvent, WsParser};

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
