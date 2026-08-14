#![no_main]

use libfuzzer_sys::fuzz_target;
use wok_negentropy::{Negentropy, Vector};
use wok_relay::ClientCommand;
use wok_ws::frame::{InflateCtx, Role, WsParser};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = wok_event::json::parse_strict(text);
        let _ = ClientCommand::parse(text);
    }
    let _ = wok_event::PackedEventView::new(data);

    for role in [Role::Server, Role::Client] {
        let mut parser = WsParser::with_role(131_072, Some(InflateCtx::new(false)), role);
        for chunk in data.chunks(257) {
            if parser.feed(chunk).is_err() {
                break;
            }
        }
    }
    let _ = InflateCtx::new(false).decompress(data, 131_072);

    let mut vector = Vector::new();
    vector.seal().unwrap();
    let mut responder = Negentropy::new(vector.clone(), 0).unwrap();
    let _ = responder.reconcile(data);
    let mut initiator = Negentropy::new(vector, 0).unwrap();
    initiator.set_initiator();
    let _ = initiator.reconcile_with_ids(data, &mut Vec::new(), &mut Vec::new());
});
