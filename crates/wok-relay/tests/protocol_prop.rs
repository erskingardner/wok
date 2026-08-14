use proptest::prelude::*;
use wok_relay::ClientCommand;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_utf8_protocol_input_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..131_073),
    ) {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = ClientCommand::parse(text);
        }
    }
}
