use proptest::prelude::*;
use serde_json::Value;
use wok_event::{parse_and_verify_event, EventLimits};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_utf8_never_panics_in_strict_json_or_event_validation(
        bytes in proptest::collection::vec(any::<u8>(), 0..131_073),
    ) {
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Ok(());
        };
        if let Ok(value) = wok_event::json::parse_strict(text) {
            let _: Result<Value, _> = serde_json::from_str(text);
            let _ = parse_and_verify_event(
                &value,
                &EventLimits::default(),
                None,
                true,
                true,
            );
        }
    }
}
