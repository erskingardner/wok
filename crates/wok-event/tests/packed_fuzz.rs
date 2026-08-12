use proptest::prelude::*;
use wok_event::PackedEventView;

proptest! {
    #[test]
    fn packed_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(v) = PackedEventView::new(&bytes) {
            let _ = v.id();
            let _ = v.pubkey();
            let _ = v.created_at();
            let _ = v.kind();
            let _ = v.expiration();
            let mut n = 0u32;
            v.foreach_tag(|_, _| {
                n = n.saturating_add(1);
                n < 10_000
            });
            let _ = v.tags();
            let _ = v.first_d_tag();
        }
    }
}
