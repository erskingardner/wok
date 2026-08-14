use proptest::prelude::*;
use wok_negentropy::{Negentropy, Vector};

fn empty_vector() -> Vector {
    let mut vector = Vector::new();
    vector.seal().unwrap();
    vector
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_protocol_frames_never_panic(
        frame in proptest::collection::vec(any::<u8>(), 0..131_073),
    ) {
        let mut responder = Negentropy::new(empty_vector(), 0).unwrap();
        let _ = responder.reconcile(&frame);

        let mut initiator = Negentropy::new(empty_vector(), 0).unwrap();
        initiator.set_initiator();
        let mut have = Vec::new();
        let mut need = Vec::new();
        let _ = initiator.reconcile_with_ids(&frame, &mut have, &mut need);
    }
}
