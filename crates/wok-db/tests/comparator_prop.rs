use proptest::prelude::*;
use wok_db::comparators::{
    cmp_string_u64, cmp_string_u64_u64, cmp_u64_u64, make_key_string_u64, make_key_u64_u64,
};

proptest! {
    #[test]
    fn string_u64_total_order(
        a in proptest::collection::vec(any::<u8>(), 1..24),
        b in proptest::collection::vec(any::<u8>(), 1..24),
        na in any::<u64>(),
        nb in any::<u64>(),
    ) {
        let ka = make_key_string_u64(&a, na);
        let kb = make_key_string_u64(&b, nb);
        let ab = cmp_string_u64(&ka, &kb);
        let ba = cmp_string_u64(&kb, &ka);
        prop_assert_eq!(ab, ba.reverse());
        let aa = cmp_string_u64(&ka, &ka);
        prop_assert_eq!(aa, std::cmp::Ordering::Equal);
    }

    #[test]
    fn u64_u64_numeric(
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        d in any::<u64>(),
    ) {
        let ka = make_key_u64_u64(a, b);
        let kb = make_key_u64_u64(c, d);
        let got = cmp_u64_u64(&ka, &kb);
        let expect = a.cmp(&c).then(b.cmp(&d));
        prop_assert_eq!(got, expect);
    }

    #[test]
    fn string_u64_u64_prefix_then_ints(
        s in proptest::collection::vec(any::<u8>(), 1..16),
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        let k = wok_db::comparators::make_key_string_u64_u64(&s, a, b);
        prop_assert_eq!(cmp_string_u64_u64(&k, &k), std::cmp::Ordering::Equal);
    }
}
