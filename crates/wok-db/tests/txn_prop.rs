use proptest::prelude::*;
use std::collections::BTreeMap;
use wok_db::{Env, EnvOptions};

#[derive(Clone, Debug)]
enum Op {
    Put(u8, Vec<u8>),
    Delete(u8),
    Read(u8),
}

fn operation() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..64, proptest::collection::vec(any::<u8>(), 0..257))
            .prop_map(|(key, value)| Op::Put(key, value)),
        (0u8..64).prop_map(Op::Delete),
        (0u8..64).prop_map(Op::Read),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn transaction_sequences_match_an_owned_model(
        operations in proptest::collection::vec(operation(), 0..129),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let dbi = env.dbis().event_payload;
        let mut model = BTreeMap::<u64, Vec<u8>>::new();
        let mut txn = env.begin_rw().unwrap();

        for operation in operations {
            match operation {
                Op::Put(key, value) => {
                    txn.put_u64(dbi, key as u64, &value, 0).unwrap();
                    model.insert(key as u64, value);
                }
                Op::Delete(key) => {
                    txn.del_u64(dbi, key as u64, None).unwrap();
                    model.remove(&(key as u64));
                }
                Op::Read(key) => {
                    let actual = txn.get_u64(dbi, key as u64).unwrap().map(<[u8]>::to_vec);
                    prop_assert_eq!(actual.as_ref(), model.get(&(key as u64)));
                }
            }
        }
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        for key in 0u64..64 {
            let actual = txn.get_u64(dbi, key).unwrap().map(<[u8]>::to_vec);
            prop_assert_eq!(actual.as_ref(), model.get(&key));
        }
    }
}
