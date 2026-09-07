//! Exact, constant-memory comparison of a persistent tree with primary events.
use crate::{open_ro, NegError, Storage};
use wok_db::RoTxn;
use wok_event::PackedEventView;

/// Check the complete registered filter, ignoring result limits as tree writers do.
/// The caller holds one read snapshot for both primary events and tree records.
pub fn verify_tree(txn: &RoTxn<'_>, tree_id: u64, filter: &str) -> Result<u64, NegError> {
    let filter = crate::cache::parse_negentropy_filter(filter, usize::MAX, usize::MAX)?;
    let mut expected = 0u64;
    let mut error = None;
    wok_db::foreach_event_from(txn, 0, |_, raw| {
        match PackedEventView::new(raw) {
            Ok(event) => expected += u64::from(filter.does_match(event)),
            Err(e) => error = Some(NegError::msg(e.to_string())),
        }
        error.is_none()
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    let mut tree = open_ro(txn, tree_id)?;
    let actual = tree.size()?;
    if actual != expected {
        return Err(NegError::msg(format!(
            "tree {tree_id} has {actual} items; primary events require {expected}; stop the relay and run wok reindex --confirm-relay-stopped"
        )));
    }
    let mut previous = None;
    tree.iterate(0, actual as usize, |item, _| {
        let result = (|| -> Result<(), NegError> {
            if previous.is_some_and(|last| last >= *item) {
                return Err(NegError::msg("duplicate or unordered tree item"));
            }
            previous = Some(*item);
            let (_, raw) = wok_db::lookup_event_by_id_ro(txn, &item.id)?
                .ok_or_else(|| NegError::msg("tree item has no primary event"))?;
            let event = PackedEventView::new(&raw).map_err(|e| NegError::msg(e.to_string()))?;
            if event.created_at() != item.timestamp || !filter.does_match(event) {
                return Err(NegError::msg(
                    "tree item does not match primary timestamp/filter",
                ));
            }
            Ok(())
        })();
        error = result.err();
        error.is_none()
    })?;
    if let Some(error) = error {
        return Err(NegError::msg(format!(
            "tree {tree_id}: {error}; stop the relay and run wok reindex --confirm-relay-stopped"
        )));
    }
    Ok(actual)
}
