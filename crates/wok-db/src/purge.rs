//! Operator cleanup of replacement history retained by lossless imports.

use crate::keys::{parse_key_string_u64, u64_from_ne_checked};
use crate::txn::{RoTxn, RwTxn};
use crate::write::{delete_events, NegentropySink};
use crate::{DbError, Env};
use wok_event::{
    is_event_a_before_event_b, is_param_replaceable_kind, is_replaceable_kind, PackedEventView,
};

/// Replacement addresses with more than one stored version, and the versions
/// beyond one per address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct SupersededHistory {
    pub groups: u64,
    pub events: u64,
}

fn is_replacement_key(key: &[u8]) -> Result<bool, DbError> {
    let (_, kind) = parse_key_string_u64(key)?;
    Ok(is_replaceable_kind(kind) || is_param_replaceable_kind(kind))
}

/// One ordered replacement-index scan. Every version beyond the first at an
/// address is superseded, whichever one wins, so no event is loaded.
pub fn count_superseded_ro(txn: &RoTxn<'_>) -> Result<SupersededHistory, DbError> {
    let mut history = SupersededHistory::default();
    let mut previous = Vec::new();
    let mut members = 0u64;
    let mut error = None;
    txn.foreach_full(txn.env().dbis().event_replace, &[], &[], false, |key, _| {
        match is_replacement_key(key) {
            Ok(true) => {}
            Ok(false) => return true,
            Err(err) => {
                error = Some(err);
                return false;
            }
        }
        if previous != key {
            previous = key.to_vec();
            members = 0;
        }
        members += 1;
        if members == 2 {
            history.groups += 1;
        }
        if members > 1 {
            history.events += 1;
        }
        true
    })?;
    match error {
        Some(error) => Err(error),
        None => Ok(history),
    }
}

/// Picks each group's winner with the read comparison, so a winner hidden by
/// expiration or moderation still removes the versions it supersedes.
fn group_losers(txn: &RwTxn<'_>, members: &[u64], losers: &mut Vec<u64>) -> Result<(), DbError> {
    let event = |lev: u64| -> Result<Vec<u8>, DbError> {
        Ok(txn
            .get_u64(txn.env().dbis().event, lev)?
            .ok_or_else(|| DbError::msg("dangling replacement index entry"))?
            .to_vec())
    };
    let mut winner = members[0];
    let mut winner_raw = event(winner)?;
    for &lev in &members[1..] {
        let raw = event(lev)?;
        if is_event_a_before_event_b(
            PackedEventView::new(&winner_raw)?,
            PackedEventView::new(&raw)?,
        ) {
            losers.push(winner);
            winner = lev;
            winner_raw = raw;
        } else {
            losers.push(lev);
        }
    }
    Ok(())
}

struct Batch {
    history: SupersededHistory,
    resume_after: Option<Vec<u8>>,
}

/// Scans whole replacement-index keys ordered after `after` until at least
/// `max_entries` entries are visited, then deletes the losers it found.
/// Every completed key is a resume point, so clean groups also yield.
fn purge_batch<N: NegentropySink>(
    txn: &mut RwTxn<'_>,
    ne: &mut N,
    after: Option<&[u8]>,
    max_entries: u64,
) -> Result<Batch, DbError> {
    let mut groups: Vec<Vec<u64>> = Vec::new();
    let mut visited = 0u64;
    let mut current: Option<(Vec<u8>, bool)> = None;
    let mut resume_after = None;
    let mut error = None;
    // With no start duplicate, an existing `after` key is skipped entirely.
    txn.foreach_full(
        txn.env().dbis().event_replace,
        after.unwrap_or_default(),
        &[],
        false,
        |key, value| {
            let step = (|| {
                if current.as_ref().is_none_or(|(previous, _)| previous != key) {
                    if visited >= max_entries {
                        resume_after = current.take().map(|(previous, _)| previous);
                        return Ok(false);
                    }
                    let replacement = is_replacement_key(key)?;
                    if replacement {
                        groups.push(Vec::new());
                    }
                    current = Some((key.to_vec(), replacement));
                }
                visited += 1;
                if current
                    .as_ref()
                    .is_some_and(|(_, replacement)| *replacement)
                {
                    let members = groups.last_mut().expect("group started above");
                    members.push(u64_from_ne_checked(value)?);
                }
                Ok::<_, DbError>(true)
            })();
            step.unwrap_or_else(|err| {
                error = Some(err);
                false
            })
        },
    )?;
    if let Some(error) = error {
        return Err(error);
    }
    groups.retain(|members| members.len() > 1);
    let mut history = SupersededHistory {
        groups: groups.len() as u64,
        events: 0,
    };
    let mut losers = Vec::new();
    for members in &groups {
        history.events += members.len() as u64 - 1;
        group_losers(txn, members, &mut losers)?;
    }
    delete_events(txn, ne, losers)?;
    Ok(Batch {
        history,
        resume_after,
    })
}

/// Physically removes every superseded replaceable version, keeping the
/// winner that reads already serve. Each transaction finishes whole groups
/// and commits once it has scanned at least `max_entries_per_txn` index
/// entries, so concurrent writers interleave between batches. Groups are
/// re-evaluated in every transaction; a concurrent replacement is never undone.
pub fn purge_superseded<N: NegentropySink>(
    env: &Env,
    mut new_sink: impl FnMut() -> N,
    max_entries_per_txn: u64,
) -> Result<SupersededHistory, DbError> {
    let mut total = SupersededHistory::default();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let mut txn = env.begin_rw()?;
        let mut sink = new_sink();
        let batch = purge_batch(
            &mut txn,
            &mut sink,
            after.as_deref(),
            max_entries_per_txn.max(1),
        )?;
        txn.commit()?;
        total.groups += batch.history.groups;
        total.events += batch.history.events;
        match batch.resume_after {
            Some(key) => after = Some(key),
            None => return Ok(total),
        }
    }
}
