use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_HISTORY_POINTS: usize = 100_000;

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub active_connections: u64,
    pub authenticated_connections: u64,
    pub written_events_total: u64,
    pub ephemeral_events_total: u64,
    pub rejected_events_total: u64,
    pub client_messages_total: u64,
    pub relay_messages_total: u64,
    pub abuse_rejections_total: u64,
}

pub struct MetricsHistory {
    enabled: AtomicBool,
    max_points: AtomicU64,
    points: Mutex<VecDeque<MetricsSnapshot>>,
}

impl Default for MetricsHistory {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            max_points: AtomicU64::new(5_760),
            points: Mutex::new(VecDeque::new()),
        }
    }
}

impl MetricsHistory {
    pub fn configure(&self, enabled: bool, max_points: usize) {
        let max_points = max_points.min(MAX_HISTORY_POINTS);
        self.enabled.store(enabled, Ordering::Relaxed);
        self.max_points
            .store(max_points.try_into().unwrap_or(u64::MAX), Ordering::Relaxed);
        let mut points = self.points.lock();
        while points.len() > max_points {
            points.pop_front();
        }
        if !enabled || max_points == 0 {
            points.clear();
        }
    }

    fn push(&self, snapshot: MetricsSnapshot) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let maximum = self.max_points.load(Ordering::Relaxed) as usize;
        if maximum == 0 {
            return;
        }
        let mut points = self.points.lock();
        while points.len() >= maximum {
            points.pop_front();
        }
        points.push_back(snapshot);
    }

    pub fn snapshots(&self) -> Vec<MetricsSnapshot> {
        self.points.lock().iter().cloned().collect()
    }
}

#[derive(Default)]
pub struct Metrics {
    pub active_connections: AtomicU64,
    pub authenticated_connections: AtomicU64,
    pub written_events_total: AtomicU64,
    pub ephemeral_events_total: AtomicU64,
    pub dup_events_total: AtomicU64,
    pub rejected_events_total: AtomicU64,
    pub auth_challenges_sent_total: AtomicU64,
    pub auth_success_total: AtomicU64,
    pub auth_failure_total: AtomicU64,
    pub slow_client_terminations: AtomicU64,
    pub abuse_connection_rejections: AtomicU64,
    pub abuse_event_rate_rejections: AtomicU64,
    pub abuse_req_rate_rejections: AtomicU64,
    pub abuse_count_rate_rejections: AtomicU64,
    pub abuse_pow_rejections: AtomicU64,
    pub abuse_query_cost_rejections: AtomicU64,
    pub abuse_query_concurrency_rejections: AtomicU64,
    pub abuse_pubkey_quota_rejections: AtomicU64,
    pub client_event: AtomicU64,
    pub client_req: AtomicU64,
    pub client_count: AtomicU64,
    pub client_close: AtomicU64,
    pub client_auth: AtomicU64,
    pub relay_event: AtomicU64,
    pub relay_eose: AtomicU64,
    pub relay_ok: AtomicU64,
    pub relay_notice: AtomicU64,
    pub relay_closed: AtomicU64,
    pub history: MetricsHistory,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        let g = |n: &AtomicU64| n.load(Ordering::Relaxed);
        MetricsSnapshot {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            active_connections: g(&self.active_connections),
            authenticated_connections: g(&self.authenticated_connections),
            written_events_total: g(&self.written_events_total),
            ephemeral_events_total: g(&self.ephemeral_events_total),
            rejected_events_total: g(&self.rejected_events_total),
            client_messages_total: g(&self.client_event)
                + g(&self.client_req)
                + g(&self.client_count)
                + g(&self.client_close)
                + g(&self.client_auth),
            relay_messages_total: g(&self.relay_event)
                + g(&self.relay_eose)
                + g(&self.relay_ok)
                + g(&self.relay_notice)
                + g(&self.relay_closed),
            abuse_rejections_total: g(&self.abuse_connection_rejections)
                + g(&self.abuse_event_rate_rejections)
                + g(&self.abuse_req_rate_rejections)
                + g(&self.abuse_count_rate_rejections)
                + g(&self.abuse_pow_rejections)
                + g(&self.abuse_query_cost_rejections)
                + g(&self.abuse_query_concurrency_rejections)
                + g(&self.abuse_pubkey_quota_rejections),
        }
    }

    pub fn record_history(&self) {
        self.history.push(self.snapshot());
    }

    pub fn history_json(&self) -> serde_json::Value {
        serde_json::json!({
            "current": self.snapshot(),
            "points": self.history.snapshots(),
        })
    }

    pub fn render(&self) -> String {
        let g = |n: &AtomicU64| n.load(Ordering::Relaxed);
        format!(
            concat!(
                "# HELP wok_active_connections Current WebSocket/Unix connections\n",
                "# TYPE wok_active_connections gauge\n",
                "wok_active_connections {}\n",
                "# TYPE wok_authenticated_connections gauge\n",
                "wok_authenticated_connections {}\n",
                "# TYPE wok_written_events_total counter\n",
                "wok_written_events_total {}\n",
                "# TYPE wok_ephemeral_events_total counter\n",
                "wok_ephemeral_events_total {}\n",
                "# TYPE wok_dup_events_total counter\n",
                "wok_dup_events_total {}\n",
                "# TYPE wok_rejected_events_total counter\n",
                "wok_rejected_events_total {}\n",
                "# TYPE wok_auth_challenges_sent_total counter\n",
                "wok_auth_challenges_sent_total {}\n",
                "# TYPE wok_auth_success_total counter\n",
                "wok_auth_success_total {}\n",
                "# TYPE wok_auth_failure_total counter\n",
                "wok_auth_failure_total {}\n",
                "# TYPE wok_slow_client_terminations_total counter\n",
                "wok_slow_client_terminations_total {}\n",
                "# TYPE wok_abuse_rejections_total counter\n",
                "wok_abuse_rejections_total{{reason=\"connection_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"event_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"req_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"count_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"pow\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"query_cost\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"query_concurrency\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"pubkey_storage_quota\"}} {}\n",
                "# TYPE wok_client_messages_total counter\n",
                "wok_client_messages_total{{type=\"EVENT\"}} {}\n",
                "wok_client_messages_total{{type=\"REQ\"}} {}\n",
                "wok_client_messages_total{{type=\"COUNT\"}} {}\n",
                "wok_client_messages_total{{type=\"CLOSE\"}} {}\n",
                "wok_client_messages_total{{type=\"AUTH\"}} {}\n",
                "# TYPE wok_relay_messages_total counter\n",
                "wok_relay_messages_total{{type=\"EVENT\"}} {}\n",
                "wok_relay_messages_total{{type=\"EOSE\"}} {}\n",
                "wok_relay_messages_total{{type=\"OK\"}} {}\n",
                "wok_relay_messages_total{{type=\"NOTICE\"}} {}\n",
                "wok_relay_messages_total{{type=\"CLOSED\"}} {}\n",
            ),
            g(&self.active_connections),
            g(&self.authenticated_connections),
            g(&self.written_events_total),
            g(&self.ephemeral_events_total),
            g(&self.dup_events_total),
            g(&self.rejected_events_total),
            g(&self.auth_challenges_sent_total),
            g(&self.auth_success_total),
            g(&self.auth_failure_total),
            g(&self.slow_client_terminations),
            g(&self.abuse_connection_rejections),
            g(&self.abuse_event_rate_rejections),
            g(&self.abuse_req_rate_rejections),
            g(&self.abuse_count_rate_rejections),
            g(&self.abuse_pow_rejections),
            g(&self.abuse_query_cost_rejections),
            g(&self.abuse_query_concurrency_rejections),
            g(&self.abuse_pubkey_quota_rejections),
            g(&self.client_event),
            g(&self.client_req),
            g(&self.client_count),
            g(&self.client_close),
            g(&self.client_auth),
            g(&self.relay_event),
            g(&self.relay_eose),
            g(&self.relay_ok),
            g(&self.relay_notice),
            g(&self.relay_closed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_fifo_and_hard_bounded() {
        let metrics = Metrics::default();
        metrics.history.configure(true, 2);
        metrics.active_connections.store(1, Ordering::Relaxed);
        metrics.record_history();
        metrics.active_connections.store(2, Ordering::Relaxed);
        metrics.record_history();
        metrics.active_connections.store(3, Ordering::Relaxed);
        metrics.record_history();
        let points = metrics.history.snapshots();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].active_connections, 2);
        assert_eq!(points[1].active_connections, 3);

        metrics.history.configure(false, usize::MAX);
        assert!(metrics.history.snapshots().is_empty());
        assert_eq!(
            metrics.history.max_points.load(Ordering::Relaxed),
            MAX_HISTORY_POINTS as u64
        );
    }
}
