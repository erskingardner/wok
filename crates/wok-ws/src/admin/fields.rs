//! What the dashboard shows for each setting, in operator order: its label,
//! what it does, what breaks when it is set too low or too high, and how to
//! edit its value. The page renders these sections as they are sent; the
//! tests below hold each input to the config key it names.

use serde::Serialize;

/// How a value is shown and edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Unit {
    /// A plain number.
    Count,
    /// A size, shown in B, KiB, MiB or GiB.
    Bytes,
    /// A duration, shown in seconds, minutes, hours, days or years.
    Seconds,
    /// A duration in microseconds, shown in µs or ms.
    Micros,
    /// A token bucket's refill, per second.
    PerSecond,
    Switch,
    Text,
    Url,
    /// `events.ephemeral_persistence`.
    Persistence,
}

/// One value of a field: where the overview and the patch carry it, and
/// the config key it is.
#[derive(Debug, Clone, Copy, Serialize)]
pub(super) struct Input {
    pub group: &'static str,
    pub name: &'static str,
    pub key: &'static str,
    pub unit: Unit,
    /// Zero turns the limit off, which the page shows as a switch.
    pub zero_off: bool,
    /// Set in the file only, so the page shows it without an input.
    pub file_only: bool,
}

impl Input {
    const fn new(group: &'static str, name: &'static str, key: &'static str, unit: Unit) -> Self {
        Self {
            group,
            name,
            key,
            unit,
            zero_off: false,
            file_only: false,
        }
    }

    const fn off(self) -> Self {
        Self {
            zero_off: true,
            ..self
        }
    }

    const fn file_only(self) -> Self {
        Self {
            file_only: true,
            ..self
        }
    }
}

/// A token bucket: its refill per second and how much may be spent at
/// once, as `[name, key]` pairs. Zero in either turns the bucket off.
const fn bucket(
    group: &'static str,
    rate: [&'static str; 2],
    burst: [&'static str; 2],
) -> [Input; 2] {
    [
        Input::new(group, rate[0], rate[1], Unit::PerSecond).off(),
        Input::new(group, burst[0], burst[1], Unit::Count).off(),
    ]
}

#[derive(Debug, Serialize)]
pub(super) struct Field {
    pub label: &'static str,
    pub help: &'static str,
    /// What breaks when the value is too low, or empty when nothing does.
    pub too_low: &'static str,
    pub too_high: &'static str,
    pub inputs: &'static [Input],
}

#[derive(Debug, Serialize)]
pub(super) struct Section {
    pub id: &'static str,
    pub title: &'static str,
    pub help: &'static str,
    pub fields: &'static [Field],
}

const fn field(
    label: &'static str,
    help: &'static str,
    too_low: &'static str,
    too_high: &'static str,
    inputs: &'static [Input],
) -> Field {
    Field {
        label,
        help,
        too_low,
        too_high,
        inputs,
    }
}

const PER_CONNECTION_REQ: [Input; 2] = bucket(
    "per_connection",
    [
        "req_rate_per_second",
        "relay.abuse.per_connection.req_rate_per_second",
    ],
    ["req_burst", "relay.abuse.per_connection.req_burst"],
);
const PER_CONNECTION_NEG_MSG: [Input; 2] = bucket(
    "per_connection",
    [
        "neg_msg_rate_per_second",
        "relay.abuse.per_connection.neg_msg_rate_per_second",
    ],
    ["neg_msg_burst", "relay.abuse.per_connection.neg_msg_burst"],
);
const PER_CONNECTION_COUNT: [Input; 2] = bucket(
    "per_connection",
    [
        "count_rate_per_second",
        "relay.abuse.per_connection.count_rate_per_second",
    ],
    ["count_burst", "relay.abuse.per_connection.count_burst"],
);
const ADDRESS_REQ: [Input; 2] = bucket(
    "abuse",
    ["req_rate_per_second", "relay.abuse.req_rate_per_second"],
    ["req_burst", "relay.abuse.req_burst"],
);
const ADDRESS_COUNT: [Input; 2] = bucket(
    "abuse",
    ["count_rate_per_second", "relay.abuse.count_rate_per_second"],
    ["count_burst", "relay.abuse.count_burst"],
);
const ADDRESS_CONNECTION: [Input; 2] = bucket(
    "abuse",
    [
        "connection_rate_per_second",
        "relay.abuse.connection_rate_per_second",
    ],
    ["connection_burst", "relay.abuse.connection_burst"],
);
const ADDRESS_EVENT: [Input; 2] = bucket(
    "abuse",
    ["event_rate_per_second", "relay.abuse.event_rate_per_second"],
    ["event_burst", "relay.abuse.event_burst"],
);
const AUTHOR_EVENT: [Input; 2] = bucket(
    "abuse",
    [
        "pubkey_event_rate_per_second",
        "relay.abuse.pubkey_event_rate_per_second",
    ],
    ["pubkey_event_burst", "relay.abuse.pubkey_event_burst"],
);
const ADDRESS_INVALID: [Input; 2] = bucket(
    "abuse",
    [
        "invalid_rate_per_second",
        "relay.abuse.invalid_rate_per_second",
    ],
    ["invalid_burst", "relay.abuse.invalid_burst"],
);

/// The editable sections, in operator order. Access comes first and is
/// shown on its own, read-only.
pub(super) const SECTIONS: &[Section] = &[
    Section {
        id: "events",
        title: "Events accepted",
        help: "What an event must meet to be stored or delivered: size, tags, timestamps and proof of work.",
        fields: &[
            field(
                "Largest event",
                "The largest event accepted, measured as its JSON.",
                "Long posts are refused, and so are Marmot Welcomes and commits in large groups, which carry the group's ratchet tree.",
                "Each event can hold that much memory while it is checked, and that much disk once stored.",
                &[Input::new("events", "max_event_size", "events.max_event_size", Unit::Bytes)],
            ),
            field(
                "Largest message",
                "The largest WebSocket message, which must hold the largest event and its envelope. Takes effect on restart.",
                "Events and REQs that fit their own limits are cut off by the connection.",
                "Each connection can hold a message that large in memory while it arrives.",
                &[Input::new("file", "max_websocket_payload_size", "relay.max_websocket_payload_size", Unit::Bytes).file_only()],
            ),
            field(
                "Tags per event",
                "The most tags one event may carry.",
                "Heavy users can't save their follow or mute lists.",
                "Every single-letter tag is an index entry, so one event can add thousands of writes.",
                &[Input::new("events", "max_num_tags", "events.max_num_tags", Unit::Count)],
            ),
            field(
                "Longest tag value",
                "The longest value of one tag. An addressable event's d tag must leave room for the a tag that names it.",
                "One long r, t or a tag gets the whole event refused.",
                "Long values take more storage in every event and index entry they are in.",
                &[Input::new("events", "max_tag_val_size", "events.max_tag_val_size", Unit::Bytes)],
            ),
            field(
                "Oldest accepted event",
                "Refuse regular events older than this. Profiles, lists, deletions and vanish requests are always accepted, whatever it is set to.",
                "Old posts can't be rebroadcast, and history can't be imported.",
                "Nothing meaningful: old events sort below new ones.",
                &[Input::new("events", "reject_older_than_secs", "events.reject_older_than_secs", Unit::Seconds).off()],
            ),
            field(
                "Future clock tolerance",
                "Refuse events dated further than this ahead of the relay's clock.",
                "Users whose clocks run fast can't post.",
                "Future-dated posts stay pinned at the top of feeds.",
                &[Input::new("events", "reject_newer_than_secs", "events.reject_newer_than_secs", Unit::Seconds)],
            ),
            field(
                "Oldest ephemeral event",
                "Refuse ephemeral events (kinds 20000 to 29999) older than this. AUTH and kind 21059 gift wraps use the windows NIP-42 and NIP-59 set.",
                "Ephemeral messages from clients with slow clocks or queues, such as NIP-46 signer replies, are lost.",
                "Old ephemeral events can be replayed to live subscribers.",
                &[Input::new("events", "reject_ephemeral_older_than_secs", "events.reject_ephemeral_older_than_secs", Unit::Seconds)],
            ),
            field(
                "Ephemeral storage",
                "Deliver ephemeral events to live subscribers only, or also keep them for their lifetime.",
                "",
                "",
                &[Input::new("events", "ephemeral_persistence", "events.ephemeral_persistence", Unit::Persistence)],
            ),
            field(
                "Ephemeral lifetime",
                "How long ephemeral events stay readable when they are kept.",
                "Clients that reconnect miss recent ephemeral events.",
                "Kept ephemeral events take more storage.",
                &[Input::new("events", "ephemeral_lifetime_secs", "events.ephemeral_lifetime_secs", Unit::Seconds)],
            ),
            field(
                "Proof of work",
                "The NIP-13 difficulty, in leading zero bits of the event id, every event must meet.",
                "More spam gets through.",
                "Most clients can't post: few mine proof of work, and Marmot clients never do.",
                &[Input::new("abuse", "min_pow_difficulty", "relay.abuse.min_pow_difficulty", Unit::Count).off()],
            ),
            field(
                "Vanish requests (NIP-62)",
                "Accept requests to erase everything an author published here.",
                "",
                "",
                &[Input::new("nip62", "enabled", "relay.nip62.enabled", Unit::Switch)],
            ),
            field(
                "Vanish relay URL",
                "The relay URL a vanish request must name to apply here. Empty uses relay.auth.service_url.",
                "",
                "",
                &[Input::new("nip62", "service_url", "relay.nip62.service_url", Unit::Url)],
            ),
        ],
    },
    Section {
        id: "queries",
        title: "Queries",
        help: "How much one REQ, COUNT or NEG-OPEN may ask for, and how many a connection may keep open.",
        fields: &[
            field(
                "Filters per request",
                "The most filters in one REQ or COUNT.",
                "Clients that batch many filters in one request are refused.",
                "One request can fan out into many scans. The query work ceiling still applies.",
                &[Input::new("limits", "max_filters_per_req", "relay.max_filters_per_req", Unit::Count)],
            ),
            field(
                "Filter size per request",
                "The JSON size of all the filters in one REQ or COUNT.",
                "Outbox clients can't fetch a large follow list in one request.",
                "More memory per subscription. The filter budget per connection caps the total.",
                &[Input::new("limits", "max_req_filter_size", "relay.max_req_filter_size", Unit::Bytes)],
            ),
            field(
                "Filter bytes per connection",
                "The JSON size of all the filters a connection's open subscriptions hold, and separately of its COUNTs not yet answered.",
                "Clients that keep many or large subscriptions open have some refused.",
                "One connection can hold that much filter memory.",
                &[Input::new("limits", "max_filter_bytes_per_connection", "relay.max_filter_bytes_per_connection", Unit::Bytes).off()],
            ),
            field(
                "Subscriptions per connection",
                "Open REQs on one connection, counting those still sending history. It also bounds the queries waiting for the concurrency cap.",
                "Apps that keep many subscriptions open have some refused.",
                "More live-matching memory per connection.",
                &[Input::new("limits", "max_subs_per_connection", "relay.max_subs_per_connection", Unit::Count)],
            ),
            field(
                "Events per filter",
                "The most events one filter returns, and the limit of a filter without one.",
                "Results are silently cut, and clients make extra round trips.",
                "More output per request. The outbound queue still bounds memory.",
                &[Input::new("limits", "max_filter_limit", "relay.max_filter_limit", Unit::Count)],
            ),
            field(
                "Events per request",
                "The most stored events one REQ returns over all its filters.",
                "Batched requests are silently truncated.",
                "One request can queue many megabytes for a slow client, who is then disconnected.",
                &[Input::new("limits", "max_total_events_per_req", "relay.max_total_events_per_req", Unit::Count).off()],
            ),
            field(
                "Tag letters per filter",
                "The most distinct tag letters, # and &, one filter may use.",
                "Comment, community and marketplace queries are refused.",
                "Small extra checks on each candidate event.",
                &[Input::new("limits", "max_tags_per_filter", "relay.max_tags_per_filter", Unit::Count)],
            ),
            field(
                "AND values per filter (NIP-91)",
                "The most values all of a filter's & keys may list. Zero turns NIP-91 off.",
                "NIP-91 queries that require several tags are refused.",
                "Each value is checked on every candidate event.",
                &[Input::new("limits", "max_and_entries", "relay.max_and_entries", Unit::Count)],
            ),
            field(
                "Events counted per COUNT",
                "The most events one COUNT filter counts. Zero turns COUNT off.",
                "Counts of popular events, such as followers or reactions, are capped.",
                "One COUNT can scan that many events.",
                &[Input::new("limits", "max_filter_limit_count", "relay.max_filter_limit_count", Unit::Count)],
            ),
            field(
                "Query work ceiling",
                "The most index work a REQ, COUNT or NEG-OPEN may need, estimated before its scan. Requests over it are refused with blocked:.",
                "Normal batched and outbox queries are refused.",
                "One request can tie up a query worker for longer.",
                &[Input::new("abuse", "max_query_work", "relay.abuse.max_query_work", Unit::Count).off()],
            ),
            field(
                "Concurrent historical queries",
                "Scans one connection runs at once; more wait their turn. Zero runs none.",
                "Busy clients see slow first results.",
                "One connection takes more than its share of the query workers.",
                &[Input::new("abuse", "max_concurrent_historical_queries", "relay.abuse.max_concurrent_historical_queries", Unit::Count)],
            ),
            field(
                "Require scoped filters",
                "Every filter must name ids, authors or a tag. This refuses enumeration such as {\"kinds\":[445]} and accepts Marmot's group, inbox, ids and directory filters.",
                "",
                "",
                &[Input::new("filters", "require_scoped_filters", "relay.filter_validation.require_scoped_filters", Unit::Switch)],
            ),
            field(
                "Kinds per filter",
                "The most kinds one filter may name.",
                "Clients that ask for many kinds at once, such as directory lookups, are refused.",
                "",
                &[Input::new("filters", "max_kinds_per_filter", "relay.filter_validation.max_kinds_per_filter", Unit::Count).off()],
            ),
            field(
                "Queryable kinds",
                "Comma-separated kinds a filter may ask for; empty allows any. Queries for other kinds are refused, even when the relay stores them.",
                "",
                "",
                &[Input::new("filters", "allowed_kinds", "relay.filter_validation.allowed_kinds", Unit::Text)],
            ),
            field(
                "Require one author or tag",
                "Every filter must name exactly one author, p tag or e tag, as strfry's plugin did. It refuses Marmot, outbox and directory filters; prefer scoped filters.",
                "",
                "",
                &[Input::new("filters", "require_author_or_tag", "relay.filter_validation.require_author_or_tag", Unit::Switch)],
            ),
        ],
    },
    Section {
        id: "rates",
        title: "Rates",
        help: "Token buckets: each refills at its rate per second and holds up to its burst. A connection has budgets of its own, under a backstop shared by every connection from one address (an IPv4 address, or an IPv6 network). Behind a reverse proxy, a client's address is the last entry of the client address header. Off, on a bucket's rate or its burst, turns that bucket off: unlimited.",
        fields: &[
            field(
                "Rate limits and quotas",
                "Every budget on this page, the storage quotas, the query work ceiling and proof of work. Off turns them all off.",
                "",
                "",
                &[Input::new("abuse", "enabled", "relay.abuse.enabled", Unit::Switch)],
            ),
            field(
                "Queries per connection",
                "REQs and NEG-OPENs one connection may send.",
                "Apps lose subscriptions at startup.",
                "One connection can keep the query workers busy. The per-address backstop and the concurrency cap still apply.",
                &PER_CONNECTION_REQ,
            ),
            field(
                "Sync rounds per connection",
                "NEG-MSG rounds of the syncs one connection has open.",
                "Clients that sync many groups or inboxes at startup are cut off.",
                "One connection can keep a sync worker busy.",
                &PER_CONNECTION_NEG_MSG,
            ),
            field(
                "COUNTs per connection",
                "COUNT requests one connection may send.",
                "Pages that show many counts lose some.",
                "Each COUNT scans every match, so one connection can run many such scans.",
                &PER_CONNECTION_COUNT,
            ),
            field(
                "Login multiplier",
                "A connection that completed NIP-42 AUTH gets this many times each per-connection budget.",
                "Logged-in clients get no more room than anonymous ones.",
                "On an open relay anyone can log in with a fresh key, so this raises every client's budget.",
                &[Input::new("per_connection", "authenticated_multiplier", "relay.abuse.per_connection.authenticated_multiplier", Unit::Count)],
            ),
            field(
                "Queries per address",
                "REQs, NEG-OPENs and NEG-MSGs from all the connections of one address: a backstop over the per-connection budgets.",
                "Users behind the same carrier NAT, office or VPN block each other.",
                "One host can open many connections and multiply its share.",
                &ADDRESS_REQ,
            ),
            field(
                "COUNTs per address",
                "COUNT requests from all the connections of one address.",
                "Users behind a shared network lose counts.",
                "One host can open many connections and run more COUNT scans.",
                &ADDRESS_COUNT,
            ),
            field(
                "Connections per address",
                "New connections, and plain HTTP requests, from one address.",
                "Shared networks fail to reconnect after an outage.",
                "Connection floods cost handshake CPU and memory.",
                &ADDRESS_CONNECTION,
            ),
            field(
                "Events per address",
                "EVENT and AUTH messages from one address.",
                "Marmot group invites, a commit plus a Welcome per new member, and bulk publishing fail.",
                "Spam, and signature checks that use CPU.",
                &ADDRESS_EVENT,
            ),
            field(
                "Events per author",
                "Events from one key. An event from a key that is not one of the connection's logged-in identities is charged to its first identity instead.",
                "Active users, bots and bulk publishing are throttled.",
                "One key can flood the relay. On an anonymous connection, a new key for each event starts a new budget each time.",
                &AUTHOR_EVENT,
            ),
            field(
                "Malformed messages per address",
                "Error replies to malformed messages from one address; past this they are ignored until the budget refills.",
                "Clients with bugs get fewer error replies to debug with.",
                "A client can make the relay answer garbage.",
                &ADDRESS_INVALID,
            ),
            field(
                "IPv6 network size",
                "The leading bits of an IPv6 address that key its per-address budgets. One host is usually given a whole /64.",
                "Unrelated users on one large network share a budget.",
                "A host can pick a new address within its network for each connection and escape every per-address budget.",
                &[Input::new("abuse", "ipv6_prefix_len", "relay.abuse.ipv6_prefix_len", Unit::Count)],
            ),
            field(
                "Client address header",
                "The header in which a reverse proxy passes each client's address, such as X-Forwarded-For. Wok reads its last entry, the one the proxy wrote, with or without a port. When that entry is not an address, the connecting address stands in, and wok_real_ip_header_unparsed_total counts the request. Empty: each client is the address that connected. Set in wok.toml, because every per-address budget trusts it.",
                "Left empty behind a proxy, every client has the proxy's address and shares one set of budgets.",
                "Set while clients can reach the relay directly, a client can send any address, to escape its budgets or spend another's.",
                &[Input::new("file", "real_ip_header", "relay.real_ip_header", Unit::Text).file_only()],
            ),
        ],
    },
    Section {
        id: "storage",
        title: "Storage",
        help: "How much the relay stores. The disk reserve and the database map size bound the real resource.",
        fields: &[
            field(
                "Stored events per author",
                "Events one key may have stored. Replacing a profile or list, and deleting the author's own events, still work at the quota.",
                "Active users and bots can no longer post new events.",
                "One key can fill the disk. A new key for each event starts a new count each time, so throwaway keys are held only by the per-address budgets.",
                &[Input::new("abuse", "max_stored_events_per_pubkey", "relay.abuse.max_stored_events_per_pubkey", Unit::Count).off()],
            ),
            field(
                "Stored events",
                "Events the relay stores in all.",
                "Every write fails once the relay holds that many events.",
                "",
                &[Input::new("abuse", "max_stored_events", "relay.abuse.max_stored_events", Unit::Count).off()],
            ),
            field(
                "Disk reserve",
                "Refuse writes while free disk space is below this. Set in wok.toml; takes effect on restart.",
                "The disk can fill, and the database with it.",
                "Writes stop while the disk still has room.",
                &[Input::new("file", "min_free_disk_bytes", "database.min_free_disk_bytes", Unit::Bytes).off().file_only()],
            ),
            field(
                "Database size limit",
                "The LMDB map size: writes fail once the database reaches it. Set in wok.toml; takes effect on restart.",
                "Writes fail once the database fills its map.",
                "Only address space: the file grows as data is written.",
                &[Input::new("file", "map_size", "database.map_size", Unit::Bytes).file_only()],
            ),
        ],
    },
    Section {
        id: "sync",
        title: "Sync (NIP-77)",
        help: "Negentropy sessions, which clients such as Marmot's use to find what they are missing.",
        fields: &[
            field(
                "Sync",
                "Answer NEG-OPEN, and advertise NIP-77. Marmot clients need it.",
                "",
                "",
                &[Input::new("limits", "negentropy_enabled", "relay.negentropy_enabled", Unit::Switch)],
            ),
            field(
                "Events per sync",
                "The most events one sync session may compare.",
                "Large syncs fail, and clients fall back to slower REQs.",
                "A sync can hold a larger temporary set in memory.",
                &[Input::new("limits", "max_sync_events", "relay.max_sync_events", Unit::Count)],
            ),
            field(
                "Sync memory per connection",
                "Memory the sync sessions of one connection may reserve. Zero refuses every session.",
                "Clients that sync many groups at once are refused.",
                "One connection can take more of the shared pool.",
                &[Input::new("limits", "sync_memory_per_connection", "relay.sync_memory_per_connection", Unit::Bytes)],
            ),
            field(
                "Sync memory in all",
                "Memory every sync session together may reserve. Zero refuses every session.",
                "Syncs are refused while several clients sync at once.",
                "Syncs can use that much memory between them.",
                &[Input::new("limits", "sync_memory_total", "relay.sync_memory_total", Unit::Bytes)],
            ),
            field(
                "Sync idle timeout",
                "How long a sync session waits for the client's next round.",
                "Slow clients' syncs are closed between rounds.",
                "Abandoned sessions hold memory longer.",
                &[Input::new("limits", "sync_idle_timeout_secs", "relay.sync_idle_timeout_secs", Unit::Seconds)],
            ),
        ],
    },
    Section {
        id: "info",
        title: "Relay information",
        help: "Public metadata returned by NIP-11 and shown on the landing page.",
        fields: &[
            field("Name", "The relay's public display name.", "", "", &[Input::new("info", "name", "relay.info.name", Unit::Text)]),
            field("Description", "What the relay is for.", "", "", &[Input::new("info", "description", "relay.info.description", Unit::Text)]),
            field("Operator pubkey", "The operator's public key, as npub or hex.", "", "", &[Input::new("info", "pubkey", "relay.info.pubkey", Unit::Text)]),
            field("Relay pubkey", "The relay's own public key, NIP-11's self.", "", "", &[Input::new("info", "self_pk", "relay.info.self_pk", Unit::Text)]),
            field("Contact", "How to reach the operator, such as an email address or a Nostr identifier.", "", "", &[Input::new("info", "contact", "relay.info.contact", Unit::Text)]),
            field("Icon URL", "A square icon.", "", "", &[Input::new("info", "icon", "relay.info.icon", Unit::Url)]),
            field("Banner URL", "A wide banner image.", "", "", &[Input::new("info", "banner", "relay.info.banner", Unit::Url)]),
            field("Privacy policy URL", "The relay's privacy policy.", "", "", &[Input::new("info", "privacy", "relay.info.privacy", Unit::Url)]),
            field("Terms of service URL", "The relay's terms of service.", "", "", &[Input::new("info", "terms", "relay.info.terms", Unit::Url)]),
        ],
    },
    Section {
        id: "advanced",
        title: "Advanced",
        help: "Scheduling, slow clients, the write-policy plugin, vanish deletions and this dashboard's history.",
        fields: &[
            field(
                "Query time slice",
                "CPU time a scan runs before it lets other scans run.",
                "Scans switch more often, which costs overhead.",
                "Short queries wait longer behind long ones.",
                &[Input::new("limits", "query_timeslice_budget_us", "relay.query_timeslice_budget_us", Unit::Micros)],
            ),
            field(
                "Outbound queue per connection",
                "Output queued for one connection before it is disconnected as too slow. Applies to new connections.",
                "Large backfills on slow links disconnect.",
                "A slow reader can hold that much memory.",
                &[Input::new("limits", "max_pending_outbound_bytes", "relay.max_pending_outbound_bytes", Unit::Bytes).off()],
            ),
            field(
                "Write-policy plugin timeout",
                "How long to wait for the write-policy plugin's verdict on an event.",
                "A slow plugin's verdicts time out, and its events are refused.",
                "A hung plugin stalls every write for that long.",
                &[Input::new("limits", "write_policy_timeout_secs", "relay.write_policy_timeout_secs", Unit::Seconds)],
            ),
            field(
                "Vanish deletion batch",
                "Records removed per transaction while a vanish request is carried out.",
                "A vanish request takes more, smaller transactions.",
                "Each transaction holds the writer longer.",
                &[Input::new("nip62", "deletion_batch_size", "relay.nip62.deletion_batch_size", Unit::Count)],
            ),
            field(
                "Dashboard history",
                "Keep in-memory samples for this dashboard's charts. Prometheus metrics are not affected.",
                "",
                "",
                &[Input::new("history", "enabled", "observability.history_enabled", Unit::Switch)],
            ),
            field(
                "History interval",
                "Time between samples.",
                "",
                "",
                &[Input::new("history", "interval_secs", "observability.history_interval_secs", Unit::Seconds)],
            ),
            field(
                "History samples",
                "Samples kept, at most 100,000.",
                "",
                "",
                &[Input::new("history", "max_points", "observability.history_max_points", Unit::Count)],
            ),
        ],
    },
];
