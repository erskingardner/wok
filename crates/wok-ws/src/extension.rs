//! RFC 7692 permessage-deflate negotiation: which of the client's
//! `Sec-WebSocket-Extensions` offers Wok accepts, and what it answers.
//!
//! A client lists its offers in order of preference (RFC 6455 §9.1), each
//! `permessage-deflate` with its own parameters, the later ones fallbacks.
//! Wok accepts the first it can honour and answers with no extension when
//! none can be honoured (RFC 7692 §7). An offer is declined when one of its
//! parameters is unknown, repeated or has an invalid value, or when it asks
//! for a server window under 15 bits: miniz_oxide, flate2's backend here,
//! compresses only with a 32 KiB window.

use crate::Deflate;

/// The window, in bits, that Wok's compressor uses. Its inflater allows the
/// same, which takes a client compressing with any smaller window, so
/// `client_max_window_bits` is accepted and left out of the response.
const WINDOW_BITS: u8 = 15;

/// Negotiate permessage-deflate from the `Sec-WebSocket-Extensions` header
/// lines, in order: the `Sec-WebSocket-Extensions` response and what it
/// agreed. `sliding_window` is `relay.compression_sliding_window`.
pub(crate) fn negotiate<'a>(
    headers: impl IntoIterator<Item = &'a str>,
    sliding_window: bool,
) -> Option<(String, Deflate)> {
    headers
        .into_iter()
        .flat_map(|line| split_unquoted(line, b','))
        .find_map(|offer| accept(offer, sliding_window))
}

/// Accept one offer, or decline it with `None`.
fn accept(offer: &str, sliding_window: bool) -> Option<(String, Deflate)> {
    let mut parts = split_unquoted(offer, b';');
    if !parts
        .next()?
        .trim()
        .eq_ignore_ascii_case("permessage-deflate")
    {
        return None;
    }
    let mut server_no_takeover = false;
    let mut client_no_takeover = false;
    let mut server_bits = false;
    let mut client_bits = false;
    for param in parts {
        let (name, value) = match param.split_once('=') {
            Some((name, value)) => (name.trim(), Some(unquote(value.trim())?)),
            None => (param.trim(), None),
        };
        let name = name.to_ascii_lowercase();
        let seen = match (name.as_str(), value.as_deref()) {
            ("server_no_context_takeover", None) => &mut server_no_takeover,
            ("client_no_context_takeover", None) => &mut client_no_takeover,
            // Only the window Wok compresses with can be honoured.
            ("server_max_window_bits", Some(bits)) if window_bits(bits) == Some(WINDOW_BITS) => {
                &mut server_bits
            }
            ("client_max_window_bits", None) => &mut client_bits,
            ("client_max_window_bits", Some(bits)) if window_bits(bits).is_some() => {
                &mut client_bits
            }
            _ => return None,
        };
        if std::mem::replace(seen, true) {
            return None;
        }
    }
    let mut response = String::from("permessage-deflate");
    if server_no_takeover {
        response.push_str("; server_no_context_takeover");
    }
    if client_no_takeover {
        response.push_str("; client_no_context_takeover");
    }
    if server_bits {
        response.push_str("; server_max_window_bits=15");
    }
    let deflate = Deflate {
        server_takeover: sliding_window && !server_no_takeover,
        client_takeover: !client_no_takeover,
    };
    Some((response, deflate))
}

/// A `*_max_window_bits` value: 8 to 15, in decimal without leading zeros
/// (RFC 7692 §7.1.2).
fn window_bits(value: &str) -> Option<u8> {
    if value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|bits| (8..=15).contains(bits))
}

/// A parameter value, a token or a quoted string (RFC 6455 §9.1), with a
/// quoted string's quotes and escapes removed. `None` if it is malformed.
fn unquote(value: &str) -> Option<String> {
    let Some(quoted) = value.strip_prefix('"') else {
        return Some(value.to_string());
    };
    let mut out = String::new();
    let mut chars = quoted.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '"' => return chars.as_str().is_empty().then_some(out),
            c => out.push(c),
        }
    }
    None
}

/// Split `s` at each `sep` outside a quoted string.
fn split_unquoted(s: &str, sep: u8) -> impl Iterator<Item = &str> {
    let mut rest = Some(s);
    std::iter::from_fn(move || {
        let s = rest?;
        let (mut quoted, mut escaped) = (false, false);
        for (i, b) in s.bytes().enumerate() {
            if escaped {
                escaped = false;
            } else if quoted && b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = !quoted;
            } else if !quoted && b == sep {
                rest = Some(&s[i + 1..]);
                return Some(&s[..i]);
            }
        }
        rest = None;
        Some(s)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The response to `offer` with the sliding window on, and whether each
    /// side keeps context, or `None` when every offer is declined.
    fn answer(offer: &str) -> Option<(String, bool, bool)> {
        negotiate([offer], true)
            .map(|(response, d)| (response, d.server_takeover, d.client_takeover))
    }

    fn accepted(
        response: &str,
        server_takeover: bool,
        client_takeover: bool,
    ) -> Option<(String, bool, bool)> {
        Some((response.to_string(), server_takeover, client_takeover))
    }

    #[test]
    fn a_bare_offer_keeps_context_both_ways() {
        assert_eq!(
            answer("permessage-deflate"),
            accepted("permessage-deflate", true, true)
        );
        assert_eq!(
            answer(" PerMessage-Deflate "),
            accepted("permessage-deflate", true, true)
        );
    }

    #[test]
    fn the_sliding_window_setting_governs_only_the_relay_compressor() {
        let (response, deflate) = negotiate(["permessage-deflate"], false).unwrap();
        assert_eq!(response, "permessage-deflate");
        assert!(!deflate.server_takeover);
        assert!(deflate.client_takeover);
    }

    #[test]
    fn server_no_context_takeover_is_echoed_and_honoured() {
        assert_eq!(
            answer("permessage-deflate; server_no_context_takeover"),
            accepted(
                "permessage-deflate; server_no_context_takeover",
                false,
                true
            )
        );
    }

    #[test]
    fn client_no_context_takeover_is_echoed() {
        assert_eq!(
            answer("permessage-deflate; client_no_context_takeover"),
            accepted(
                "permessage-deflate; client_no_context_takeover",
                true,
                false
            )
        );
        assert_eq!(
            answer("permessage-deflate;client_no_context_takeover;server_no_context_takeover"),
            accepted(
                "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
                false,
                false
            )
        );
    }

    #[test]
    fn a_server_window_is_honoured_only_at_15_bits() {
        assert_eq!(
            answer("permessage-deflate; server_max_window_bits=15"),
            accepted("permessage-deflate; server_max_window_bits=15", true, true)
        );
        assert_eq!(
            answer("permessage-deflate; server_max_window_bits=\"15\""),
            accepted("permessage-deflate; server_max_window_bits=15", true, true)
        );
        for bits in 8..15 {
            let offer = format!("permessage-deflate; server_max_window_bits={bits}");
            assert_eq!(answer(&offer), None, "{offer}");
        }
    }

    #[test]
    fn a_client_window_is_accepted_and_left_out() {
        for offer in [
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; client_max_window_bits=8",
            "permessage-deflate; client_max_window_bits=10",
            "permessage-deflate; client_max_window_bits=15",
            "permessage-deflate; client_max_window_bits = \"9\"",
        ] {
            assert_eq!(
                answer(offer),
                accepted("permessage-deflate", true, true),
                "{offer}"
            );
        }
    }

    #[test]
    fn a_repeated_parameter_is_declined() {
        for offer in [
            "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
            "permessage-deflate; client_no_context_takeover; CLIENT_NO_CONTEXT_TAKEOVER",
            "permessage-deflate; server_max_window_bits=15; server_max_window_bits=15",
            "permessage-deflate; client_max_window_bits; client_max_window_bits=10",
        ] {
            assert_eq!(answer(offer), None, "{offer}");
        }
    }

    #[test]
    fn an_unknown_parameter_is_declined() {
        for offer in [
            "permessage-deflate; x-webkit-something",
            "permessage-deflate; client_no_context_takeover; mystery=1",
            "permessage-deflate;",
            "permessage-deflate; ; client_no_context_takeover",
            "permessage-deflate; server_no_context_takeover extra",
        ] {
            assert_eq!(answer(offer), None, "{offer}");
        }
    }

    #[test]
    fn an_invalid_value_is_declined() {
        for offer in [
            "permessage-deflate; server_no_context_takeover=1",
            "permessage-deflate; client_no_context_takeover=",
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; server_max_window_bits=",
            "permessage-deflate; server_max_window_bits=015",
            "permessage-deflate; server_max_window_bits=16",
            "permessage-deflate; server_max_window_bits=+15",
            "permessage-deflate; server_max_window_bits=\"15",
            "permessage-deflate; server_max_window_bits=\"15\"x",
            "permessage-deflate; client_max_window_bits=7",
            "permessage-deflate; client_max_window_bits=16",
            "permessage-deflate; client_max_window_bits=08",
            "permessage-deflate; client_max_window_bits=1e1",
            "permessage-deflate; client_max_window_bits=999",
        ] {
            assert_eq!(answer(offer), None, "{offer}");
        }
    }

    #[test]
    fn the_first_offer_that_can_be_honoured_is_accepted() {
        // Python websockets' default with a small server window, then the
        // plain fallback it lists when told to.
        assert_eq!(
            answer(
                "permessage-deflate; server_max_window_bits=10; client_max_window_bits, \
                 permessage-deflate; client_max_window_bits"
            ),
            accepted("permessage-deflate", true, true)
        );
        assert_eq!(
            answer(
                "x-webkit-deflate-frame, permessage-deflate; mystery, \
                 permessage-deflate; server_no_context_takeover, permessage-deflate"
            ),
            accepted(
                "permessage-deflate; server_no_context_takeover",
                false,
                true
            )
        );
        assert_eq!(
            answer("permessage-deflate; server_max_window_bits=9, permessage-deflate; server_max_window_bits=8"),
            None
        );
        assert_eq!(answer("x-webkit-deflate-frame"), None);
        assert_eq!(answer(""), None);
    }

    #[test]
    fn offers_on_several_header_lines_are_read_in_order() {
        let (response, _) = negotiate(
            [
                "permessage-deflate; server_max_window_bits=12",
                "permessage-deflate; client_no_context_takeover",
            ],
            true,
        )
        .unwrap();
        assert_eq!(response, "permessage-deflate; client_no_context_takeover");
    }

    #[test]
    fn a_comma_inside_a_quoted_value_does_not_split_offers() {
        // The quoted value is one (invalid) value, not the end of an offer.
        assert_eq!(
            answer("permessage-deflate; client_max_window_bits=\"10, permessage-deflate\""),
            None
        );
        assert_eq!(
            answer("permessage-deflate; client_max_window_bits=\"1\\0\", permessage-deflate"),
            accepted("permessage-deflate", true, true)
        );
    }
}
