use fips_message::{
    accept_hello, control, decode, FrameKind, Limits, ProtocolError, Reassembler, SessionId,
};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SessionOutput {
    pub reply: Option<Vec<u8>>,
    pub messages: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct ServerSession {
    limits: Limits,
    session: Option<SessionId>,
    reassembler: Option<Reassembler>,
}

impl ServerSession {
    pub(crate) fn new(limits: Limits) -> Result<Self, ProtocolError> {
        limits.validate()?;
        Ok(Self {
            limits,
            session: None,
            reassembler: None,
        })
    }

    pub(crate) const fn session(&self) -> Option<SessionId> {
        self.session
    }

    pub(crate) fn receive(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<SessionOutput, ProtocolError> {
        let frame = decode(datagram)?;
        if self.session.is_none() {
            let session = accept_hello(datagram)?;
            self.session = Some(session);
            self.reassembler = Some(Reassembler::new(session, self.limits)?);
            return Ok(SessionOutput {
                reply: Some(control(FrameKind::Ready, session)?),
                messages: Vec::new(),
            });
        }
        let session = self.session.expect("established session");
        match frame.kind {
            FrameKind::Hello if frame.session == session => Ok(SessionOutput {
                reply: Some(control(FrameKind::Ready, session)?),
                messages: Vec::new(),
            }),
            FrameKind::Hello => Err(ProtocolError::WrongSession),
            FrameKind::Data => {
                let completed = self
                    .reassembler
                    .as_mut()
                    .expect("established reassembler")
                    .ingest(datagram, now)?;
                Ok(SessionOutput {
                    reply: None,
                    messages: completed
                        .into_iter()
                        .map(|message| message.payload)
                        .collect(),
                })
            }
            kind => Err(ProtocolError::UnexpectedFrame(kind)),
        }
    }

    pub(crate) fn expire(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if let Some(reassembler) = &mut self.reassembler {
            reassembler.expire(now)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips_message::{chunk_message, HEADER_LEN};
    use std::time::Duration;
    use wok_db::{Env, EnvOptions};
    use wok_relay::{start, Outbound, OutboundFrame, TransportSource};

    fn limits() -> Limits {
        Limits {
            max_message_size: 1024,
            max_chunks: 32,
            max_incomplete_messages: 4,
            max_reassembly_bytes: 2048,
            max_completed_messages: 4,
            incomplete_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn opening_hello_is_retained_and_answered_before_data() {
        let now = Instant::now();
        let session = SessionId::from_u128(1);
        let hello = control(FrameKind::Hello, session).unwrap();
        let mut server = ServerSession::new(limits()).unwrap();
        let output = server.receive(&hello, now).unwrap();
        assert_eq!(
            decode(output.reply.as_ref().unwrap()).unwrap().kind,
            FrameKind::Ready
        );
        assert_eq!(server.session(), Some(session));

        let data = chunk_message(session, 0, b"nostr", HEADER_LEN + 3, limits()).unwrap();
        assert!(server.receive(&data[0], now).unwrap().messages.is_empty());
        let output = server.receive(&data[1], now).unwrap();
        assert_eq!(output.messages, vec![b"nostr".to_vec()]);
    }

    #[test]
    fn duplicate_hello_replays_ready_but_mismatched_hello_fails() {
        let now = Instant::now();
        let session = SessionId::from_u128(2);
        let hello = control(FrameKind::Hello, session).unwrap();
        let mut server = ServerSession::new(limits()).unwrap();
        server.receive(&hello, now).unwrap();
        assert!(server.receive(&hello, now).unwrap().reply.is_some());
        let stale = control(FrameKind::Hello, SessionId::from_u128(1)).unwrap();
        assert_eq!(
            server.receive(&stale, now),
            Err(ProtocolError::WrongSession)
        );
    }

    #[test]
    fn zero_length_datagram_is_data_not_an_eof_signal() {
        let mut server = ServerSession::new(limits()).unwrap();
        assert!(matches!(
            server.receive(&[], Instant::now()),
            Err(ProtocolError::TruncatedHeader { actual: 0 })
        ));
    }

    #[test]
    fn incomplete_data_never_escapes_and_expiry_fails_ordering() {
        let now = Instant::now();
        let session = SessionId::from_u128(3);
        let hello = control(FrameKind::Hello, session).unwrap();
        let chunks = chunk_message(session, 0, b"incomplete", HEADER_LEN + 3, limits()).unwrap();
        let mut server = ServerSession::new(limits()).unwrap();
        server.receive(&hello, now).unwrap();
        assert!(server.receive(&chunks[0], now).unwrap().messages.is_empty());
        assert_eq!(
            server.expire(now + Duration::from_secs(5)),
            Err(ProtocolError::OrderedMessageExpired { message_id: 0 })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_message_reaches_relay_and_response_chunks_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut config = wok_relay::Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        config.relay.auth.enabled = false;
        let handle = start(env, config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let connection = handle
            .register_connection(
                TransportSource::Fips {
                    public_key: [8; 32],
                    port: 7777,
                },
                Outbound::new(tx, 1024 * 1024),
            )
            .await;

        let now = Instant::now();
        let session = SessionId::from_u128(4);
        let mut server = ServerSession::new(limits()).unwrap();
        server
            .receive(&control(FrameKind::Hello, session).unwrap(), now)
            .unwrap();
        let request = br#"["REQ","fips-test",{}]"#;
        let chunks = chunk_message(session, 0, request, HEADER_LEN + 7, limits()).unwrap();
        for chunk in chunks {
            for message in server.receive(&chunk, now).unwrap().messages {
                connection
                    .client_message(String::from_utf8(message).unwrap())
                    .await;
            }
        }

        let response = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("relay response timeout")
            .expect("relay response queue closed")
            .into_text();
        assert!(response.contains("\"EOSE\""), "{response}");

        let mut client = Reassembler::new(session, limits()).unwrap();
        let encoded =
            chunk_message(session, 0, response.as_bytes(), HEADER_LEN + 5, limits()).unwrap();
        let mut decoded = Vec::new();
        for datagram in encoded {
            decoded.extend(client.ingest(&datagram, now).unwrap());
        }
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload, response.as_bytes());

        connection.close().await;
        handle.request_shutdown();
    }
}
