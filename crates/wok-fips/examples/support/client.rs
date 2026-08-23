use fips::native::client::{FipsAddr, FipsStream};
use fips_message::{chunk_message, HandshakeClient, Limits, Reassembler, SessionId};
use std::error::Error;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

pub(crate) struct Exchange {
    pub(crate) max_datagram: usize,
    pub(crate) responses: Vec<String>,
}

pub(crate) fn exchange(
    socket: &Path,
    destination: FipsAddr,
    message: &str,
    mut done: impl FnMut(&str) -> bool,
) -> Result<Exchange, Box<dyn Error>> {
    let stream = FipsStream::connect_at(socket, 0, destination)?;
    stream.set_nonblocking(true)?;
    let limits = limits();
    let session = SessionId::from_u128(rand::random());
    let started = Instant::now();
    let deadline = started + Duration::from_secs(30);
    let mut handshake = HandshakeClient::new(
        session,
        started,
        Duration::from_millis(250),
        Duration::from_secs(15),
    )?;
    let mut recv_buf = vec![0; stream.max_payload()];
    while !handshake.is_ready() {
        let now = Instant::now();
        if let Some(hello) = handshake.poll(now)? {
            send_datagram(&stream, &hello, deadline)?;
        }
        match stream.recv(&mut recv_buf) {
            Ok(len) => {
                handshake.receive(&recv_buf[..len])?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }

    for datagram in chunk_message(session, 0, message.as_bytes(), stream.max_payload(), limits)? {
        send_datagram(&stream, &datagram, deadline)?;
    }

    let mut replies = Reassembler::new(session, limits)?;
    let mut responses = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for a complete relay response",
            )
            .into());
        }
        match stream.recv(&mut recv_buf) {
            Ok(len) => {
                for reply in replies.ingest(&recv_buf[..len], Instant::now())? {
                    let reply = String::from_utf8(reply.payload)?;
                    let complete = done(&reply);
                    responses.push(reply);
                    if complete {
                        return Ok(Exchange {
                            max_datagram: stream.max_payload(),
                            responses,
                        });
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn limits() -> Limits {
    Limits {
        max_message_size: 128 * 1024,
        max_chunks: 4096,
        max_incomplete_messages: 16,
        max_reassembly_bytes: 8 * 1024 * 1024,
        max_completed_messages: 16,
        incomplete_timeout: Duration::from_secs(30),
    }
}

fn send_datagram(stream: &FipsStream, datagram: &[u8], deadline: Instant) -> io::Result<()> {
    loop {
        match stream.send(datagram) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for the local FIPS daemon to accept a datagram",
                    ));
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}
