//! Write-policy plugin matching `src/PluginEventSifter.h`.
//!
//! The plugin is an external process. wok writes one JSON object per line on
//! stdin and reads one JSON object per line on stdout.
//!
//! A worker thread owns the child's pipes so the relay writer thread can
//! enforce `writePolicy.timeoutSeconds` on the whole round trip (a hung
//! plugin must not wedge the single LMDB writer) and the 8192-byte response
//! line cap, like C++'s `StreamReader::setMaxRecordSize`.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

/// C++ StreamReader record cap for plugin responses.
const MAX_RECORD_SIZE: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginResult {
    Accept,
    Reject,
    ShadowReject,
}

pub struct PluginEventSifter {
    running: Option<Running>,
    timeout: Duration,
}

struct Running {
    child: Child,
    to_worker: std_mpsc::Sender<String>,
    from_worker: std_mpsc::Receiver<Result<String, String>>,
    cmd: String,
    last_mod: Option<std::time::SystemTime>,
}

impl PluginEventSifter {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            running: None,
            timeout: Duration::from_secs(timeout_secs.max(1)),
        }
    }

    pub fn accept_event(
        &mut self,
        plugin_cmd: &str,
        ev_json: &Value,
        source_type: &str,
        source_info: &str,
        authed: Option<&[u8]>,
        ok_msg: &mut String,
    ) -> PluginResult {
        if plugin_cmd.is_empty() {
            self.running = None;
            return PluginResult::Accept;
        }
        if let Err(e) = self.ensure(plugin_cmd) {
            tracing::error!("Plugin error: {e}");
            *ok_msg = "error: internal error".into();
            return PluginResult::Reject;
        }
        let mut request = json!({
            "type": "new",
            "event": ev_json,
            "receivedAt": now_secs(),
            "sourceType": source_type,
            "sourceInfo": source_info,
        });
        if let Some(pk) = authed {
            request["authed"] = json!(hex::encode(pk));
        }
        match self.roundtrip(&request) {
            Ok((action, msg)) => {
                *ok_msg = msg;
                match action.as_str() {
                    "accept" => PluginResult::Accept,
                    "reject" => PluginResult::Reject,
                    "shadowReject" => PluginResult::ShadowReject,
                    other => {
                        tracing::error!(action = ?other, "write policy plugin returned unknown action");
                        *ok_msg = "error: internal error".into();
                        self.running = None;
                        PluginResult::Reject
                    }
                }
            }
            Err(e) => {
                tracing::error!("Plugin error: {e}");
                self.running = None;
                *ok_msg = "error: internal error".into();
                PluginResult::Reject
            }
        }
    }

    fn ensure(&mut self, cmd: &str) -> Result<(), String> {
        // C++ restarts the plugin when the binary's mtime changes (only for
        // single-word commands that name a file directly).
        let mtime = if !cmd.contains(' ') {
            Some(
                std::fs::metadata(cmd)
                    .and_then(|m| m.modified())
                    .map_err(|e| format!("couldn't stat plugin: {cmd}: {e}"))?,
            )
        } else {
            None
        };
        if let Some(r) = &self.running {
            if r.cmd == cmd && r.last_mod == mtime {
                return Ok(());
            }
            self.running = None;
        }
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("posix_spawn failed to invoke '{cmd}': {e}"))?;
        let stdin = child.stdin.take().ok_or("plugin stdin")?;
        let stdout = child.stdout.take().ok_or("plugin stdout")?;
        let (req_tx, req_rx) = std_mpsc::channel::<String>();
        let (resp_tx, resp_rx) = std_mpsc::channel::<Result<String, String>>();
        std::thread::Builder::new()
            .name("plugin-io".into())
            .spawn(move || plugin_worker(stdin, stdout, req_rx, resp_tx))
            .map_err(|e| e.to_string())?;
        self.running = Some(Running {
            child,
            to_worker: req_tx,
            from_worker: resp_rx,
            cmd: cmd.to_string(),
            last_mod: mtime,
        });
        Ok(())
    }

    fn roundtrip(&mut self, request: &Value) -> Result<(String, String), String> {
        let running = self.running.as_mut().ok_or("plugin not running")?;
        let mut line = serde_json::to_string(request).map_err(|e| e.to_string())?;
        line.push('\n');
        running
            .to_worker
            .send(line)
            .map_err(|_| "Failed to write event: plugin worker gone".to_string())?;
        let want_id = request["event"]["id"].as_str().unwrap_or("");
        // C++ gives each read a fresh timeout window.
        loop {
            let resp_line = match running.from_worker.recv_timeout(self.timeout) {
                Ok(Ok(l)) => l,
                Ok(Err(e)) => return Err(format!("Failed to read response: {e}")),
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    return Err("Failed to read response: timeout".into())
                }
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Failed to read response: eof".into())
                }
            };
            let response: Value = match serde_json::from_str(resp_line.trim()) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        response = ?resp_line.trim_end(),
                        "write policy plugin returned unparseable JSON"
                    );
                    continue;
                }
            };
            if response["id"].as_str() != Some(want_id) {
                return Err("id mismatch".into());
            }
            let action = response["action"]
                .as_str()
                .ok_or("missing action")?
                .to_string();
            let msg = response["msg"].as_str().unwrap_or("").to_string();
            return Ok((action, msg));
        }
    }
}

/// Synchronous body of the plugin I/O worker thread. Writes each request,
/// then reads response lines until the channel closes or the child dies.
fn plugin_worker(
    mut stdin: ChildStdin,
    stdout: ChildStdout,
    requests: std_mpsc::Receiver<String>,
    responses: std_mpsc::Sender<Result<String, String>>,
) {
    let mut reader = BufReader::new(stdout);
    while let Ok(line) = requests.recv() {
        if let Err(e) = stdin.write_all(line.as_bytes()).and_then(|_| stdin.flush()) {
            let _ = responses.send(Err(format!("Failed to write event: {e}")));
            break;
        }
        match read_record(&mut reader) {
            Ok(Some(resp)) => {
                if responses.send(Ok(resp)).is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = responses.send(Err("eof".into()));
                break;
            }
            Err(e) => {
                let _ = responses.send(Err(e));
                break;
            }
        }
    }
}

/// Read one newline-terminated record, enforcing the 8192-byte cap without
/// unbounded allocation.
fn read_record(reader: &mut BufReader<ChildStdout>) -> Result<Option<String>, String> {
    let mut buf = Vec::new();
    let mut chunk = reader.take(MAX_RECORD_SIZE as u64 + 1);
    let n = chunk
        .read_until(b'\n', &mut buf)
        .map_err(|e| format!("Failed to read response: {e}"))?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_RECORD_SIZE {
        return Err(format!(
            "plugin response record too large (> {MAX_RECORD_SIZE} bytes)"
        ));
    }
    String::from_utf8(buf).map(Some).map_err(|e| e.to_string())
}

impl Drop for PluginEventSifter {
    fn drop(&mut self) {
        if let Some(mut r) = self.running.take() {
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn plugin_accepts_and_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("plug.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nwhile read line; do echo '{\"id\":\"'$(echo \"$line\" | sed -n 's/.*\"id\":\"\\([^\"]*\\)\".*/\\1/p')'\",\"action\":\"accept\"}'; done\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut sifter = PluginEventSifter::new(5);
        let ev = json!({"id":"abcd","kind":1});
        let mut msg = String::new();
        let res = sifter.accept_event(
            &format!("sh {}", script.display()),
            &ev,
            "IP4",
            "127.0.0.1",
            None,
            &mut msg,
        );
        assert_eq!(res, PluginResult::Accept);
    }

    #[test]
    fn hung_plugin_times_out_instead_of_wedging() {
        let mut sifter = PluginEventSifter::new(1);
        let ev = json!({"id":"abcd","kind":1});
        let mut msg = String::new();
        let start = Instant::now();
        let res = sifter.accept_event("sleep 3600", &ev, "IP4", "127.0.0.1", None, &mut msg);
        let elapsed = start.elapsed();
        assert_eq!(res, PluginResult::Reject);
        assert_eq!(msg, "error: internal error");
        assert!(
            elapsed < Duration::from_secs(10),
            "timeout not enforced: {elapsed:?}"
        );
    }
}
