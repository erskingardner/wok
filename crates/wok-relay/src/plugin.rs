//! Write-policy plugin matching `src/PluginEventSifter.h`.
//!
//! The plugin is an external process. wok writes one JSON object per line on
//! stdin and reads one JSON object per line on stdout.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

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
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    cmd: String,
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
                        tracing::error!("unknown action: {other}");
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
        if self.running.as_ref().map(|r| r.cmd.as_str()) == Some(cmd) {
            return Ok(());
        }
        self.running = None;
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
        self.running = Some(Running {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            cmd: cmd.to_string(),
        });
        Ok(())
    }

    fn roundtrip(&mut self, request: &Value) -> Result<(String, String), String> {
        let running = self.running.as_mut().ok_or("plugin not running")?;
        let mut line = serde_json::to_string(request).map_err(|e| e.to_string())?;
        line.push('\n');
        running
            .stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write event: {e}"))?;
        running.stdin.flush().ok();
        let deadline = Instant::now() + self.timeout;
        let want_id = request["event"]["id"].as_str().unwrap_or("");
        loop {
            if Instant::now() > deadline {
                return Err("Failed to read response: timeout".into());
            }
            let mut resp_line = String::new();
            running
                .stdout
                .read_line(&mut resp_line)
                .map_err(|e| format!("Failed to read response: {e}"))?;
            if resp_line.is_empty() {
                return Err("Failed to read response: eof".into());
            }
            let response: Value = match serde_json::from_str(resp_line.trim()) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!("Got unparseable line from write policy plugin: {resp_line}");
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

impl Drop for PluginEventSifter {
    fn drop(&mut self) {
        if let Some(mut r) = self.running.take() {
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
