use crate::types::{Instance, InstanceEvent};
use dashmap::DashMap;
use regex::Regex;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;
use tracing::debug;

pub struct ProcessManager {
    instances: Arc<DashMap<String, Instance>>,
    running_processes: Arc<DashMap<String, tokio::sync::oneshot::Sender<()>>>,
    event_tx: broadcast::Sender<InstanceEvent>,
    checkpoint_regex: Regex,
}

impl ProcessManager {
    pub fn new(
        instances: Arc<DashMap<String, Instance>>,
        event_tx: broadcast::Sender<InstanceEvent>,
    ) -> Self {
        let checkpoint_regex = Regex::new(
            r"CHECK_POINT\|MODE=(\d+)\|PING=(\d+)ms\|POOL=(\d+)\|TCPS=(\d+)\|UDPS=(\d+)\|TCPRX=(\d+)\|TCPTX=(\d+)\|UDPRX=(\d+)\|UDPTX=(\d+)"
        ).unwrap();

        Self {
            instances,
            running_processes: Arc::new(DashMap::new()),
            event_tx,
            checkpoint_regex,
        }
    }

    pub async fn start_instance(&self, id: &str) -> Result<(), String> {
        let mut entry = match self.instances.get_mut(id) {
            Some(e) => e,
            None => return Err(format!("Instance {} not found", id)),
        };

        if entry.status == "running" {
            return Ok(());
        }

        entry.tcp_rx_base = entry.tcprx;
        entry.tcp_tx_base = entry.tcptx;
        entry.udp_rx_base = entry.udprx;
        entry.udp_tx_base = entry.udptx;
        entry.tcp_rx_reset = 0;
        entry.tcp_tx_reset = 0;
        entry.udp_rx_reset = 0;
        entry.udp_tx_reset = 0;

        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get current exe path: {}", e))?;

        let url = entry.url.clone();
        let instance_id = id.to_string();

        let mut child = Command::new(&exe_path)
            .arg(&url)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn child process: {}", e))?;

        entry.status = "running".to_string();
        let instance_snapshot = entry.clone();
        drop(entry);

        let _ = self.event_tx.send(InstanceEvent {
            event_type: "update".to_string(),
            time: chrono_now_string(),
            instance: instance_snapshot,
            logs: String::new(),
        });

        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        self.running_processes.insert(instance_id.clone(), stop_tx);

        let instances_clone = Arc::clone(&self.instances);
        let event_tx_clone = self.event_tx.clone();
        let re = self.checkpoint_regex.clone();
        let running_proc_map = Arc::clone(&self.running_processes);

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        tokio::spawn(async move {
            let instances_for_stdout = Arc::clone(&instances_clone);
            let event_tx_for_stdout = event_tx_clone.clone();
            let re_for_stdout = re.clone();
            let id_for_stdout = instance_id.clone();

            const MAX_LOG_LINE_LEN: usize = 65536;

            if let Some(out) = stdout {
                tokio::spawn(async move {
                    let mut reader = BufReader::new(out);
                    let mut line_buf = Vec::new();
                    loop {
                        line_buf.clear();
                        match (&mut reader)
                            .take(MAX_LOG_LINE_LEN as u64)
                            .read_until(b'\n', &mut line_buf)
                            .await
                        {
                            Ok(0) => break,
                            Ok(_) => {
                                let line = String::from_utf8_lossy(&line_buf)
                                    .trim_end_matches(&['\r', '\n'][..])
                                    .to_string();
                                Self::process_log_line(
                                    &id_for_stdout,
                                    &line,
                                    &instances_for_stdout,
                                    &event_tx_for_stdout,
                                    &re_for_stdout,
                                );
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            let instances_for_stderr = Arc::clone(&instances_clone);
            let event_tx_for_stderr = event_tx_clone.clone();
            let re_for_stderr = re.clone();
            let id_for_stderr = instance_id.clone();

            if let Some(err) = stderr {
                tokio::spawn(async move {
                    let mut reader = BufReader::new(err);
                    let mut line_buf = Vec::new();
                    loop {
                        line_buf.clear();
                        match (&mut reader)
                            .take(MAX_LOG_LINE_LEN as u64)
                            .read_until(b'\n', &mut line_buf)
                            .await
                        {
                            Ok(0) => break,
                            Ok(_) => {
                                let line = String::from_utf8_lossy(&line_buf)
                                    .trim_end_matches(&['\r', '\n'][..])
                                    .to_string();
                                Self::process_log_line(
                                    &id_for_stderr,
                                    &line,
                                    &instances_for_stderr,
                                    &event_tx_for_stderr,
                                    &re_for_stderr,
                                );
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            tokio::select! {
                _ = &mut stop_rx => {
                    #[cfg(unix)]
                    {
                        if let Some(pid) = child.id() {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGTERM);
                            }
                        }
                        tokio::select! {
                            _ = child.wait() => {}
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                                let _ = child.kill().await;
                                let _ = child.wait().await;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                    }
                }
                status = child.wait() => {
                    debug!("Instance {} child exited: {:?}", instance_id, status);
                }
            }

            running_proc_map.remove(&instance_id);

            if let Some(mut inst) = instances_clone.get_mut(&instance_id) {
                if inst.status == "running" {
                    inst.status = "stopped".to_string();
                    let snap = inst.clone();
                    drop(inst);
                    let _ = event_tx_clone.send(InstanceEvent {
                        event_type: "update".to_string(),
                        time: chrono_now_string(),
                        instance: snap,
                        logs: String::new(),
                    });
                }
            }
        });

        Ok(())
    }

    pub async fn stop_instance(&self, id: &str) {
        if let Some((_, stop_tx)) = self.running_processes.remove(id) {
            let _ = stop_tx.send(());
        }

        if let Some(mut entry) = self.instances.get_mut(id) {
            entry.status = "stopped".to_string();
            entry.ping = 0;
            entry.pool = 0;
            entry.tcps = 0;
            entry.udps = 0;
            let snap = entry.clone();
            drop(entry);

            let _ = self.event_tx.send(InstanceEvent {
                event_type: "update".to_string(),
                time: chrono_now_string(),
                instance: snap,
                logs: String::new(),
            });
        }
    }

    pub async fn stop_all(&self) {
        let ids: Vec<String> = self
            .running_processes
            .iter()
            .map(|e| e.key().clone())
            .collect();
        for id in ids {
            self.stop_instance(&id).await;
        }
    }

    pub async fn restart_instance(&self, id: &str) -> Result<(), String> {
        self.stop_instance(id).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.start_instance(id).await
    }

    fn strip_ansi(s: &str) -> std::borrow::Cow<'_, str> {
        if !s.contains('\x1b') {
            return std::borrow::Cow::Borrowed(s);
        }
        static ANSI_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = ANSI_RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;?]*[a-zA-Z]").unwrap());
        std::borrow::Cow::Owned(re.replace_all(s, "").into_owned())
    }

    fn process_log_line(
        instance_id: &str,
        line: &str,
        instances: &Arc<DashMap<String, Instance>>,
        event_tx: &broadcast::Sender<InstanceEvent>,
        re: &Regex,
    ) {
        let clean_line = Self::strip_ansi(line);
        if let Some(caps) = re.captures(&clean_line) {
            if let Some(mut inst) = instances.get_mut(instance_id) {
                if let Ok(v) = caps[1].parse::<i32>() {
                    inst.mode = v;
                }
                if let Ok(v) = caps[2].parse::<i32>() {
                    inst.ping = v;
                }
                if let Ok(v) = caps[3].parse::<i32>() {
                    inst.pool = v;
                }
                if let Ok(v) = caps[4].parse::<i32>() {
                    inst.tcps = v;
                }
                if let Ok(v) = caps[5].parse::<i32>() {
                    inst.udps = v;
                }

                if let Ok(raw_tcprx) = caps[6].parse::<u64>() {
                    inst.tcprx = inst.tcp_rx_base + raw_tcprx.saturating_sub(inst.tcp_rx_reset);
                }
                if let Ok(raw_tcptx) = caps[7].parse::<u64>() {
                    inst.tcptx = inst.tcp_tx_base + raw_tcptx.saturating_sub(inst.tcp_tx_reset);
                }
                if let Ok(raw_udprx) = caps[8].parse::<u64>() {
                    inst.udprx = inst.udp_rx_base + raw_udprx.saturating_sub(inst.udp_rx_reset);
                }
                if let Ok(raw_udptx) = caps[9].parse::<u64>() {
                    inst.udptx = inst.udp_tx_base + raw_udptx.saturating_sub(inst.udp_tx_reset);
                }

                inst.last_checkpoint = Some(Instant::now());
                if inst.status == "error" {
                    inst.status = "running".to_string();
                }

                let snap = inst.clone();
                drop(inst);

                let _ = event_tx.send(InstanceEvent {
                    event_type: "update".to_string(),
                    time: chrono_now_string(),
                    instance: snap,
                    logs: String::new(),
                });
            }
            return;
        }

        if clean_line.contains("Server error:") || clean_line.contains("Client error:") {
            if let Some(mut inst) = instances.get_mut(instance_id) {
                inst.status = "error".to_string();
                inst.ping = 0;
                inst.pool = 0;
                inst.tcps = 0;
                inst.udps = 0;
                let snap = inst.clone();
                drop(inst);

                let _ = event_tx.send(InstanceEvent {
                    event_type: "update".to_string(),
                    time: chrono_now_string(),
                    instance: snap,
                    logs: String::new(),
                });
            }
        }

        // Send log event
        if let Some(inst) = instances.get(instance_id) {
            let snap = inst.clone();
            drop(inst);
            let _ = event_tx.send(InstanceEvent {
                event_type: "log".to_string(),
                time: chrono_now_string(),
                instance: snap,
                logs: line.to_string(),
            });
        }
    }
}

fn chrono_now_string() -> String {
    crate::types::now_timestamp_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_and_checkpoint_regex() {
        let raw_line = "\x1b[32m2026-09-07T12:00:00Z INFO\x1b[0m CHECK_POINT|MODE=2|PING=18ms|POOL=12|TCPS=3|UDPS=4|TCPRX=1024|TCPTX=2048|UDPRX=512|UDPTX=256\x1b[0m";
        let cleaned = ProcessManager::strip_ansi(raw_line);
        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.contains("CHECK_POINT|MODE=2|PING=18ms|POOL=12|TCPS=3|UDPS=4|TCPRX=1024|TCPTX=2048|UDPRX=512|UDPTX=256"));

        let instances = Arc::new(DashMap::new());
        let (event_tx, _) = broadcast::channel(16);
        let pm = ProcessManager::new(Arc::clone(&instances), event_tx.clone());

        let mut inst = Instance::new(
            "inst-1".to_string(),
            "test".to_string(),
            "client".to_string(),
            "client://".to_string(),
        );
        inst.status = "running".to_string();
        instances.insert("inst-1".to_string(), inst);

        ProcessManager::process_log_line(
            "inst-1",
            raw_line,
            &instances,
            &event_tx,
            &pm.checkpoint_regex,
        );

        let updated = instances.get("inst-1").unwrap();
        assert_eq!(updated.mode, 2);
        assert_eq!(updated.ping, 18);
        assert_eq!(updated.pool, 12);
        assert_eq!(updated.tcps, 3);
        assert_eq!(updated.udps, 4);
        assert_eq!(updated.tcprx, 1024);
        assert_eq!(updated.tcptx, 2048);
        assert_eq!(updated.udprx, 512);
        assert_eq!(updated.udptx, 256);
    }
}
