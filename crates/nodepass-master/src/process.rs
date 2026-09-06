use crate::types::{Instance, InstanceEvent};
use dashmap::DashMap;
use regex::Regex;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
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
            let mut stdout_reader = stdout.map(|s| BufReader::new(s).lines());
            let mut stderr_reader = stderr.map(|s| BufReader::new(s).lines());

            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        let _ = child.kill().await;
                        break;
                    }
                    line_res = async {
                        if let Some(ref mut reader) = stdout_reader {
                            reader.next_line().await
                        } else {
                            futures_util::future::pending().await
                        }
                    } => {
                        match line_res {
                            Ok(Some(line)) => {
                                Self::process_log_line(&instance_id, &line, &instances_clone, &event_tx_clone, &re);
                            }
                            _ => break,
                        }
                    }
                    err_res = async {
                        if let Some(ref mut reader) = stderr_reader {
                            reader.next_line().await
                        } else {
                            futures_util::future::pending().await
                        }
                    } => {
                        match err_res {
                            Ok(Some(line)) => {
                                Self::process_log_line(&instance_id, &line, &instances_clone, &event_tx_clone, &re);
                            }
                            _ => break,
                        }
                    }
                    status = child.wait() => {
                        debug!("Instance {} child exited: {:?}", instance_id, status);
                        break;
                    }
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

    pub async fn restart_instance(&self, id: &str) -> Result<(), String> {
        self.stop_instance(id).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.start_instance(id).await
    }

    fn process_log_line(
        instance_id: &str,
        line: &str,
        instances: &Arc<DashMap<String, Instance>>,
        event_tx: &broadcast::Sender<InstanceEvent>,
        re: &Regex,
    ) {
        if let Some(caps) = re.captures(line) {
            if let Some(mut inst) = instances.get_mut(instance_id) {
                if let Ok(v) = caps[1].parse::<i32>() { inst.mode = v; }
                if let Ok(v) = caps[2].parse::<i32>() { inst.ping = v; }
                if let Ok(v) = caps[3].parse::<i32>() { inst.pool = v; }
                if let Ok(v) = caps[4].parse::<i32>() { inst.tcps = v; }
                if let Ok(v) = caps[5].parse::<i32>() { inst.udps = v; }

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

        if line.contains("Server error:") || line.contains("Client error:") {
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
    // Return timestamp formatted like 2006-01-02 15:04:05
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}
