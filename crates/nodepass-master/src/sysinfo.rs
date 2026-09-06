use crate::types::SystemInfo;
use std::time::Instant;

pub fn get_linux_sys_info() -> SystemInfo {
    let info = SystemInfo::default();

    #[cfg(target_os = "linux")]
    {
        // /proc/uptime
        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            if let Some(first) = content.split_whitespace().next() {
                if let Ok(secs) = first.parse::<f64>() {
                    info.sysup = secs as u64;
                }
            }
        }

        // /proc/meminfo
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            let mut mem_total = 0u64;
            let mut mem_available = 0u64;
            let mut swap_total = 0u64;
            let mut swap_free = 0u64;

            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let val = parts[1].parse::<u64>().unwrap_or(0) * 1024;
                    match parts[0] {
                        "MemTotal:" => mem_total = val,
                        "MemAvailable:" => mem_available = val,
                        "SwapTotal:" => swap_total = val,
                        "SwapFree:" => swap_free = val,
                        _ => {}
                    }
                }
            }

            info.mem_total = mem_total;
            info.mem_used = mem_total.saturating_sub(mem_available);
            info.swap_total = swap_total;
            info.swap_used = swap_total.saturating_sub(swap_free);
        }

        // /proc/stat CPU utilization (simple estimation)
        if let Ok(content) = fs::read_to_string("/proc/stat") {
            if let Some(line) = content.lines().next() {
                let parts: Vec<u64> = line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|s| s.parse::<u64>().ok())
                    .collect();
                if parts.len() >= 4 {
                    let idle = parts[3];
                    let total: u64 = parts.iter().sum();
                    if total > 0 {
                        let non_idle = total.saturating_sub(idle);
                        info.cpu = ((non_idle * 100) / total) as i32;
                    }
                }
            }
        }
    }

    info
}

#[allow(clippy::too_many_arguments)]
pub fn get_master_info(
    mid: &str,
    alias: &str,
    version: &str,
    hostname: &str,
    log_level: &str,
    tls_code: &str,
    crt_path: &str,
    key_path: &str,
    start_time: Instant,
) -> serde_json::Value {
    let sys_info = get_linux_sys_info();

    serde_json::json!({
        "mid": mid,
        "alias": alias,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "noc": num_cpus(),
        "cpu": sys_info.cpu,
        "mem_total": sys_info.mem_total,
        "mem_used": sys_info.mem_used,
        "swap_total": sys_info.swap_total,
        "swap_used": sys_info.swap_used,
        "netrx": sys_info.netrx,
        "nettx": sys_info.nettx,
        "diskr": sys_info.diskr,
        "diskw": sys_info.diskw,
        "sysup": sys_info.sysup,
        "ver": version,
        "name": hostname,
        "uptime": start_time.elapsed().as_secs(),
        "log": log_level,
        "tls": tls_code,
        "crt": crt_path,
        "key": key_path,
    })
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
