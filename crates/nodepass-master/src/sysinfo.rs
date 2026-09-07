use crate::types::SystemInfo;
#[cfg(target_os = "linux")]
use std::fs;
use std::time::Instant;

#[cfg(target_os = "linux")]
static PREV_CPU: parking_lot::Mutex<Option<(u64, u64)>> = parking_lot::Mutex::new(None);

pub fn get_linux_sys_info() -> SystemInfo {
    #[allow(unused_mut)]
    let mut info = SystemInfo::default();

    #[cfg(target_os = "linux")]
    {
        // /proc/uptime
        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            parse_linux_uptime(&content, &mut info);
        }

        // /proc/meminfo
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            parse_linux_meminfo(&content, &mut info);
        }

        // /proc/stat CPU utilization (delta-based estimation)
        if let Ok(content) = fs::read_to_string("/proc/stat") {
            let mut prev_guard = PREV_CPU.lock();
            parse_linux_stat(&content, &mut info, &mut prev_guard);
        }

        // /proc/net/dev
        if let Ok(content) = fs::read_to_string("/proc/net/dev") {
            parse_linux_net_dev(&content, &mut info);
        }

        // /proc/diskstats
        if let Ok(content) = fs::read_to_string("/proc/diskstats") {
            parse_linux_diskstats(&content, &mut info);
        }
    }

    info
}

pub fn parse_linux_uptime(content: &str, info: &mut SystemInfo) {
    if let Some(first) = content.split_whitespace().next() {
        if let Ok(secs) = first.parse::<f64>() {
            info.sysup = secs as u64;
        }
    }
}

pub fn parse_linux_meminfo(content: &str, info: &mut SystemInfo) {
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

pub fn parse_linux_stat(content: &str, info: &mut SystemInfo, prev_cpu: &mut Option<(u64, u64)>) {
    if let Some(line) = content.lines().next() {
        if line.starts_with("cpu ") {
            let parts: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .filter_map(|s| s.parse::<u64>().ok())
                .collect();
            if parts.len() >= 4 {
                let idle = parts[3];
                let total: u64 = parts.iter().sum();
                if let Some((prev_total, prev_idle)) = *prev_cpu {
                    let delta_total = total.saturating_sub(prev_total);
                    let delta_idle = idle.saturating_sub(prev_idle);
                    if delta_total > 0 {
                        let non_idle = delta_total.saturating_sub(delta_idle);
                        info.cpu = ((non_idle * 100) / delta_total).min(100) as i32;
                    }
                } else if total > 0 {
                    let non_idle = total.saturating_sub(idle);
                    info.cpu = ((non_idle * 100) / total).min(100) as i32;
                }
                *prev_cpu = Some((total, idle));
            }
        }
    }
}

pub fn parse_linux_net_dev(content: &str, info: &mut SystemInfo) {
    let mut rx_total = 0u64;
    let mut tx_total = 0u64;
    for line in content.lines().skip(2) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 10 {
            let ifname = fields[0].trim_end_matches(':');
            if ifname.starts_with("lo")
                || ifname.starts_with("veth")
                || ifname.starts_with("docker")
                || ifname.starts_with("podman")
                || ifname.starts_with("br-")
                || ifname.starts_with("virbr")
            {
                continue;
            }
            if let Ok(rx) = fields[1].parse::<u64>() {
                rx_total = rx_total.saturating_add(rx);
            }
            if let Ok(tx) = fields[9].parse::<u64>() {
                tx_total = tx_total.saturating_add(tx);
            }
        }
    }
    info.netrx = rx_total;
    info.nettx = tx_total;
}

pub fn parse_linux_diskstats(content: &str, info: &mut SystemInfo) {
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 14 {
            let dev_name = fields[2];
            if dev_name.contains("loop")
                || dev_name.contains("ram")
                || dev_name.starts_with("dm-")
                || dev_name.starts_with("md")
            {
                continue;
            }
            // Skip partition devices ending with a digit (e.g. sda1, nvme0n1p1)
            if dev_name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                continue;
            }
            if let Ok(r_sectors) = fields[5].parse::<u64>() {
                read_bytes = read_bytes.saturating_add(r_sectors.saturating_mul(512));
            }
            if let Ok(w_sectors) = fields[9].parse::<u64>() {
                write_bytes = write_bytes.saturating_add(w_sectors.saturating_mul(512));
            }
        }
    }
    info.diskr = read_bytes;
    info.diskw = write_bytes;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_linux_proc_files() {
        let mut info = SystemInfo::default();
        assert_eq!(info.cpu, -1);

        // Uptime
        let uptime_str = "123456.78 987654.32";
        parse_linux_uptime(uptime_str, &mut info);
        assert_eq!(info.sysup, 123456);

        // Meminfo
        let meminfo_str = "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       2048000 kB\nSwapFree:        1024000 kB\n";
        parse_linux_meminfo(meminfo_str, &mut info);
        assert_eq!(info.mem_total, 16384000 * 1024);
        assert_eq!(info.mem_used, 8192000 * 1024);
        assert_eq!(info.swap_total, 2048000 * 1024);
        assert_eq!(info.swap_used, 1024000 * 1024);

        // Stat
        let stat_str = "cpu  2255 34 2290 22625563 6290 127 456 0 0 0\n";
        let mut prev = None;
        parse_linux_stat(stat_str, &mut info, &mut prev);
        assert!(info.cpu >= 0 && info.cpu <= 100);

        // Net dev
        let net_dev_str = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000       10    0    0    0     0          0         0     1000       10    0    0    0     0       0          0\n  eth0: 50000000   1000    0    0    0     0          0         0 20000000   1000    0    0    0     0       0          0\n";
        parse_linux_net_dev(net_dev_str, &mut info);
        assert_eq!(info.netrx, 50000000);
        assert_eq!(info.nettx, 20000000);

        // Diskstats
        let diskstats_str = "   8       0 sda 1000 0 80000 100 2000 0 160000 200 0 300 300 0 0 0 0\n   8       1 sda1 1000 0 80000 100 2000 0 160000 200 0 300 300 0 0 0 0\n";
        parse_linux_diskstats(diskstats_str, &mut info);
        assert_eq!(info.diskr, 80000 * 512);
        assert_eq!(info.diskw, 160000 * 512);
    }
}
