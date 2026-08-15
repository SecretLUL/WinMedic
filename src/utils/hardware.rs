use sysinfo::{Disks, System};

#[derive(Debug, Clone)]
pub struct SystemTelemetry {
    pub os_name: String,
    pub os_version: String,
    pub host_name: String,
    pub cpu_name: String,
    pub cpu_count: usize,
    pub cpu_usage: f32,
    pub ram_total_mb: u64,
    pub ram_used_mb: u64,
    pub ram_usage_percent: f32,
    pub disks: Vec<DiskInfo>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_space_gb: f64,
    pub available_space_gb: f64,
    pub used_percent: f32,
    pub is_removable: bool,
}

pub struct TelemetryCollector {
    sys: System,
    disks: Disks,
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        Self { sys, disks }
    }

    pub fn refresh(&mut self) -> SystemTelemetry {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.disks.refresh(true);

        let os_name = System::name().unwrap_or_else(|| "Windows".to_string());
        let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
        let host_name = System::host_name().unwrap_or_else(|| "PC".to_string());

        let cpus = self.sys.cpus();
        let cpu_name = cpus
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "CPU".to_string());
        let cpu_count = cpus.len();
        let cpu_usage = self.sys.global_cpu_usage();

        let ram_total_mb = self.sys.total_memory() / (1024 * 1024);
        let ram_used_mb = self.sys.used_memory() / (1024 * 1024);
        let ram_usage_percent = if ram_total_mb > 0 {
            (ram_used_mb as f32 / ram_total_mb as f32) * 100.0
        } else {
            0.0
        };

        let disks_info: Vec<DiskInfo> = self
            .disks
            .iter()
            .map(|d| {
                let total_gb = d.total_space() as f64 / (1024.0 * 1024.0 * 1024.0);
                let avail_gb = d.available_space() as f64 / (1024.0 * 1024.0 * 1024.0);
                let used_gb = total_gb - avail_gb;
                let used_percent = if total_gb > 0.0 {
                    ((used_gb / total_gb) * 100.0) as f32
                } else {
                    0.0
                };
                DiskInfo {
                    name: d.name().to_string_lossy().to_string(),
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    total_space_gb: total_gb,
                    available_space_gb: avail_gb,
                    used_percent,
                    is_removable: d.is_removable(),
                }
            })
            .collect();

        let uptime_secs = System::uptime();

        SystemTelemetry {
            os_name,
            os_version,
            host_name,
            cpu_name,
            cpu_count,
            cpu_usage,
            ram_total_mb,
            ram_used_mb,
            ram_usage_percent,
            disks: disks_info,
            uptime_secs,
        }
    }
}
