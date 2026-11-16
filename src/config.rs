use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Cisco PVST+ / Rapid-PVST+: one spanning tree per VLAN; every VLAN on
    /// the trunk is monitored.
    #[serde(alias = "rapid-pvst", alias = "rpvst", alias = "pvst+")]
    Pvst,
    /// IEEE STP / RSTP / MSTP (CIST): one spanning tree, monitored on the
    /// native (untagged) VLAN only. Use this for UniFi (RSTP) networks.
    #[serde(alias = "rstp", alias = "mstp", alias = "ieee")]
    Stp,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Capture interface: the Npcap device name (`\Device\NPF_{GUID}`), the
    /// GUID alone, or a case-insensitive substring of the device description.
    pub interface: String,
    #[serde(default = "default_mode")]
    pub mode: Mode,
    /// VLAN ID that untagged IEEE BPDUs are reported under.
    #[serde(default = "default_native_vlan")]
    pub native_vlan: u16,
    /// Optional allow list; if set, only these VLANs are reported.
    #[serde(default)]
    pub vlans: Option<Vec<u16>>,
    #[serde(default = "default_true")]
    pub promiscuous: bool,
    /// Sliding window (seconds) used for the `stp.tc.recent[vlan]` item.
    #[serde(default = "default_tc_window")]
    pub tc_window: u64,
    /// A TC within this many seconds of a visible tree change (root, root
    /// path cost, hop count, designated bridge/port) is "significant";
    /// otherwise it is "minor" (typically an edge device connecting).
    #[serde(default = "default_tc_correlation_window")]
    pub tc_correlation_window: u64,
    /// TCs within this many seconds of BPDUs (re)appearing are attributed to
    /// the monitor's own link coming up and are not alerted.
    #[serde(default = "default_tc_local_grace")]
    pub tc_local_grace: u64,
    pub zabbix: ZabbixConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZabbixConfig {
    /// Zabbix server or proxy address (trapper port). For a Zabbix 7.0 HA
    /// cluster list every node, separated by `,` or `;` – optionally as
    /// `host:port`. Data goes to whichever node accepts it.
    pub server: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Technical host name of the Zabbix host the template is linked to.
    pub host: String,
    /// Seconds between periodic state reports.
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Seconds between low-level discovery refreshes.
    #[serde(default = "default_lld_interval")]
    pub lld_interval: u64,
    /// Network timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_mode() -> Mode {
    Mode::Pvst
}
fn default_native_vlan() -> u16 {
    1
}
fn default_true() -> bool {
    true
}
fn default_tc_window() -> u64 {
    300
}
fn default_tc_correlation_window() -> u64 {
    30
}
fn default_tc_local_grace() -> u64 {
    20
}
fn default_port() -> u16 {
    10051
}
fn default_interval() -> u64 {
    30
}
fn default_lld_interval() -> u64 {
    300
}
fn default_timeout() -> u64 {
    5
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if !(1..=4094).contains(&self.native_vlan) {
            bail!("native_vlan must be between 1 and 4094");
        }
        if let Some(v) = &self.vlans {
            if let Some(bad) = v.iter().find(|v| !(1..=4094).contains(*v)) {
                bail!("invalid VLAN {bad} in `vlans`");
            }
        }
        if self.zabbix.interval == 0 || self.zabbix.lld_interval == 0 || self.tc_window == 0 {
            bail!("interval, lld_interval and tc_window must be greater than zero");
        }
        if self.zabbix.host.trim().is_empty() {
            bail!("zabbix.host must not be empty");
        }
        Ok(())
    }
}
