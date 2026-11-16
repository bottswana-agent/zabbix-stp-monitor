//! Turns monitor state and events into Zabbix item values.

use std::collections::VecDeque;

use log::{error, info, warn};
use serde_json::json;

use crate::state::{Event, Monitor, TcClass, VlanState};
use crate::zabbix::{Sender, Value};

/// Maximum number of undelivered event values kept for retry.
const MAX_PENDING: usize = 10_000;

pub enum Output {
    Zabbix(Sender),
    /// Print values instead of sending them (`--dry-run`).
    Stdout,
}

pub struct Reporter {
    output: Output,
    pub monitor: Monitor,
    tc_window: i64,
    started: i64,
    /// Event values (TC alerts) that have not been delivered yet.
    pending: VecDeque<Value>,
}

impl Reporter {
    pub fn new(output: Output, monitor: Monitor, tc_window: u64, started: i64) -> Self {
        Reporter {
            output,
            monitor,
            tc_window: tc_window as i64,
            started,
            pending: VecDeque::new(),
        }
    }

    pub fn set_started(&mut self, t: i64) {
        self.started = t;
    }

    /// Process events produced by the monitor; pushes alert data immediately.
    pub fn handle_events(&mut self, events: Vec<Event>, now: i64) {
        let mut new_vlan = false;
        let mut urgent = Vec::new();
        for ev in events {
            match ev {
                Event::NewVlan(vlan) => {
                    info!("discovered spanning tree on VLAN {vlan}");
                    new_vlan = true;
                }
                Event::TopologyChange {
                    vlan,
                    clock,
                    class,
                    reclassified: _,
                    detail,
                } => {
                    match class {
                        TcClass::Significant => warn!("TOPOLOGY CHANGE {detail}"),
                        TcClass::Minor => info!("topology change {detail}"),
                        TcClass::Local => info!("topology change ignored {detail}"),
                    }
                    urgent.push(Value::new(format!("stp.tc.event[{vlan}]"), &detail, clock));
                    if let Some(st) = self.monitor.vlans.get_mut(&vlan) {
                        urgent.extend(tc_values(st, now, self.tc_window));
                    }
                }
                Event::RootChanged { vlan, old, new } => {
                    warn!("ROOT BRIDGE CHANGED on VLAN {vlan}: {old} -> {new}");
                    if let Some(st) = self.monitor.vlans.get_mut(&vlan) {
                        urgent.extend(vlan_values(st, now, self.tc_window));
                    }
                }
            }
        }
        if new_vlan {
            self.send_lld(now);
        }
        if !urgent.is_empty() {
            self.pending.extend(urgent);
            while self.pending.len() > MAX_PENDING {
                self.pending.pop_front();
            }
            self.deliver(Vec::new());
        }
    }

    /// Low-level discovery: tells Zabbix which VLANs exist.
    pub fn send_lld(&mut self, now: i64) {
        let data: Vec<_> = self
            .monitor
            .vlans
            .keys()
            .map(|v| json!({"{#VLAN}": v.to_string()}))
            .collect();
        let value = Value::new("stp.vlan.discovery", serde_json::Value::Array(data), now);
        self.send(&[value], "discovery");
    }

    /// Periodic full state report.
    pub fn report(&mut self, now: i64) {
        let m = &mut self.monitor;
        let mut values = vec![
            Value::new("stp.monitor.heartbeat", now, now),
            Value::new("stp.monitor.uptime", now - self.started, now),
            Value::new("stp.monitor.bpdu.total", m.total_bpdus, now),
            Value::new(
                "stp.monitor.bpdu.age",
                now - m.last_bpdu.unwrap_or(self.started),
                now,
            ),
            Value::new("stp.monitor.vlans", m.vlans.len(), now),
        ];
        for st in m.vlans.values_mut() {
            values.extend(vlan_values(st, now, self.tc_window));
        }
        self.deliver(values);
    }

    /// Send `values` together with any pending event values. Pending values
    /// are kept for retry if delivery fails.
    fn deliver(&mut self, values: Vec<Value>) {
        let n_pending = self.pending.len();
        let mut batch: Vec<Value> = self.pending.iter().cloned().collect();
        batch.extend(values);
        if batch.is_empty() {
            return;
        }
        if self.send(&batch, "report") {
            self.pending.drain(..n_pending);
        }
    }

    fn send(&self, values: &[Value], what: &str) -> bool {
        match &self.output {
            Output::Stdout => {
                for v in values {
                    println!("{} {} = {}", v.clock, v.key, v.value);
                }
                true
            }
            Output::Zabbix(sender) => match sender.send(values) {
                Ok(r) => {
                    if r.failed > 0 {
                        warn!(
                            "Zabbix {what}: processed {}, failed {} of {}. Check that host {:?} exists, has the \
                             'STP Monitor' template linked, and that discovery has created the VLAN items \
                             (this is normal for a minute after a new VLAN appears).",
                            r.processed,
                            r.failed,
                            r.total,
                            sender.host()
                        );
                    } else {
                        log::debug!("Zabbix {what}: processed {} values", r.processed);
                    }
                    true
                }
                Err(e) => {
                    error!("Zabbix {what} failed: {e:#}");
                    false
                }
            },
        }
    }
}

fn tc_values(st: &mut VlanState, now: i64, window: i64) -> Vec<Value> {
    let v = st.vlan;
    vec![
        Value::new(format!("stp.tc.count[{v}]"), st.tc_count, now),
        Value::new(
            format!("stp.tc.recent[{v}]"),
            st.tc_in_window(now, window),
            now,
        ),
        Value::new(
            format!("stp.tc.significant.count[{v}]"),
            st.tc_significant_count,
            now,
        ),
        Value::new(
            format!("stp.tc.significant.recent[{v}]"),
            st.significant_in_window(now, window),
            now,
        ),
        Value::new(format!("stp.tc.local.count[{v}]"), st.tc_local_count, now),
        Value::new(format!("stp.tc.last[{v}]"), st.last_tc.unwrap_or(0), now),
        Value::new(format!("stp.tc.active[{v}]"), st.tc_active(now) as u8, now),
    ]
}

fn vlan_values(st: &mut VlanState, now: i64, window: i64) -> Vec<Value> {
    let v = st.vlan;
    let mut out = vec![
        Value::new(format!("stp.bpdu.count[{v}]"), st.bpdu_count, now),
        Value::new(format!("stp.bpdu.age[{v}]"), now - st.last_seen, now),
        Value::new(format!("stp.tcn.count[{v}]"), st.tcn_bpdu_count, now),
        Value::new(format!("stp.root.changes[{v}]"), st.root_changes, now),
        Value::new(format!("stp.tree.changes[{v}]"), st.tree_changes, now),
    ];
    out.extend(tc_values(st, now, window));
    if let Some(b) = &st.last_config {
        let c = b
            .config
            .as_ref()
            .expect("last_config always carries config info");
        let na = "n/a".to_string();
        out.extend([
            Value::new(
                format!("stp.protocol[{v}]"),
                format!("{} ({})", b.protocol_name(), b.encapsulation),
                now,
            ),
            Value::new(format!("stp.root.id[{v}]"), c.root_id, now),
            Value::new(format!("stp.root.priority[{v}]"), c.root_id.priority, now),
            Value::new(format!("stp.root.mac[{v}]"), c.root_id.mac_string(), now),
            Value::new(format!("stp.root.cost[{v}]"), c.root_path_cost, now),
            Value::new(format!("stp.bridge.id[{v}]"), c.bridge_id, now),
            Value::new(format!("stp.port.id[{v}]"), c.port_id_string(), now),
            Value::new(
                format!("stp.port.role[{v}]"),
                b.port_role()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| na.clone()),
                now,
            ),
            Value::new(
                format!("stp.port.state[{v}]"),
                b.port_state().unwrap_or("n/a"),
                now,
            ),
            Value::new(format!("stp.timer.hello[{v}]"), c.hello_time, now),
            Value::new(format!("stp.timer.maxage[{v}]"), c.max_age, now),
            Value::new(format!("stp.timer.fwddelay[{v}]"), c.forward_delay, now),
            Value::new(format!("stp.message.age[{v}]"), c.message_age, now),
        ]);
    }
    out
}
