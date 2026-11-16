//! Per-VLAN spanning tree state, topology change detection and classification.
//!
//! # TC classification
//!
//! Not every topology change matters. In RSTP networks that do not mark
//! access ports as edge ports (UniFi switches are a common example), every
//! client device that connects – a PC, phone dock, printer, AP – can trigger a
//! network-wide TC. Those are noise. A TC that actually moved the spanning
//! tree (link failure, root change, path change) is not.
//!
//! From a trunk we can only see the tree as advertised by the upstream switch,
//! so each TC is classified as:
//!
//! * **Significant** – within `correlation_window` seconds of a change in what
//!   the upstream switch advertises: root bridge, root path cost, hop count
//!   to the root (message age), or designated bridge/port. The tree moved.
//! * **Minor** – no visible tree change. Typically an edge device connecting
//!   or disconnecting somewhere. A minor TC is upgraded to significant if a
//!   tree change follows within the correlation window.
//! * **Local** – within `local_grace` seconds of BPDUs (re)appearing on this
//!   trunk, i.e. most likely caused by the monitor's own link coming up.

use std::collections::{BTreeMap, VecDeque};

use crate::bpdu::{format_mac, Bpdu, BpduType, BridgeId, ConfigInfo};
use crate::config::Mode;

/// Minimum seconds between TC indications for them to count as separate events.
const MIN_TC_HOLD: i64 = 5;
/// Minimum BPDU gap (seconds) treated as the trunk link having gone down.
const MIN_LINK_GAP: i64 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcClass {
    Significant,
    Minor,
    Local,
}

/// Tuning for TC classification.
#[derive(Debug, Clone, Copy)]
pub struct TcPolicy {
    pub correlation_window: i64,
    pub local_grace: i64,
}

impl Default for TcPolicy {
    fn default() -> Self {
        TcPolicy {
            correlation_window: 30,
            local_grace: 20,
        }
    }
}

/// Something that should be pushed to Zabbix immediately rather than waiting
/// for the next periodic report.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// First BPDU seen for a VLAN – Zabbix low-level discovery must be refreshed.
    NewVlan(u16),
    /// A topology change was signalled on a VLAN (or an earlier minor TC was
    /// upgraded to significant, in which case `reclassified` is true).
    TopologyChange {
        vlan: u16,
        clock: i64,
        class: TcClass,
        reclassified: bool,
        detail: String,
    },
    /// The root bridge of a VLAN changed.
    RootChanged {
        vlan: u16,
        old: BridgeId,
        new: BridgeId,
    },
}

#[derive(Debug, Clone)]
pub struct VlanState {
    pub vlan: u16,
    /// Last BPDU that carried configuration information (i.e. not a TCN).
    pub last_config: Option<Bpdu>,
    pub last_seen: i64,
    pub bpdu_count: u64,
    /// Topology changes excluding local-link ones.
    pub tc_count: u64,
    pub tc_significant_count: u64,
    pub tc_local_count: u64,
    pub tcn_bpdu_count: u64,
    pub last_tc: Option<i64>,
    pub root_changes: u64,
    pub tree_changes: u64,
    pub last_tree_change: Option<(i64, String)>,
    /// Time of the most recent BPDU that signalled a topology change. One TC
    /// "event" spans several BPDUs (RSTP keeps the flag set for tcWhile, a
    /// TCN is repeated until acknowledged, and VLAN 1 is often reported by
    /// both IEEE and PVST+ BPDUs), so indications closer together than the
    /// hold time are merged into one event.
    last_tc_indication: Option<i64>,
    hold: i64,
    /// When BPDUs (re)started arriving for this VLAN.
    link_up_since: i64,
    /// Most recent minor TC, which may still be upgraded to significant.
    pending_minor: Option<(i64, String)>,
    recent_tc: VecDeque<i64>,
    recent_significant: VecDeque<i64>,
}

impl VlanState {
    fn new(vlan: u16, now: i64) -> Self {
        VlanState {
            vlan,
            last_config: None,
            last_seen: now,
            bpdu_count: 0,
            tc_count: 0,
            tc_significant_count: 0,
            tc_local_count: 0,
            tcn_bpdu_count: 0,
            last_tc: None,
            root_changes: 0,
            tree_changes: 0,
            last_tree_change: None,
            last_tc_indication: None,
            hold: MIN_TC_HOLD,
            link_up_since: now,
            pending_minor: None,
            recent_tc: VecDeque::new(),
            recent_significant: VecDeque::new(),
        }
    }

    /// Number of (non-local) TC events within `window` seconds before `now`.
    pub fn tc_in_window(&mut self, now: i64, window: i64) -> u64 {
        prune(&mut self.recent_tc, now, window)
    }

    /// Number of significant TC events within `window` seconds before `now`.
    pub fn significant_in_window(&mut self, now: i64, window: i64) -> u64 {
        prune(&mut self.recent_significant, now, window)
    }

    /// True while TC indications are still arriving.
    pub fn tc_active(&self, now: i64) -> bool {
        self.last_tc_indication
            .is_some_and(|t| now - t <= self.hold)
    }

    fn hello(&self) -> f64 {
        self.last_config
            .as_ref()
            .and_then(|b| b.config.as_ref())
            .map_or(2.0, |c| c.hello_time)
    }
}

fn prune(q: &mut VecDeque<i64>, now: i64, window: i64) -> u64 {
    while q.front().is_some_and(|&t| t <= now - window) {
        q.pop_front();
    }
    q.len() as u64
}

/// Describe what changed in the advertised tree, if anything.
fn tree_diff(old: &ConfigInfo, new: &ConfigInfo) -> Option<String> {
    let mut d = Vec::new();
    if old.root_id != new.root_id {
        d.push(format!("root bridge {} -> {}", old.root_id, new.root_id));
    }
    if old.root_path_cost != new.root_path_cost {
        d.push(format!(
            "root path cost {} -> {}",
            old.root_path_cost, new.root_path_cost
        ));
    }
    let (oh, nh) = (
        old.message_age.round() as i64,
        new.message_age.round() as i64,
    );
    if oh != nh {
        d.push(format!("hops to root {oh} -> {nh}"));
    }
    if old.bridge_id != new.bridge_id {
        d.push(format!(
            "designated bridge {} -> {}",
            old.bridge_id, new.bridge_id
        ));
    }
    if old.port_id != new.port_id {
        d.push(format!(
            "designated port {} -> {}",
            old.port_id_string(),
            new.port_id_string()
        ));
    }
    (!d.is_empty()).then(|| d.join(", "))
}

pub struct Monitor {
    mode: Mode,
    native_vlan: u16,
    allowed_vlans: Option<Vec<u16>>,
    policy: TcPolicy,
    pub vlans: BTreeMap<u16, VlanState>,
    pub total_bpdus: u64,
    pub ignored_bpdus: u64,
    pub last_bpdu: Option<i64>,
}

impl Monitor {
    pub fn new(
        mode: Mode,
        native_vlan: u16,
        allowed_vlans: Option<Vec<u16>>,
        policy: TcPolicy,
    ) -> Self {
        Monitor {
            mode,
            native_vlan,
            allowed_vlans,
            policy,
            vlans: BTreeMap::new(),
            total_bpdus: 0,
            ignored_bpdus: 0,
            last_bpdu: None,
        }
    }

    /// Feed one parsed BPDU (received at unix time `now`) into the state
    /// machine and return any events that should be reported immediately.
    pub fn process(&mut self, bpdu: &Bpdu, now: i64) -> Vec<Event> {
        let vlan = match self.mode {
            // Plain STP/RSTP/MSTP: a single (common) spanning tree, carried in
            // untagged IEEE BPDUs on the native VLAN. Ignore Cisco PVST+.
            Mode::Stp => {
                if bpdu.encapsulation != crate::bpdu::Encapsulation::Ieee {
                    self.ignored_bpdus += 1;
                    return Vec::new();
                }
                self.native_vlan
            }
            Mode::Pvst => bpdu.vlan(self.native_vlan),
        };
        if let Some(allowed) = &self.allowed_vlans {
            if !allowed.contains(&vlan) {
                self.ignored_bpdus += 1;
                return Vec::new();
            }
        }

        self.total_bpdus += 1;
        self.last_bpdu = Some(now);
        let policy = self.policy;

        let mut events = Vec::new();
        let st = self.vlans.entry(vlan).or_insert_with(|| {
            events.push(Event::NewVlan(vlan));
            VlanState::new(vlan, now)
        });

        // --- Link (re)appearance: BPDUs resumed after a gap ---------------
        let gap = MIN_LINK_GAP.max((3.0 * st.hello()).ceil() as i64);
        if st.bpdu_count > 0 && now - st.last_seen > gap {
            st.link_up_since = now;
        }
        st.bpdu_count += 1;
        st.last_seen = now;

        // --- Tree changes (must run before TC classification) -------------
        if let Some(cfg) = &bpdu.config {
            if let Some(prev) = st.last_config.as_ref().and_then(|b| b.config.as_ref()) {
                if prev.root_id != cfg.root_id {
                    st.root_changes += 1;
                    events.push(Event::RootChanged {
                        vlan,
                        old: prev.root_id,
                        new: cfg.root_id,
                    });
                }
                if let Some(reason) = tree_diff(prev, cfg) {
                    st.tree_changes += 1;
                    st.last_tree_change = Some((now, reason.clone()));
                    // Upgrade a recent minor TC: the tree moved after all.
                    if let Some((t, detail)) = st.pending_minor.take() {
                        if now - t <= policy.correlation_window {
                            st.tc_significant_count += 1;
                            st.recent_significant.push_back(t);
                            events.push(Event::TopologyChange {
                                vlan,
                                clock: now,
                                class: TcClass::Significant,
                                reclassified: true,
                                detail: format!("[significant: {reason}] (reclassified) {detail}"),
                            });
                        }
                    }
                }
            }
            // Merge indications less than two hello intervals (min 5 s) apart.
            st.hold = MIN_TC_HOLD.max((2.0 * cfg.hello_time).ceil() as i64 + 1);
            st.last_config = Some(bpdu.clone());
        }

        // --- Topology change detection and classification -----------------
        if bpdu.bpdu_type == BpduType::Tcn {
            st.tcn_bpdu_count += 1;
        }
        if bpdu.is_topology_change() {
            if !st.tc_active(now) {
                let base = describe_tc(vlan, bpdu);
                let (class, detail) = if now - st.link_up_since <= policy.local_grace {
                    st.tc_local_count += 1;
                    (
                        TcClass::Local,
                        format!(
                            "[local link: BPDUs started {}s ago] {base}",
                            now - st.link_up_since
                        ),
                    )
                } else {
                    st.tc_count += 1;
                    st.last_tc = Some(now);
                    st.recent_tc.push_back(now);
                    match &st.last_tree_change {
                        Some((t, reason)) if now - t <= policy.correlation_window => {
                            st.tc_significant_count += 1;
                            st.recent_significant.push_back(now);
                            st.pending_minor = None;
                            (
                                TcClass::Significant,
                                format!("[significant: {reason}] {base}"),
                            )
                        }
                        _ => {
                            let detail = format!("[minor: no tree change seen] {base}");
                            st.pending_minor = Some((now, base));
                            (TcClass::Minor, detail)
                        }
                    }
                };
                events.push(Event::TopologyChange {
                    vlan,
                    clock: now,
                    class,
                    reclassified: false,
                    detail,
                });
            }
            st.last_tc_indication = Some(now);
        }

        events
    }
}

fn describe_tc(vlan: u16, b: &Bpdu) -> String {
    let what = if b.bpdu_type == BpduType::Tcn {
        "TCN BPDU received"
    } else {
        "TC flag set in BPDU"
    };
    let mut s = format!(
        "VLAN {vlan}: {what} ({} {}) from {}",
        b.protocol_name(),
        b.encapsulation,
        format_mac(&b.src_mac)
    );
    if let Some(c) = &b.config {
        s.push_str(&format!(
            "; sender bridge {} port {}; root {} cost {}; flags [{}]",
            c.bridge_id,
            c.port_id_string(),
            c.root_id,
            c.root_path_cost,
            b.flags_string()
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpdu::tests::build_frame;
    use crate::bpdu::{parse_frame, Encapsulation};

    fn monitor(mode: Mode, native: u16) -> Monitor {
        Monitor::new(mode, native, None, TcPolicy::default())
    }

    fn rpvst(vlan: u16, flags: u8, root_prio: u16) -> Bpdu {
        parse_frame(&build_frame(
            Encapsulation::PvstPlus,
            None,
            2,
            0x02,
            flags,
            vlan,
            root_prio,
            4,
        ))
        .unwrap()
    }

    /// UniFi-style RSTP BPDU: IEEE, untagged, version 2, priority 32768 with
    /// no system ID extension.
    fn unifi(flags: u8, cost: u32) -> Bpdu {
        parse_frame(&build_frame(
            Encapsulation::Ieee,
            None,
            2,
            0x02,
            flags,
            0,
            32768,
            cost,
        ))
        .unwrap()
    }

    fn tcs(ev: &[Event]) -> Vec<(TcClass, bool)> {
        ev.iter()
            .filter_map(|e| match e {
                Event::TopologyChange {
                    class,
                    reclassified,
                    ..
                } => Some((*class, *reclassified)),
                _ => None,
            })
            .collect()
    }

    /// Feed steady BPDUs every 2 s from `from` to `to` (exclusive).
    fn steady(m: &mut Monitor, b: &Bpdu, from: i64, to: i64) {
        for t in (from..to).step_by(2) {
            m.process(b, t);
        }
    }

    #[test]
    fn tc_indications_are_merged() {
        let mut m = monitor(Mode::Pvst, 1);
        steady(&mut m, &rpvst(10, 0x3C, 32768), 0, 100);
        let ev = m.process(&rpvst(10, 0x3D, 32768), 102);
        assert_eq!(tcs(&ev), vec![(TcClass::Minor, false)]);
        assert!(m.process(&rpvst(10, 0x3D, 32768), 104).is_empty());
        assert!(m.process(&rpvst(10, 0x3C, 32768), 106).is_empty());
        assert!(m.process(&rpvst(10, 0x3D, 32768), 108).is_empty());
        assert!(m.process(&rpvst(10, 0x3C, 32768), 110).is_empty());
        steady(&mut m, &rpvst(10, 0x3C, 32768), 112, 120);
        assert_eq!(m.process(&rpvst(10, 0x3D, 32768), 120).len(), 1);
        let st = m.vlans.get_mut(&10).unwrap();
        assert_eq!(st.tc_count, 2);
        assert!(st.tc_active(124) && !st.tc_active(126));
        assert_eq!(st.tc_in_window(125, 300), 2);
        assert_eq!(st.tc_in_window(405, 300), 1);
        assert_eq!(st.tc_in_window(1000, 300), 0);
    }

    #[test]
    fn vlans_are_independent() {
        let mut m = monitor(Mode::Pvst, 1);
        m.process(&rpvst(10, 0x3D, 32768), 100);
        m.process(&rpvst(20, 0x3C, 32768), 100);
        assert_eq!(m.vlans[&10].tc_count + m.vlans[&10].tc_local_count, 1);
        assert_eq!(m.vlans[&20].tc_count + m.vlans[&20].tc_local_count, 0);
    }

    #[test]
    fn root_change_detected_and_tc_is_significant() {
        let mut m = monitor(Mode::Pvst, 1);
        steady(&mut m, &rpvst(10, 0x3C, 32768), 0, 100);
        let ev = m.process(&rpvst(10, 0x3D, 4096), 100);
        assert!(matches!(ev[0], Event::RootChanged { vlan: 10, .. }));
        assert_eq!(tcs(&ev), vec![(TcClass::Significant, false)]);
        assert_eq!(m.vlans[&10].root_changes, 1);
        assert_eq!(m.vlans[&10].tc_significant_count, 1);
    }

    #[test]
    fn stp_mode_ignores_pvst_and_uses_native_vlan() {
        let mut m = monitor(Mode::Stp, 99);
        assert!(m.process(&rpvst(10, 0x3D, 32768), 1).is_empty());
        assert_eq!(m.ignored_bpdus, 1);
        assert_eq!(m.process(&unifi(0x3C, 4), 1), vec![Event::NewVlan(99)]);
    }

    #[test]
    fn repeated_tcn_counts_once() {
        let mut m = monitor(Mode::Stp, 1);
        let tcn =
            parse_frame(&build_frame(Encapsulation::Ieee, None, 0, 0x80, 0, 1, 0, 0)).unwrap();
        let cfg = parse_frame(&build_frame(
            Encapsulation::Ieee,
            None,
            0,
            0x00,
            0,
            1,
            32768,
            4,
        ))
        .unwrap();
        steady(&mut m, &cfg, 0, 100);
        assert_eq!(m.process(&tcn, 101).len(), 1);
        assert!(m.process(&tcn, 103).is_empty());
        steady(&mut m, &cfg, 104, 120);
        assert_eq!(m.process(&tcn, 120).len(), 1);
        assert_eq!(m.vlans[&1].tcn_bpdu_count, 3);
        assert_eq!(m.vlans[&1].tc_count, 2);
    }

    #[test]
    fn allow_list_filters() {
        let mut m = Monitor::new(Mode::Pvst, 1, Some(vec![20]), TcPolicy::default());
        assert!(m.process(&rpvst(10, 0x3C, 32768), 1).is_empty());
        assert_eq!(m.process(&rpvst(20, 0x3C, 32768), 1).len(), 1);
    }

    #[test]
    fn ieee_and_pvst_on_vlan1_do_not_double_count() {
        let mut m = monitor(Mode::Pvst, 1);
        let ieee_tc = parse_frame(&build_frame(
            Encapsulation::Ieee,
            None,
            2,
            0x02,
            0x3D,
            1,
            32768,
            0,
        ))
        .unwrap();
        let sstp = parse_frame(&build_frame(
            Encapsulation::PvstPlus,
            None,
            2,
            0x02,
            0x3C,
            1,
            32768,
            0,
        ))
        .unwrap();
        for t in [100, 102, 104] {
            m.process(&ieee_tc, t);
            m.process(&sstp, t);
        }
        assert_eq!(m.vlans[&1].tc_count + m.vlans[&1].tc_local_count, 1);
    }

    // --- UniFi / RSTP scenarios -------------------------------------------

    #[test]
    fn unifi_edge_device_tc_is_minor() {
        let mut m = monitor(Mode::Stp, 1);
        steady(&mut m, &unifi(0x3C, 20000), 0, 100);
        // A laptop plugs into an access port somewhere: TC, nothing else changes.
        let ev = m.process(&unifi(0x3D, 20000), 100);
        assert_eq!(tcs(&ev), vec![(TcClass::Minor, false)]);
        steady(&mut m, &unifi(0x3C, 20000), 102, 200);
        let st = m.vlans.get_mut(&1).unwrap();
        assert_eq!((st.tc_count, st.tc_significant_count), (1, 0));
        assert_eq!(st.significant_in_window(200, 300), 0);
    }

    #[test]
    fn unifi_uplink_failure_is_significant() {
        let mut m = monitor(Mode::Stp, 1);
        steady(&mut m, &unifi(0x3C, 20000), 0, 100);
        // Uplink fails, alternate path takes over: cost changes with the TC.
        let ev = m.process(&unifi(0x3D, 40000), 100);
        assert_eq!(tcs(&ev), vec![(TcClass::Significant, false)]);
    }

    #[test]
    fn minor_tc_upgraded_when_tree_changes_shortly_after() {
        let mut m = monitor(Mode::Stp, 1);
        steady(&mut m, &unifi(0x3C, 20000), 0, 100);
        assert_eq!(
            tcs(&m.process(&unifi(0x3D, 20000), 100)),
            vec![(TcClass::Minor, false)]
        );
        let ev = m.process(&unifi(0x3D, 40000), 104);
        assert_eq!(tcs(&ev), vec![(TcClass::Significant, true)]);
        let st = m.vlans.get_mut(&1).unwrap();
        assert_eq!((st.tc_count, st.tc_significant_count), (1, 1));
        assert_eq!(st.significant_in_window(110, 300), 1);
    }

    #[test]
    fn tree_change_long_after_tc_does_not_upgrade() {
        let mut m = monitor(Mode::Stp, 1);
        steady(&mut m, &unifi(0x3C, 20000), 0, 100);
        m.process(&unifi(0x3D, 20000), 100);
        steady(&mut m, &unifi(0x3C, 20000), 102, 200);
        assert!(tcs(&m.process(&unifi(0x3C, 40000), 200)).is_empty());
    }

    #[test]
    fn tc_right_after_link_up_is_local() {
        let mut m = monitor(Mode::Stp, 1);
        // Monitor starts / its port comes up; the switch flags TC because the
        // port just went forwarding.
        m.process(&unifi(0x3C, 20000), 0);
        let ev = m.process(&unifi(0x3D, 20000), 2);
        assert_eq!(tcs(&ev), vec![(TcClass::Local, false)]);
        steady(&mut m, &unifi(0x3C, 20000), 4, 100);
        // Link flap: 30 s of silence, then BPDUs resume with TC.
        m.process(&unifi(0x3C, 20000), 130);
        let ev = m.process(&unifi(0x3D, 20000), 132);
        assert_eq!(tcs(&ev), vec![(TcClass::Local, false)]);
        let st = &m.vlans[&1];
        assert_eq!((st.tc_count, st.tc_local_count), (0, 2));
    }
}
