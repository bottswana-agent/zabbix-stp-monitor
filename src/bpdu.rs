//! Parsing of Ethernet frames carrying Spanning Tree BPDUs.
//!
//! Two encapsulations are understood:
//!
//! * **IEEE** – 802.3 + LLC (DSAP/SSAP 0x42) to `01:80:C2:00:00:00`. Used by
//!   plain 802.1D STP, 802.1w RSTP and 802.1s MSTP, and by Cisco PVST+ /
//!   Rapid-PVST+ for the native VLAN (VLAN 1 by default).
//! * **PVST+ (SSTP)** – 802.3 + LLC/SNAP (OUI 00:00:0C, PID 0x010B) to
//!   `01:00:0C:CC:CC:CD`. Cisco sends one of these per VLAN, tagged with that
//!   VLAN on trunks, and appends an "originating VLAN" (PVID) TLV.
//!
//! The VLAN a BPDU belongs to is taken (in order of preference) from the PVID
//! TLV, the 802.1Q tag, or the bridge-ID system-ID extension. This matters on
//! Windows, where the NIC driver frequently strips 802.1Q tags before Npcap
//! sees the frame – the PVID TLV still tells us the VLAN.

use std::fmt;

#[allow(dead_code)]
pub const IEEE_STP_MAC: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];
#[allow(dead_code)]
pub const PVST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD];

/// BPF filter that matches both encapsulations (destination MAC is the first
/// field of the frame, so this works for tagged and untagged frames alike).
pub const BPF_FILTER: &str = "ether dst 01:80:c2:00:00:00 or ether dst 01:00:0c:cc:cc:cd";

const LLC_STP: [u8; 3] = [0x42, 0x42, 0x03];
const SNAP_PVST: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x0B];

const FLAG_TC: u8 = 0x01;
const FLAG_PROPOSAL: u8 = 0x02;
const FLAG_LEARNING: u8 = 0x10;
const FLAG_FORWARDING: u8 = 0x20;
const FLAG_AGREEMENT: u8 = 0x40;
const FLAG_TCA: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encapsulation {
    Ieee,
    PvstPlus,
}

impl fmt::Display for Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Encapsulation::Ieee => "IEEE",
            Encapsulation::PvstPlus => "PVST+",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpduType {
    /// 802.1D configuration BPDU (type 0x00).
    Config,
    /// 802.1D topology change notification BPDU (type 0x80).
    Tcn,
    /// RST / MST BPDU (type 0x02).
    Rst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRole {
    /// "Unknown" in RSTP, "Master" in MSTP.
    UnknownOrMaster,
    AlternateOrBackup,
    Root,
    Designated,
}

impl fmt::Display for PortRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PortRole::UnknownOrMaster => "unknown/master",
            PortRole::AlternateOrBackup => "alternate/backup",
            PortRole::Root => "root",
            PortRole::Designated => "designated",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BridgeId {
    /// Full 16-bit priority field: 4-bit priority + 12-bit system ID extension.
    pub priority: u16,
    pub mac: [u8; 6],
}

impl BridgeId {
    fn from_bytes(b: &[u8]) -> Self {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&b[2..8]);
        BridgeId {
            priority: u16::from_be_bytes([b[0], b[1]]),
            mac,
        }
    }

    /// The configured bridge priority (multiple of 4096).
    pub fn priority_base(&self) -> u16 {
        self.priority & 0xF000
    }

    /// The system ID extension, which carries the VLAN ID with PVST+.
    pub fn sys_id_ext(&self) -> u16 {
        self.priority & 0x0FFF
    }

    pub fn mac_string(&self) -> String {
        format_mac(&self.mac)
    }
}

impl fmt::Display for BridgeId {
    /// Formats like Wireshark: `priority/sys-id-ext/mac`, e.g. `24576/10/00:11:22:33:44:55`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.priority_base(),
            self.sys_id_ext(),
            self.mac_string()
        )
    }
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Fields present in configuration and RST/MST BPDUs (absent in TCN BPDUs).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigInfo {
    pub root_id: BridgeId,
    pub root_path_cost: u32,
    /// Bridge ID of the bridge that transmitted the BPDU (the designated bridge
    /// for this segment – i.e. the switch on the other end of the trunk).
    pub bridge_id: BridgeId,
    pub port_id: u16,
    /// Timers in seconds.
    pub message_age: f64,
    pub max_age: f64,
    pub hello_time: f64,
    pub forward_delay: f64,
}

impl ConfigInfo {
    /// Port ID formatted Cisco-style as `priority.number`, e.g. `128.12`.
    pub fn port_id_string(&self) -> String {
        format!("{}.{}", self.port_id >> 12 << 4, self.port_id & 0x0FFF)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bpdu {
    pub encapsulation: Encapsulation,
    pub src_mac: [u8; 6],
    /// VLAN from an 802.1Q tag, if the frame still had one.
    pub tag_vlan: Option<u16>,
    /// VLAN from the PVST+ originating-VLAN TLV, if present.
    pub pvid_tlv: Option<u16>,
    /// 0 = STP, 2 = RSTP, 3 = MSTP.
    pub protocol_version: u8,
    pub bpdu_type: BpduType,
    pub flags: u8,
    pub config: Option<ConfigInfo>,
}

impl Bpdu {
    pub fn protocol_name(&self) -> &'static str {
        match (self.bpdu_type, self.protocol_version) {
            (BpduType::Tcn, _) => "STP",
            (_, 0) => "STP",
            (_, 2) => "RSTP",
            (_, 3) => "MSTP",
            _ => "unknown",
        }
    }

    /// True if this BPDU signals a topology change: either a legacy TCN BPDU,
    /// or a config/RST BPDU with the TC flag set.
    pub fn is_topology_change(&self) -> bool {
        self.bpdu_type == BpduType::Tcn || self.flag(FLAG_TC)
    }

    pub fn tc(&self) -> bool {
        self.flag(FLAG_TC)
    }
    pub fn tc_ack(&self) -> bool {
        self.flag(FLAG_TCA)
    }
    pub fn proposal(&self) -> bool {
        self.bpdu_type == BpduType::Rst && self.flag(FLAG_PROPOSAL)
    }
    pub fn agreement(&self) -> bool {
        self.bpdu_type == BpduType::Rst && self.flag(FLAG_AGREEMENT)
    }

    /// Role of the transmitting port (RST/MST BPDUs only).
    pub fn port_role(&self) -> Option<PortRole> {
        if self.bpdu_type != BpduType::Rst {
            return None;
        }
        Some(match (self.flags >> 2) & 0x03 {
            0 => PortRole::UnknownOrMaster,
            1 => PortRole::AlternateOrBackup,
            2 => PortRole::Root,
            _ => PortRole::Designated,
        })
    }

    /// State of the transmitting port (RST/MST BPDUs only).
    pub fn port_state(&self) -> Option<&'static str> {
        if self.bpdu_type != BpduType::Rst {
            return None;
        }
        Some(if self.flag(FLAG_FORWARDING) {
            "forwarding"
        } else if self.flag(FLAG_LEARNING) {
            "learning"
        } else {
            "discarding"
        })
    }

    /// Human readable list of the set flags.
    pub fn flags_string(&self) -> String {
        let mut v = Vec::new();
        if self.tc() {
            v.push("TC");
        }
        if self.proposal() {
            v.push("proposal");
        }
        if self.agreement() {
            v.push("agreement");
        }
        if self.bpdu_type == BpduType::Rst {
            if self.flag(FLAG_LEARNING) {
                v.push("learning");
            }
            if self.flag(FLAG_FORWARDING) {
                v.push("forwarding");
            }
        }
        if self.tc_ack() {
            v.push("TCA");
        }
        v.join(",")
    }

    /// Work out which VLAN this BPDU describes.
    pub fn vlan(&self, native_vlan: u16) -> u16 {
        if let Some(v) = self.pvid_tlv {
            return v;
        }
        if let Some(v) = self.tag_vlan {
            if v != 0 {
                return v;
            }
        }
        // Extended system ID: Cisco carries the VLAN in the low 12 bits of the
        // bridge priority, also in the untagged IEEE BPDU for VLAN 1 (which is
        // sent even when the trunk's native VLAN is something else). Single
        // instance RSTP switches (UniFi, most SMB gear) and the MSTP CIST use
        // 0 here, so their BPDUs fall through to the native VLAN.
        if let Some(c) = &self.config {
            let ext = c.bridge_id.sys_id_ext();
            if ext != 0 {
                return ext;
            }
        }
        native_vlan
    }

    fn flag(&self, mask: u8) -> bool {
        self.flags & mask != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated(&'static str),
    NotLlc,
    NotStp,
    BadProtocolId(u16),
    UnknownBpduType(u8),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated(what) => write!(f, "frame truncated ({what})"),
            ParseError::NotLlc => write!(f, "not an 802.3/LLC frame"),
            ParseError::NotStp => write!(f, "LLC payload is not STP"),
            ParseError::BadProtocolId(p) => write!(f, "unexpected BPDU protocol id 0x{p:04x}"),
            ParseError::UnknownBpduType(t) => write!(f, "unknown BPDU type 0x{t:02x}"),
        }
    }
}

impl std::error::Error for ParseError {}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn timer(b: &[u8], off: usize) -> f64 {
    // Timers are encoded in units of 1/256 second.
    be16(b, off) as f64 / 256.0
}

/// Parse a raw Ethernet frame (as captured, starting with the destination MAC).
pub fn parse_frame(frame: &[u8]) -> Result<Bpdu, ParseError> {
    if frame.len() < 14 {
        return Err(ParseError::Truncated("ethernet header"));
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);

    // Walk any VLAN tags (802.1Q, 802.1ad, legacy QinQ). Keep the innermost.
    let mut off = 12;
    let mut tag_vlan = None;
    loop {
        if frame.len() < off + 2 {
            return Err(ParseError::Truncated("ethertype"));
        }
        let ethertype = be16(frame, off);
        if matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) {
            if frame.len() < off + 4 {
                return Err(ParseError::Truncated("vlan tag"));
            }
            tag_vlan = Some(be16(frame, off + 2) & 0x0FFF);
            off += 4;
            continue;
        }
        if ethertype > 1500 {
            return Err(ParseError::NotLlc);
        }
        // 802.3 length field; trim trailing Ethernet padding / FCS.
        let len = ethertype as usize;
        let start = off + 2;
        let end = (start + len).min(frame.len());
        return parse_llc(&frame[start..end], src_mac, tag_vlan);
    }
}

fn parse_llc(payload: &[u8], src_mac: [u8; 6], tag_vlan: Option<u16>) -> Result<Bpdu, ParseError> {
    let (encapsulation, body) = if payload.starts_with(&LLC_STP) {
        (Encapsulation::Ieee, &payload[LLC_STP.len()..])
    } else if payload.starts_with(&SNAP_PVST) {
        (Encapsulation::PvstPlus, &payload[SNAP_PVST.len()..])
    } else {
        return Err(ParseError::NotStp);
    };

    if body.len() < 4 {
        return Err(ParseError::Truncated("bpdu header"));
    }
    let protocol_id = be16(body, 0);
    if protocol_id != 0 {
        return Err(ParseError::BadProtocolId(protocol_id));
    }
    let protocol_version = body[2];
    let bpdu_type = match body[3] {
        0x00 => BpduType::Config,
        0x80 => BpduType::Tcn,
        0x02 => BpduType::Rst,
        t => return Err(ParseError::UnknownBpduType(t)),
    };

    let mut bpdu = Bpdu {
        encapsulation,
        src_mac,
        tag_vlan,
        pvid_tlv: None,
        protocol_version,
        bpdu_type,
        flags: 0,
        config: None,
    };

    if bpdu_type == BpduType::Tcn {
        return Ok(bpdu);
    }

    if body.len() < 35 {
        return Err(ParseError::Truncated("configuration bpdu"));
    }
    bpdu.flags = body[4];
    bpdu.config = Some(ConfigInfo {
        root_id: BridgeId::from_bytes(&body[5..13]),
        root_path_cost: be32(body, 13),
        bridge_id: BridgeId::from_bytes(&body[17..25]),
        port_id: be16(body, 25),
        message_age: timer(body, 27),
        max_age: timer(body, 29),
        hello_time: timer(body, 31),
        forward_delay: timer(body, 33),
    });

    if encapsulation == Encapsulation::PvstPlus {
        // Config BPDU = 35 bytes, RST BPDU = 36 bytes (version-1 length byte).
        // Cisco pads the config BPDU, so search a few bytes for the TLV
        // (type 0x0000, length 0x0002, value = VLAN ID).
        let base = if bpdu_type == BpduType::Rst { 36 } else { 35 };
        bpdu.pvid_tlv = (base..=base + 3).find_map(|o| {
            let tlv = body.get(o..o + 6)?;
            let vlan = be16(tlv, 4);
            (tlv[..4] == [0, 0, 0, 2] && (1..=4094).contains(&vlan)).then_some(vlan)
        });
    }

    Ok(bpdu)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const SWITCH_MAC: [u8; 6] = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

    /// Build a BPDU frame for tests.
    #[allow(clippy::too_many_arguments)]
    pub fn build_frame(
        encap: Encapsulation,
        tag: Option<u16>,
        version: u8,
        bpdu_type: u8,
        flags: u8,
        vlan: u16,
        root_prio: u16,
        cost: u32,
    ) -> Vec<u8> {
        let mut body = vec![0x00, 0x00, version, bpdu_type];
        if bpdu_type != 0x80 {
            body.push(flags);
            body.extend_from_slice(&(root_prio + vlan).to_be_bytes());
            body.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            body.extend_from_slice(&cost.to_be_bytes());
            body.extend_from_slice(&(32768 + vlan).to_be_bytes());
            body.extend_from_slice(&SWITCH_MAC);
            body.extend_from_slice(&0x800cu16.to_be_bytes()); // port 128.12
            for t in [0u16, 20, 2, 15] {
                body.extend_from_slice(&(t * 256).to_be_bytes());
            }
            if bpdu_type == 0x02 {
                body.push(0); // version 1 length
            } else if encap == Encapsulation::PvstPlus {
                body.push(0); // Cisco padding
            }
            if encap == Encapsulation::PvstPlus {
                body.extend_from_slice(&[0, 0, 0, 2]);
                body.extend_from_slice(&vlan.to_be_bytes());
            }
        }
        let (dst, llc): ([u8; 6], &[u8]) = match encap {
            Encapsulation::Ieee => (IEEE_STP_MAC, &LLC_STP),
            Encapsulation::PvstPlus => (PVST_MAC, &SNAP_PVST),
        };
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&SWITCH_MAC);
        if let Some(t) = tag {
            f.extend_from_slice(&[0x81, 0x00]);
            f.extend_from_slice(&(0xE000 | t).to_be_bytes());
        }
        f.extend_from_slice(&((llc.len() + body.len()) as u16).to_be_bytes());
        f.extend_from_slice(llc);
        f.extend_from_slice(&body);
        while f.len() < 60 {
            f.push(0);
        }
        f
    }

    #[test]
    fn parses_ieee_stp_config() {
        let f = build_frame(Encapsulation::Ieee, None, 0, 0x00, 0x00, 1, 32768, 19);
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.encapsulation, Encapsulation::Ieee);
        assert_eq!(b.bpdu_type, BpduType::Config);
        assert_eq!(b.protocol_name(), "STP");
        let c = b.config.as_ref().unwrap();
        assert_eq!(c.root_id.priority_base(), 32768);
        assert_eq!(c.root_id.sys_id_ext(), 1);
        assert_eq!(c.root_id.to_string(), "32768/1/00:11:22:33:44:55");
        assert_eq!(c.root_path_cost, 19);
        assert_eq!(c.port_id_string(), "128.12");
        assert_eq!(c.hello_time, 2.0);
        assert_eq!(c.max_age, 20.0);
        assert_eq!(c.forward_delay, 15.0);
        assert_eq!(b.vlan(1), 1);
        assert!(!b.is_topology_change());
    }

    #[test]
    fn parses_rapid_pvst_tagged() {
        let f = build_frame(
            Encapsulation::PvstPlus,
            Some(20),
            2,
            0x02,
            0x3D,
            20,
            24576,
            4,
        );
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.encapsulation, Encapsulation::PvstPlus);
        assert_eq!(b.protocol_name(), "RSTP");
        assert_eq!(b.tag_vlan, Some(20));
        assert_eq!(b.pvid_tlv, Some(20));
        assert_eq!(b.vlan(1), 20);
        assert!(b.tc());
        assert!(b.is_topology_change());
        assert_eq!(b.port_role(), Some(PortRole::Designated));
        assert_eq!(b.port_state(), Some("forwarding"));
    }

    #[test]
    fn vlan_from_pvid_tlv_when_tag_stripped() {
        // Windows NIC drivers often strip the 802.1Q tag.
        let f = build_frame(Encapsulation::PvstPlus, None, 2, 0x02, 0x3C, 300, 32768, 4);
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.tag_vlan, None);
        assert_eq!(b.vlan(1), 300);
    }

    #[test]
    fn pvst_config_bpdu_with_padding() {
        let f = build_frame(
            Encapsulation::PvstPlus,
            Some(10),
            0,
            0x00,
            0x00,
            10,
            32768,
            4,
        );
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.pvid_tlv, Some(10));
    }

    #[test]
    fn vlan_from_sys_id_ext_as_last_resort() {
        let mut f = build_frame(Encapsulation::PvstPlus, None, 2, 0x02, 0x3C, 42, 32768, 4);
        // Corrupt the TLV type so it is not recognised.
        let n = f.iter().rposition(|&b| b == 2).unwrap();
        f[n] = 9;
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.pvid_tlv, None);
        assert_eq!(b.vlan(1), 42);
    }

    #[test]
    fn cisco_ieee_bpdu_for_vlan1_with_other_native_vlan() {
        // Untagged IEEE BPDU carries VLAN 1 (sys-id-ext 1) although native is 10.
        let f = build_frame(Encapsulation::Ieee, None, 2, 0x02, 0x3C, 1, 32768, 4);
        assert_eq!(parse_frame(&f).unwrap().vlan(10), 1);
    }

    #[test]
    fn unifi_rstp_bpdu() {
        // UniFi: plain 802.1w RSTP, untagged, priority 32768, no sys-id-ext.
        let f = build_frame(Encapsulation::Ieee, None, 2, 0x02, 0x3C, 0, 32768, 20000);
        assert_eq!(f[12..14], [0x00, 0x27]); // 802.3 length 39 = LLC 3 + RST BPDU 36
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.protocol_name(), "RSTP");
        assert_eq!(b.encapsulation, Encapsulation::Ieee);
        assert_eq!(b.vlan(1), 1);
        assert_eq!(b.config.as_ref().unwrap().root_id.priority, 32768);
        // Some implementations omit the version-1-length byte (35-byte RST BPDU).
        let mut short = f.clone();
        short[13] = 0x26;
        assert!(parse_frame(&short).is_ok());
    }

    #[test]
    fn parses_tcn() {
        let f = build_frame(Encapsulation::Ieee, None, 0, 0x80, 0, 1, 0, 0);
        let b = parse_frame(&f).unwrap();
        assert_eq!(b.bpdu_type, BpduType::Tcn);
        assert!(b.is_topology_change());
        assert!(b.config.is_none());
    }

    #[test]
    fn rejects_non_stp() {
        let mut f = build_frame(Encapsulation::Ieee, None, 0, 0x00, 0, 1, 32768, 0);
        f[14] = 0xFE; // DSAP
        assert_eq!(parse_frame(&f), Err(ParseError::NotStp));
        assert!(parse_frame(&f[..10]).is_err());
        let mut ip = f.clone();
        ip[12] = 0x08;
        ip[13] = 0x00;
        assert_eq!(parse_frame(&ip), Err(ParseError::NotLlc));
    }

    #[test]
    fn rejects_truncated_config() {
        let f = build_frame(Encapsulation::Ieee, None, 0, 0x00, 0, 1, 32768, 0);
        // Rewrite the 802.3 length so the BPDU appears short.
        let mut g = f.clone();
        g[12] = 0;
        g[13] = 20;
        assert_eq!(
            parse_frame(&g),
            Err(ParseError::Truncated("configuration bpdu"))
        );
    }
}
