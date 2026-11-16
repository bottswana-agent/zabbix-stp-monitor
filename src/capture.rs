//! Packet capture via libpcap / Npcap.

use std::path::Path;
use std::sync::mpsc::Sender;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use pcap::{Activated, Capture, Device, Linktype};

use crate::bpdu::{self, Bpdu};

pub enum CaptureMsg {
    Bpdu(Bpdu, i64),
    /// The capture ended (end of file, or a fatal error on a live interface).
    End(Result<()>),
}

pub fn list_interfaces() -> Result<()> {
    let devices = Device::list().context("listing capture devices (is Npcap installed?)")?;
    if devices.is_empty() {
        println!("No capture interfaces found. On Windows, make sure Npcap is installed.");
    }
    for d in devices {
        println!("{}", d.name);
        if let Some(desc) = &d.desc {
            println!("    description: {desc}");
        }
        for a in &d.addresses {
            println!("    address:     {}", a.addr);
        }
    }
    Ok(())
}

/// Find a device by exact name, by a fragment of its name (e.g. the GUID on
/// Windows), or by a fragment of its description.
pub fn find_device(wanted: &str) -> Result<Device> {
    let devices = Device::list().context("listing capture devices (is Npcap installed?)")?;
    if let Some(d) = devices.iter().find(|d| d.name == wanted) {
        return Ok(d.clone());
    }
    let w = wanted.to_lowercase();
    let matches: Vec<&Device> = devices
        .iter()
        .filter(|d| {
            d.name.to_lowercase().contains(&w)
                || d.desc
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(&w))
        })
        .collect();
    match matches.as_slice() {
        [d] => Ok((*d).clone()),
        [] => bail!("no capture interface matches {wanted:?}; run with --list-interfaces"),
        many => {
            let names: Vec<String> = many
                .iter()
                .map(|d| format!("{} ({})", d.name, d.desc.as_deref().unwrap_or("-")))
                .collect();
            Err(anyhow!(
                "{wanted:?} matches several interfaces, be more specific:\n  {}",
                names.join("\n  ")
            ))
        }
    }
}

pub fn run_live(interface: &str, promiscuous: bool, tx: Sender<CaptureMsg>) {
    let result = (|| -> Result<()> {
        let device = find_device(interface)?;
        info!(
            "capturing on {} ({})",
            device.name,
            device.desc.as_deref().unwrap_or("no description")
        );
        let mut cap = Capture::from_device(device)?
            .promisc(promiscuous)
            .snaplen(512)
            .timeout(1000)
            .immediate_mode(true)
            .open()
            .context("opening capture interface (are you running as Administrator?)")?;
        capture_loop(&mut cap, &tx)
    })();
    let _ = tx.send(CaptureMsg::End(result));
}

pub fn run_file(path: &Path, tx: Sender<CaptureMsg>) {
    let result = (|| -> Result<()> {
        let mut cap =
            Capture::from_file(path).with_context(|| format!("opening {}", path.display()))?;
        capture_loop(&mut cap, &tx)
    })();
    let _ = tx.send(CaptureMsg::End(result));
}

fn capture_loop<T: Activated + ?Sized>(
    cap: &mut Capture<T>,
    tx: &Sender<CaptureMsg>,
) -> Result<()> {
    if cap.get_datalink() != Linktype::ETHERNET {
        bail!(
            "interface link type is {:?}, expected Ethernet",
            cap.get_datalink()
        );
    }
    cap.filter(bpdu::BPF_FILTER, true)
        .context("setting BPF filter")?;
    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => return Ok(()),
            Err(e) => return Err(e).context("reading packet"),
        };
        #[allow(clippy::unnecessary_cast)] // tv_sec is i32 on Windows
        let ts = packet.header.ts.tv_sec as i64;
        match bpdu::parse_frame(packet.data) {
            Ok(b) => {
                debug!("bpdu: {b:?}");
                if tx.send(CaptureMsg::Bpdu(b, ts)).is_err() {
                    return Ok(()); // receiver gone, shutting down
                }
            }
            Err(e) => warn!("ignoring frame from {}: {e}", src_mac(packet.data)),
        }
    }
}

fn src_mac(frame: &[u8]) -> String {
    frame
        .get(6..12)
        .map(|m| bpdu::format_mac(m.try_into().unwrap()))
        .unwrap_or_else(|| "?".into())
}
