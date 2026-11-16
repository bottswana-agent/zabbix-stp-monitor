//! stp-monitor: passively watches Spanning Tree BPDUs arriving on a trunk port
//! and pushes the spanning tree state and topology-change alerts to Zabbix.

mod bpdu;
mod capture;
mod config;
mod reporter;
mod state;
mod zabbix;

use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info};

use capture::CaptureMsg;
use config::Config;
use reporter::{Output, Reporter};
use state::{Monitor, TcPolicy};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "stp-monitor.toml")]
    config: PathBuf,

    /// List capture interfaces and exit.
    #[arg(long)]
    list_interfaces: bool,

    /// Read frames from a pcap file instead of the live interface (for testing).
    #[arg(long, value_name = "FILE")]
    pcap_file: Option<PathBuf>,

    /// Print the values that would be sent instead of sending them to Zabbix.
    #[arg(long)]
    dry_run: bool,

    /// Increase log verbosity (-v debug, -vv trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn main() {
    let args = Args::parse();
    let level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    if let Err(e) = run(args) {
        error!("{e:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    if args.list_interfaces {
        return capture::list_interfaces();
    }

    let cfg = Config::load(&args.config)?;
    info!(
        "mode {:?}, native VLAN {}, reporting to Zabbix {} (port {}) as host {:?}{}",
        cfg.mode,
        cfg.native_vlan,
        cfg.zabbix.server,
        cfg.zabbix.port,
        cfg.zabbix.host,
        if args.dry_run { " (dry run)" } else { "" }
    );

    let output = if args.dry_run {
        Output::Stdout
    } else {
        let sender = zabbix::Sender::new(
            &cfg.zabbix.server,
            cfg.zabbix.port,
            &cfg.zabbix.host,
            cfg.zabbix.timeout,
        );
        info!(
            "Zabbix endpoints (in failover order): {}",
            sender.endpoints()
        );
        Output::Zabbix(sender)
    };
    let policy = TcPolicy {
        correlation_window: cfg.tc_correlation_window as i64,
        local_grace: cfg.tc_local_grace as i64,
    };
    let monitor = Monitor::new(cfg.mode, cfg.native_vlan, cfg.vlans.clone(), policy);
    let replay = args.pcap_file.is_some();

    // In replay mode the clock follows the packet timestamps.
    let mut now = if replay { 0 } else { unix_now() };
    let mut reporter = Reporter::new(output, monitor, cfg.tc_window, now);

    let (tx, rx) = mpsc::channel();
    let _capture = match args.pcap_file.clone() {
        Some(path) => std::thread::spawn(move || capture::run_file(&path, tx)),
        None => {
            let (iface, promisc) = (cfg.interface.clone(), cfg.promiscuous);
            std::thread::spawn(move || capture::run_live(&iface, promisc, tx))
        }
    };

    let interval = Duration::from_secs(cfg.zabbix.interval);
    let lld_interval = Duration::from_secs(cfg.zabbix.lld_interval);
    let mut next_report = Instant::now() + interval;
    let mut next_lld = Instant::now() + lld_interval;

    loop {
        let timeout = next_report
            .min(next_lld)
            .saturating_duration_since(Instant::now());
        match rx.recv_timeout(timeout) {
            Ok(CaptureMsg::Bpdu(bpdu, ts)) => {
                now = if replay { ts } else { unix_now() };
                if reporter.monitor.total_bpdus == 0 && replay {
                    // start the uptime clock at the first packet of the file
                    reporter.set_started(ts);
                }
                let events = reporter.monitor.process(&bpdu, now);
                reporter.handle_events(events, now);
            }
            Ok(CaptureMsg::End(result)) => {
                // Final report, then exit (end of pcap file or capture error).
                reporter.send_lld(now);
                reporter.report(now);
                return result;
            }
            Err(RecvTimeoutError::Timeout) => {
                if !replay {
                    now = unix_now();
                }
                if Instant::now() >= next_lld {
                    reporter.send_lld(now);
                    next_lld = Instant::now() + lld_interval;
                }
                if Instant::now() >= next_report {
                    reporter.report(now);
                    next_report = Instant::now() + interval;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(anyhow::anyhow!("capture thread exited unexpectedly"))
                    .context("capture");
            }
        }
    }
}
