# stp-monitor

A small Rust service that listens passively on a trunk port, decodes Spanning Tree BPDUs, and pushes the spanning tree state to **Zabbix 7.0** (6.0 LTS also supported). It alerts on **topology changes (TC/TCN)** and filters out the noisy ones, and also alerts on root bridge and path changes.

* **Cisco Rapid-PVST+ / PVST+** (`mode = "rapid-pvst"`): monitors the spanning tree of **every VLAN** on the trunk.
* **IEEE STP / RSTP / MSTP**, including **UniFi** (`mode = "rstp"`): monitors the single tree on the **native VLAN** (for MSTP, the CIST).
* Runs on Windows (Npcap) with a Hyper-V virtual NIC in trunk mode. It also runs on Linux (libpcap).
* Never transmits anything. The switch sees only a silent host, so BPDU Guard on the port is safe.

## How it works

```
switch trunk ──► Hyper-V external vSwitch ──► vNIC in trunk mode ──► Npcap ──► stp-monitor ──► Zabbix trapper (10051)
```

1. It captures frames sent to `01:80:C2:00:00:00` (IEEE) and `01:00:0C:CC:CC:CD` (Cisco PVST+).
2. It works out which VLAN each BPDU belongs to (Rapid-PVST mode), in this order:
   1. the PVST+ "originating VLAN" TLV,
   2. the 802.1Q tag,
   3. the bridge-ID system-ID extension,
   4. otherwise `native_vlan`.

   Windows NIC drivers often strip 802.1Q tags before Npcap sees the frame. The TLV still identifies the VLAN, so per-VLAN monitoring keeps working without the tags.
3. It keeps state per VLAN: root bridge, root path cost, hops to the root, the upstream switch's bridge and port ID, port role and state, timers, and counters.
4. It sends to Zabbix with the native sender protocol. No `zabbix_sender.exe` is needed.
   * A full report every `interval` seconds.
   * VLAN low-level discovery every `lld_interval` seconds, and right away when a new VLAN appears.
   * TC events and root changes right away. TC data is queued and retried if Zabbix can't be reached.

## Filtering noisy topology changes

In RSTP, a port that comes up as an **edge** port (portfast) doesn't cause a topology change. Many switches don't treat access ports as edge ports, so every laptop, dock, printer, phone or AP that connects or reboots sends a TC across the network. **UniFi networks are a typical example.** Alerting on every TC then means alerting on every device that connects.

From the trunk, stp-monitor can see whether the TC came with a **change to the tree** as advertised by the upstream switch: the root bridge, root path cost, hop count to the root (message age), or designated bridge or port. On that basis it classifies each TC:

| Class | Meaning | Alerted by default |
|---|---|---|
| **significant** | TC within `tc_correlation_window` (30 s) of a tree change. A link failed or recovered, or the root moved. A minor TC is upgraded to significant if a tree change follows within the window. | **Yes** (Warning) |
| **minor** | TC with no visible tree change. Typically an edge device connecting. | No. Set `{$STP.TC.ALERT.MINOR}=1` to alert. Still counts towards the **storm** alert. |
| **local link** | TC within `tc_local_grace` (20 s) of BPDUs (re)appearing on the trunk, i.e. caused by the monitor's own link or vNIC coming up. | Never. Counted separately. |

Minor TCs aren't thrown away:
* They count towards `stp.tc.recent`, which drives the **TC storm** trigger. A device flapping on a non-edge port causes constant MAC-table flushes and flooding, so that is worth an alert.
* Each event is still recorded in `stp.tc.event[vlan]` with its classification, for investigation.

**Limitation:** stp-monitor sees the tree only from this trunk. A real link failure in a part of the network that doesn't change this switch's path to the root looks the same as an edge device connecting, so it is classified as minor. If you need those as well, set `{$STP.TC.ALERT.MINOR}=1`, perhaps per VLAN with a context macro such as `{$STP.TC.ALERT.MINOR:"10"}=1`.

Tune the storm threshold per VLAN with `{$STP.TC.STORM:"<vlan>"}`.

The BPDU shows which switch *relayed* the TC, not the switch where it started. To find the source, check the switches. On UniFi, look at the switch's port events. On Cisco, use `show spanning-tree detail | include ieee|occurr|from|is exec`.

## UniFi networks

UniFi switches run standard **802.1w RSTP**: one spanning tree for all VLANs, with BPDUs sent untagged. (Some newer models also support MSTP.) Configure stp-monitor with:

```toml
mode = "rstp"        # one tree, reported under native_vlan
native_vlan = 1      # the port's Native VLAN (UniFi "Default" network = VLAN 1)
```

On the UniFi switch port that connects to the Hyper-V host, the settings are roughly as follows. Menu names differ between UniFi Network versions.

* **Native VLAN / Network:** `Default`, or the VLAN you set as `native_vlan`.
* **Tagged VLAN Management:** `Allow All`. stp-monitor only needs BPDUs, but a full trunk is what you'd normally give a Hyper-V host.
* **Spanning Tree Protocol:** enabled on the port.
* On the switch (device settings), set **Spanning Tree** to **RSTP**.

Things to watch for on UniFi, which the template has alerts for:

* **Root bridge placement.** Every UniFi switch defaults to priority 32768, so the root is whichever switch (or meshing AP) has the lowest MAC address. Give the core switch a lower priority, such as 4096. Then set `{$STP.ROOT.MAC.MATCHES}` to its MAC, e.g. `^24:5a:4c:00:00:01$`, so that you get an alert if the root moves.
* **Network diameter.** RSTP discards BPDUs once the hop count reaches max age (20 by default). Long daisy chains of Flex or Lite switches can get close to that. The "network diameter close to max age" trigger fires when you're within `{$STP.HOPS.MARGIN}` hops of the limit.
* **Edge-device TCs.** These are classified as minor (see above). If your firmware has an edge/portfast option for access ports, turning it on stops these TCs at the source.

## Hyper-V setup

You need an **external** vSwitch on the physical NIC that connects to the switch trunk. You can run the monitor in a small VM (recommended) or on the Hyper-V host itself.

**Option A: dedicated VM**

```powershell
Add-VMNetworkAdapter -VMName STPMON -SwitchName "External" -Name "STP-Trunk"
Set-VMNetworkAdapterVlan -VMName STPMON -VMNetworkAdapterName "STP-Trunk" -Trunk -AllowedVlanIdList "1-4094" -NativeVlanId 1
```

**Option B: on the host (management OS vNIC)**

```powershell
Add-VMNetworkAdapter -ManagementOS -Name "STP-Trunk" -SwitchName "External"
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName "STP-Trunk" -Trunk -AllowedVlanIdList "1-4094" -NativeVlanId 1
```

`-NativeVlanId` must match the switch port's native VLAN. That is what lets the untagged RSTP BPDUs (UniFi, and Cisco's IEEE BPDU) reach the vNIC. Inside the OS that owns the trunk vNIC, you can unbind IPv4/IPv6 from that adapter. Npcap doesn't need an IP address.

Upstream switch port, Cisco example:

```
interface GigabitEthernet1/0/10
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 1,10,20,30
 ! Do NOT configure "spanning-tree bpdufilter enable" – it stops BPDUs being sent.
```

**Check that BPDUs arrive** before you set up Zabbix:

```powershell
.\stp-monitor.exe --dry-run -v
```

You should see `discovered spanning tree on VLAN …` within a few seconds. The first TC you see may be classified as "local link": your vNIC coming up triggers it. If nothing appears, capture on the same adapter with Wireshark using the filter `stp`. If Wireshark doesn't see BPDUs either, the problem is in the vSwitch, VLAN or switch-port configuration.

## Download

GitHub Actions builds the Windows exe on every push. It is packaged in a zip together with the example config and the Zabbix templates.

* **Release builds:** pushing a `v*` tag (e.g. `v0.2.0`) publishes a GitHub Release with `stp-monitor-windows-x64.zip` attached.
* **Other builds:** download the `stp-monitor-windows-x64` artifact from the workflow run.

The machine that runs the exe still needs the [Npcap](https://npcap.com/#download) runtime (see below).

## Building on Windows

1. Install Rust with [rustup](https://rustup.rs) (the default MSVC toolchain).
2. Install the [Npcap](https://npcap.com/#download) runtime. Tick **"Install Npcap in WinPcap API-compatible Mode"**. Without it, add `C:\Windows\System32\Npcap` to `PATH`, or the program fails to start because `wpcap.dll` is missing.
3. Download the **Npcap SDK** from the same page and unzip it, for example to `C:\npcap-sdk`.
4. Build:

```powershell
$env:LIBPCAP_LIBDIR = "C:\npcap-sdk\Lib\x64"
cargo build --release
# -> target\release\stp-monitor.exe
```

On Linux, install `libpcap-dev` and run `cargo build --release`.

## Configuration

Copy `stp-monitor.example.toml` to `stp-monitor.toml` and edit it. To find the interface:

```powershell
.\stp-monitor.exe --list-interfaces
Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid   # map friendly name -> GUID
```

`interface` can be any of:
* the full Npcap name (`\Device\NPF_{GUID}`),
* just the GUID,
* any unique part of the adapter description.

| Setting | Default | Meaning |
|---|---|---|
| `interface` | (required) | Capture interface. |
| `mode` | `pvst` | `pvst` / `rapid-pvst` = per-VLAN (Cisco). `stp` / `rstp` / `mstp` = one tree on the native VLAN (UniFi, IEEE); PVST+ BPDUs are ignored. |
| `native_vlan` | `1` | VLAN that untagged IEEE BPDUs are reported under. |
| `vlans` | all | Optional allow list. |
| `tc_window` | `300` | Seconds a TC counts towards the `*.recent` items. This is how long a TC alert stays open. |
| `tc_correlation_window` | `30` | Seconds between a TC and a tree change for the TC to count as significant. |
| `tc_local_grace` | `20` | Seconds after BPDUs (re)appear during which TCs are blamed on the monitor's own link. |
| `zabbix.server` | (required) | Server or proxy. A list separated by `,` or `;`, each `host[:port]`, for **Zabbix 7.0 HA** clusters. |
| `zabbix.port` | `10051` | Default trapper port. |
| `zabbix.host` | (required) | Host name in Zabbix. |
| `zabbix.interval` | `30` | Seconds between full reports. |
| `zabbix.lld_interval` | `300` | Seconds between VLAN discovery refreshes. |

## Running

```powershell
.\stp-monitor.exe -c C:\stp-monitor\stp-monitor.toml
```

Useful options:
* `--dry-run` prints the values instead of sending them.
* `--pcap-file capture.pcap` replays a saved capture (for testing).
* `-v` turns on debug logging.

To run it at boot as a background service with no extra software, use a scheduled task as SYSTEM:

```powershell
$a = New-ScheduledTaskAction -Execute "C:\stp-monitor\stp-monitor.exe" -Argument "-c C:\stp-monitor\stp-monitor.toml" -WorkingDirectory "C:\stp-monitor"
$t = New-ScheduledTaskTrigger -AtStartup
$s = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName "stp-monitor" -Action $a -Trigger $t -Settings $s -User SYSTEM -RunLevel Highest
Start-ScheduledTask -TaskName "stp-monitor"
```

You can also wrap it as a real Windows service with [NSSM](https://nssm.cc), which also captures the log output to a file:

```powershell
nssm install stp-monitor C:\stp-monitor\stp-monitor.exe -c C:\stp-monitor\stp-monitor.toml
```

## Zabbix setup (7.0)

1. **Data collection → Templates → Import** `zabbix/stp_monitor_template_7.0.yaml`. For Zabbix 6.0 LTS, use `stp_monitor_template_6.0.yaml`.
2. **Data collection → Hosts → Create host**:
   * **Host name** must equal `zabbix.host`.
   * It needs no interface.
   * Link the template **STP Monitor**.
   * If the host is monitored by a proxy or proxy group, set that on the host and point `zabbix.server` at the proxies.
3. Start stp-monitor. VLANs show up through discovery within a minute or two. Until discovery has created a VLAN's items, Zabbix reports some values as "failed"; this is expected for that first minute.

**Zabbix 7.0 specifics**

* **HA cluster:** list every node in `zabbix.server`. Only the active node accepts trapper data, so stp-monitor tries the nodes in order and sticks with the one that works.
* **Proxy groups:** if a proxy replies with a redirect to the proxy that owns the host, stp-monitor resends there and keeps using that proxy until it fails or the redirect is reset.
* To regenerate the templates after editing items or triggers, run `python3 zabbix/gen_template.py`. UUIDs are stable, so re-importing updates the template in place.

### Items

| Key | Description |
|---|---|
| `stp.monitor.heartbeat`, `.uptime`, `.bpdu.total`, `.bpdu.age`, `.vlans` | Health of the monitor itself. |
| `stp.root.id[vlan]`, `.priority`, `.mac`, `stp.root.cost[vlan]` | Root bridge and path cost. |
| `stp.bridge.id[vlan]`, `stp.port.id/role/state[vlan]` | Upstream switch bridge ID and its port. |
| `stp.protocol[vlan]` | e.g. `RSTP (IEEE)` (UniFi), `RSTP (PVST+)` (Cisco), `MSTP (IEEE)`. |
| `stp.timer.hello/maxage/fwddelay[vlan]`, `stp.message.age[vlan]` | Timers from the BPDU. Message age ≈ hops to the root. |
| `stp.bpdu.count[vlan]`, `stp.bpdu.age[vlan]` | BPDU counters, and seconds since the last BPDU. |
| `stp.tc.count[vlan]`, `stp.tc.recent[vlan]` | All TCs except local-link ones, since start and within `tc_window`. |
| `stp.tc.significant.count[vlan]`, `stp.tc.significant.recent[vlan]` | Significant TCs. |
| `stp.tc.local.count[vlan]` | TCs blamed on the monitor's own link. |
| `stp.tc.last[vlan]`, `stp.tc.active[vlan]` | Time of the last TC, and whether a TC is in progress. |
| `stp.tc.event[vlan]` | Text for each TC: `[significant: root path cost 20000 -> 40000, hops to root 1 -> 2] …`, `[minor: …] …` or `[local link: …] …`. |
| `stp.tree.changes[vlan]`, `stp.root.changes[vlan]`, `stp.tcn.count[vlan]` | Counts of tree changes, root changes and legacy TCN BPDUs. |

### Triggers

| Trigger | Severity | Condition |
|---|---|---|
| VLAN {#VLAN}: STP topology change with path change | Warning | Significant TC within `tc_window`. Depends on the storm trigger. |
| VLAN {#VLAN}: STP topology change (minor) | Info | Any TC within `tc_window`, **only if `{$STP.TC.ALERT.MINOR}=1`** (default 0). |
| VLAN {#VLAN}: STP topology change storm | High | `stp.tc.recent >= {$STP.TC.STORM}` (default 5), minor TCs included. |
| VLAN {#VLAN}: STP root bridge changed | High | `change(stp.root.id)`. Closed manually. |
| VLAN {#VLAN}: STP root bridge is not the expected switch | Average | The root MAC doesn't match `{$STP.ROOT.MAC.MATCHES}` (default `.*`, i.e. off). |
| VLAN {#VLAN}: STP root path cost changed | Info | `change(stp.root.cost)`. Closed manually. |
| VLAN {#VLAN}: STP network diameter close to max age | Warning | `maxage - message.age <= {$STP.HOPS.MARGIN}` (default 3). |
| VLAN {#VLAN}: No BPDUs received | Average | `stp.bpdu.age > {$STP.BPDU.TIMEOUT}` (default 60 s). |
| No BPDUs received on the trunk port | Average | No BPDUs on any VLAN. |
| STP monitor is not reporting | High | `nodata(heartbeat, {$STP.MONITOR.NODATA})` (default 3 m). |

## Development

```bash
cargo test                          # parser, TC classification (incl. UniFi scenarios), Zabbix protocol/failover/redirect
cargo run -- --dry-run --pcap-file some.pcap -c stp-monitor.example.toml
python3 zabbix/gen_template.py      # regenerate Zabbix templates
```

## Limitations

* MSTP: only the CIST is reported. MSTI records aren't decoded.
* TC classification only sees the tree from this trunk (see above).
* No TLS/PSK to Zabbix. Use plain trapper; a local Zabbix proxy can handle encryption if you need it.
