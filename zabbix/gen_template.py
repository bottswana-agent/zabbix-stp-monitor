#!/usr/bin/env python3
"""Generate the Zabbix template for stp-monitor.

    python3 zabbix/gen_template.py

writes stp_monitor_template_7.0.yaml (Zabbix 7.0+) and
stp_monitor_template_6.0.yaml (Zabbix 6.0 LTS) next to this script.
UUIDs are derived from item keys / trigger names so regenerating gives the
same UUIDs and re-importing updates the existing template in place.
"""
import hashlib
import os
import uuid

T = 'STP Monitor'
V = '{#VLAN}'


def uid(*parts):
    # Zabbix requires UUIDv4 formatted values; derive them deterministically.
    return uuid.UUID(bytes=hashlib.md5('|'.join(('stp-monitor',) + parts).encode()).digest(), version=4).hex


def q(s):
    return "'" + s.replace("'", "''") + "'"


def K(key):
    return f'/{T}/{key}'


def P(k):
    return f'stp.{k}[{V}]'


# --------------------------------------------------------------------------
# Template-level (host) items
# --------------------------------------------------------------------------
NODATA = f"nodata({K('stp.monitor.heartbeat')},{{$STP.MONITOR.NODATA}})=1"
host_items = [
    dict(name='STP monitor: heartbeat', key='stp.monitor.heartbeat', units='unixtime', history='7d',
         desc='Unix time of the last periodic report from stp-monitor.',
         triggers=[dict(expr=NODATA, name='STP monitor is not reporting', prio='HIGH',
                        desc='No data received from stp-monitor. The service may be stopped or cannot reach Zabbix.')]),
    dict(name='STP monitor: uptime', key='stp.monitor.uptime', units='uptime', history='7d',
         desc='Seconds since stp-monitor started.'),
    dict(name='STP monitor: BPDUs received', key='stp.monitor.bpdu.total',
         desc='Total BPDUs received since start (all VLANs).'),
    dict(name='STP monitor: time since last BPDU', key='stp.monitor.bpdu.age', units='s',
         desc='Seconds since any BPDU was received on the trunk.',
         triggers=[dict(expr=f"last({K('stp.monitor.bpdu.age')})>{{$STP.BPDU.TIMEOUT}}",
                        name='No BPDUs received on the trunk port', prio='AVERAGE',
                        opdata='Last BPDU {ITEM.LASTVALUE1} ago',
                        desc='No spanning tree BPDUs were seen on any VLAN. Check the trunk / vSwitch configuration '
                             'and that spanning tree is enabled on the upstream switch port.',
                        deps=[('STP monitor is not reporting', NODATA)])]),
    dict(name='STP monitor: VLANs seen', key='stp.monitor.vlans',
         desc='Number of VLANs (spanning tree instances) seen.'),
]

# --------------------------------------------------------------------------
# Per-VLAN item prototypes
# --------------------------------------------------------------------------
STORM_NAME = f'VLAN {V}: STP topology change storm'
STORM_EXPR = f"last({K(P('tc.recent'))})>={{$STP.TC.STORM}}"
SIG_NAME = f'VLAN {V}: STP topology change with path change'
SIG_EXPR = f"last({K(P('tc.significant.recent'))})>0"

proto = [
    dict(name=f'VLAN {V}: STP protocol', key=P('protocol'), vt='CHAR',
         desc='Protocol and encapsulation of the BPDUs, e.g. "RSTP (IEEE)" (UniFi) or "RSTP (PVST+)" (Cisco).'),
    dict(name=f'VLAN {V}: Root bridge ID', key=P('root.id'), vt='CHAR',
         desc='Root bridge ID as priority/sys-id-ext/MAC.',
         triggers=[dict(expr=f"change({K(P('root.id'))})=1", name=f'VLAN {V}: STP root bridge changed',
                        prio='HIGH', manual=True, opdata='New root: {ITEM.LASTVALUE1}', scope='notice',
                        desc='The root bridge of this spanning tree changed. This causes a reconvergence and flushes '
                             'MAC tables. Close the problem manually once investigated.')]),
    dict(name=f'VLAN {V}: Root bridge priority', key=P('root.priority'),
         desc='Root bridge priority including the system ID extension.'),
    dict(name=f'VLAN {V}: Root bridge MAC', key=P('root.mac'), vt='CHAR',
         desc='Root bridge MAC address (lower case, colon separated).',
         triggers=[dict(expr=f"find({K(P('root.mac'))},,\"regexp\",\"{{$STP.ROOT.MAC.MATCHES}}\")=0",
                        name=f'VLAN {V}: STP root bridge is not the expected switch', prio='AVERAGE',
                        opdata='Root: {ITEM.LASTVALUE1}', scope='notice',
                        desc='The root bridge MAC does not match {$STP.ROOT.MAC.MATCHES}. With default priorities '
                             '(common on UniFi) the switch with the lowest MAC becomes root, which may be an access '
                             'switch or even an AP. Set a low bridge priority on the core switch.')]),
    dict(name=f'VLAN {V}: Root path cost', key=P('root.cost'),
         desc='Root path cost advertised by the upstream switch.',
         triggers=[dict(expr=f"change({K(P('root.cost'))})<>0", name=f'VLAN {V}: STP root path cost changed',
                        prio='INFO', manual=True, opdata='Cost: {ITEM.LASTVALUE1}', scope='notice',
                        desc='The upstream switch now reaches the root over a different path (a link failed or '
                             'recovered somewhere in the network).')]),
    dict(name=f'VLAN {V}: Designated bridge ID', key=P('bridge.id'), vt='CHAR',
         desc='Bridge ID of the switch sending the BPDUs (the switch at the other end of the trunk).'),
    dict(name=f'VLAN {V}: Designated port ID', key=P('port.id'), vt='CHAR',
         desc='Port ID (priority.number) of the upstream switch port.'),
    dict(name=f'VLAN {V}: Designated port role', key=P('port.role'), vt='CHAR',
         desc='Role of the upstream switch port (RSTP only).'),
    dict(name=f'VLAN {V}: Designated port state', key=P('port.state'), vt='CHAR',
         desc='State of the upstream switch port (RSTP only).'),
    dict(name=f'VLAN {V}: Hello time', key=P('timer.hello'), vt='FLOAT', units='s',
         desc='Hello time advertised by the root.'),
    dict(name=f'VLAN {V}: Max age', key=P('timer.maxage'), vt='FLOAT', units='s',
         desc='Max age advertised by the root. Also the maximum number of bridge hops.'),
    dict(name=f'VLAN {V}: Forward delay', key=P('timer.fwddelay'), vt='FLOAT', units='s',
         desc='Forward delay advertised by the root.'),
    dict(name=f'VLAN {V}: Message age (hops to root)', key=P('message.age'), vt='FLOAT', units='s',
         desc='Message age of the last BPDU; incremented by one per bridge, so roughly the hop count to the root.'),
    dict(name=f'VLAN {V}: BPDUs received', key=P('bpdu.count'), desc='BPDUs received for this VLAN since start.'),
    dict(name=f'VLAN {V}: Time since last BPDU', key=P('bpdu.age'), units='s',
         desc='Seconds since a BPDU was received for this VLAN.',
         triggers=[dict(expr=f"last({K(P('bpdu.age'))})>{{$STP.BPDU.TIMEOUT}}", name=f'VLAN {V}: No BPDUs received',
                        prio='AVERAGE', opdata='Last BPDU {ITEM.LASTVALUE1} ago',
                        desc='BPDUs for this VLAN stopped arriving. The VLAN may have been removed from the trunk, '
                             'or spanning tree disabled for it.')]),
    dict(name=f'VLAN {V}: TCN BPDUs received', key=P('tcn.count'),
         desc='Legacy 802.1D TCN BPDUs received since start.'),
    dict(name=f'VLAN {V}: Root bridge changes', key=P('root.changes'), desc='Root bridge changes seen since start.'),
    dict(name=f'VLAN {V}: Tree changes', key=P('tree.changes'),
         desc='Changes in the advertised tree (root, root path cost, hops, designated bridge/port) since start.'),
    dict(name=f'VLAN {V}: Topology changes', key=P('tc.count'),
         desc='Topology change events since start, excluding ones caused by the monitor\'s own link.'),
    dict(name=f'VLAN {V}: Topology changes (recent)', key=P('tc.recent'),
         desc='Topology changes (significant + minor) within tc_window seconds (default 300).',
         triggers=[
             dict(expr=STORM_EXPR, name=STORM_NAME, prio='HIGH', opdata='{ITEM.LASTVALUE1} TC(s) in window',
                  scope='performance',
                  desc='Repeated topology changes: usually a flapping link, or a device repeatedly connecting on a '
                       'port that is not an edge/portfast port. Tune with context macro {$STP.TC.STORM:"<vlan>"}.'),
             dict(expr=f"last({K(P('tc.recent'))})>0 and {{$STP.TC.ALERT.MINOR}}=1",
                  name=f'VLAN {V}: STP topology change (minor)', prio='INFO',
                  opdata='{ITEM.LASTVALUE1} TC(s) in window', scope='notice',
                  desc='A topology change without any visible change in the tree, typically a client device '
                       'connecting. Disabled unless {$STP.TC.ALERT.MINOR} is 1.',
                  deps=[(STORM_NAME, STORM_EXPR), (SIG_NAME, SIG_EXPR)]),
         ]),
    dict(name=f'VLAN {V}: Topology changes with path change (recent)', key=P('tc.significant.recent'),
         desc='Significant topology changes within tc_window: the TC coincided with a change in root bridge, '
              'root path cost, hops to root or designated bridge/port.',
         triggers=[dict(expr=SIG_EXPR, name=SIG_NAME, prio='WARNING', opdata='{ITEM.LASTVALUE1} TC(s) in window',
                        scope='notice',
                        desc='The spanning tree changed shape: a link failed or recovered, or the root moved. See '
                             '"Last topology change details" for what changed.',
                        deps=[(STORM_NAME, STORM_EXPR)])]),
    dict(name=f'VLAN {V}: Topology changes with path change', key=P('tc.significant.count'),
         desc='Significant topology changes since start.'),
    dict(name=f'VLAN {V}: Topology changes from own link', key=P('tc.local.count'),
         desc='TCs seen right after BPDUs (re)appeared on the trunk, attributed to the monitor\'s own link. Not alerted.'),
    dict(name=f'VLAN {V}: Last topology change time', key=P('tc.last'), units='unixtime',
         desc='Time of the last topology change (0 = none since start).'),
    dict(name=f'VLAN {V}: Topology change in progress', key=P('tc.active'),
         desc='1 while TC indications are still arriving.'),
    dict(name=f'VLAN {V}: Last topology change details', key=P('tc.event'), vt='TEXT', history='90d',
         desc='One value per TC event, prefixed [significant: ...], [minor: ...] or [local link: ...], with the '
              'sender bridge, port, root and flags.'),
]

# Triggers that reference more than one item live on the discovery rule.
rule_triggers = [
    dict(expr=f"last({K(P('timer.maxage'))})-last({K(P('message.age'))})<={{$STP.HOPS.MARGIN}}",
         name=f'VLAN {V}: STP network diameter close to max age', prio='WARNING',
         opdata='Hops: {ITEM.LASTVALUE2} / max age {ITEM.LASTVALUE1}', scope='capacity',
         desc='BPDUs are discarded once message age reaches max age. Long daisy chains of switches (common with '
              'UniFi Flex/USW-Lite access switches) can hit this and cause loops or instability. Flatten the topology '
              'or raise max age on the root.'),
]

macros = [
    ('{$STP.BPDU.TIMEOUT}', '60', 'Seconds without BPDUs before alerting.'),
    ('{$STP.MONITOR.NODATA}', '3m', 'How long stp-monitor may be silent before alerting.'),
    ('{$STP.TC.STORM}', '5', 'Topology changes (significant + minor) within tc_window that count as a storm.'),
    ('{$STP.TC.ALERT.MINOR}', '0',
     'Set to 1 to also alert on minor TCs (no tree change, e.g. edge devices connecting).'),
    ('{$STP.ROOT.MAC.MATCHES}', '.*',
     'Regular expression the root bridge MAC must match, e.g. ^(00:11:22:33:44:55|00:11:22:33:44:66)$.'),
    ('{$STP.HOPS.MARGIN}', '3', 'Alert when the hop count to the root is within this many of max age.'),
]


# --------------------------------------------------------------------------
def render(version):
    L = []

    def w(ind, s):
        L.append('  ' * ind + s)

    def trig(ind, t):
        w(ind, f"- uuid: {uid('trigger', t['name'])}")
        w(ind + 1, f"expression: {q(t['expr'])}")
        w(ind + 1, f"name: {q(t['name'])}")
        if 'opdata' in t:
            w(ind + 1, f"opdata: {q(t['opdata'])}")
        w(ind + 1, f"priority: {t['prio']}")
        if 'desc' in t:
            w(ind + 1, f"description: {q(t['desc'])}")
        if t.get('manual'):
            w(ind + 1, 'recovery_mode: NONE')
            w(ind + 1, "manual_close: 'YES'")
        if t.get('deps'):
            w(ind + 1, 'dependencies:')
            for name, expr in t['deps']:
                w(ind + 2, f'- name: {q(name)}')
                w(ind + 3, f'expression: {q(expr)}')
        w(ind + 1, 'tags:')
        w(ind + 2, '- tag: scope')
        w(ind + 3, f"value: {t.get('scope', 'availability')}")

    def item(ind, it, prototype):
        w(ind, f"- uuid: {uid('item', it['key'])}")
        w(ind + 1, f"name: {q(it['name'])}")
        w(ind + 1, 'type: TRAP')
        w(ind + 1, f"key: {q(it['key'])}")
        w(ind + 1, f"history: {it.get('history', '30d')}")
        vt = it.get('vt', 'UNSIGNED')
        if vt in ('CHAR', 'TEXT'):
            w(ind + 1, "trends: '0'")
        if vt != 'UNSIGNED':
            w(ind + 1, f'value_type: {vt}')
        if 'units' in it:
            w(ind + 1, f"units: {it['units']}")
        w(ind + 1, f"description: {q(it['desc'])}")
        if vt == 'CHAR':
            w(ind + 1, 'preprocessing:')
            w(ind + 2, '- type: DISCARD_UNCHANGED_HEARTBEAT')
            w(ind + 3, 'parameters:')
            w(ind + 4, '- 1h')
        w(ind + 1, 'tags:')
        w(ind + 2, '- tag: component')
        w(ind + 3, 'value: stp')
        if prototype:
            w(ind + 2, '- tag: vlan')
            w(ind + 3, f"value: '{V}'")
        if it.get('triggers'):
            w(ind + 1, 'trigger_prototypes:' if prototype else 'triggers:')
            for t in it['triggers']:
                trig(ind + 2, t)

    w(0, 'zabbix_export:')
    w(1, f"version: '{version}'")
    # Zabbix 6.2 split host groups and template groups.
    w(1, 'template_groups:' if version >= '6.2' else 'groups:')
    w(2, f"- uuid: {uid('group')}")
    w(3, 'name: Templates/Network devices')
    w(1, 'templates:')
    w(2, f"- uuid: {uid('template')}")
    w(3, f'template: {q(T)}')
    w(3, f'name: {q(T)}')
    w(3, "description: 'Spanning tree data pushed by stp-monitor (Zabbix trapper). Link to the host named in "
         "stp-monitor.toml [zabbix] host. Works with Cisco Rapid-PVST+/PVST+ (per VLAN) and IEEE STP/RSTP/MSTP "
         "networks such as UniFi (native VLAN).'")
    if version >= '6.4':
        w(3, 'vendor:')
        w(4, 'name: stp-monitor')
        w(4, "version: '0.2'")
    w(3, 'groups:')
    w(4, '- name: Templates/Network devices')
    w(3, 'items:')
    for it in host_items:
        item(4, it, False)
    w(3, 'discovery_rules:')
    w(4, f"- uuid: {uid('lld')}")
    w(5, "name: 'STP VLAN discovery'")
    w(5, 'type: TRAP')
    w(5, 'key: stp.vlan.discovery')
    w(5, 'lifetime: 7d')
    w(5, "description: 'VLANs (spanning tree instances) seen on the trunk; sent by stp-monitor.'")
    w(5, 'item_prototypes:')
    for it in proto:
        item(6, it, True)
    w(5, 'trigger_prototypes:')
    for t in rule_triggers:
        trig(6, t)
    w(3, 'tags:')
    w(4, '- tag: class')
    w(5, 'value: network')
    w(3, 'macros:')
    for m, v, d in macros:
        w(4, f'- macro: {q(m)}')
        w(5, f'value: {q(v)}')
        w(5, f'description: {q(d)}')
    return '\n'.join(L) + '\n'


if __name__ == '__main__':
    here = os.path.dirname(os.path.abspath(__file__))
    for ver in ('7.0', '6.0'):
        path = os.path.join(here, f'stp_monitor_template_{ver}.yaml')
        with open(path, 'w') as f:
            f.write(render(ver))
        print('wrote', path)
