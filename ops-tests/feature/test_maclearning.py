# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for simple static routes between nodes.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division
import re
import time
from pytest import mark

WORKSTATION1_IP = "10.1.1.1"
WORKSTATION2_IP = "10.1.1.2"
WORKSTATION_MASK = "24"
WORKSTATION1_MAC = "00:00:00:00:00:aa"
WORKSTATION2_MAC = "00:00:00:00:00:bb"
PING_COUNT = "10"
VLAN_10 = "10"
REGEX_ETH1 = "eth1\s*Link encap:\w+\s+HWaddr [\S:]+\s*inet addr:[\d.]+"

TOPOLOGY = """
# +-------+                   +-------+
# |       |     +-------+     |       |
# |  hs1  <----->  sw1  <----->  hs3  |
# |       |     +-------+     |       |
# +-------+                   +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] sw1
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
hs1:1 -- sw1:1
sw1:2 -- hs2:1
"""


def configure_switch(switch, p1, p2):

    with switch.libs.vtysh.ConfigVlan(VLAN_10) as ctx:
        ctx.no_shutdown()

    with switch.libs.vtysh.ConfigInterface(str(p1)) as ctx:
        ctx.no_routing()
        ctx.vlan_access(VLAN_10)
        ctx.no_shutdown()

    with switch.libs.vtysh.ConfigInterface(str(p2)) as ctx:
        ctx.no_routing()
        ctx.vlan_access(VLAN_10)
        ctx.no_shutdown()


def configure_workstation_mac(hs, mac):

    hs("ifconfig eth1 down")
    hs("ifconfig eth1 hw ether " + mac)
    hs("ifconfig eth1 up")


def configure_workstation_ip(workstation, ip):
    eth1 = re.search(REGEX_ETH1, workstation("ifconfig"))
    if eth1:
        workstation("ifconfig eth1 0.0.0.0")
    workstation("ip addr add %s/%s dev eth1" %
                (ip, WORKSTATION_MASK))


def check_mac_learning(switch, vlan, mac1, mac2, p1, p2):
    show_mac_table = switch.libs.vtysh.show_mac_address_table()

    assert show_mac_table[mac1]['vlan_id'] == vlan
    assert show_mac_table[mac1]['port'] == p1
    assert show_mac_table[mac1]['from'] == 'dynamic'

    assert show_mac_table[mac2]['vlan_id'] == vlan
    assert show_mac_table[mac2]['port'] == p2
    assert show_mac_table[mac2]['from'] == 'dynamic'

    return True


@mark.platform_incompatible(['docker'])
def test_maclearning(topology, step):
    """
    Updates the Mac vs port entries in the OVSDB and verifies the same.
    """
    sw1 = topology.get('sw1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert sw1 is not None
    assert hs1 is not None
    assert hs2 is not None

    p1 = sw1.ports["1"]
    p2 = sw1.ports["2"]

    # Configure IP and MAC on eth1 of workstations in the topology
    configure_workstation_ip(hs1, WORKSTATION1_IP)
    configure_workstation_mac(hs1, WORKSTATION1_MAC)
    configure_workstation_ip(hs2, WORKSTATION2_IP)
    configure_workstation_mac(hs2, WORKSTATION2_MAC)

    # Configure the switch for vlan and interfaces
    configure_switch(sw1, p1, p2)

    # ------------------------------------------------------
    # Case 1        Dynamically learnt MAC addresses
    # ------------------------------------------------------

    # Ping from workstation1 to workstation2 to update the MAC table in
    # database
    hs1("ping -c %s %s" % (PING_COUNT, WORKSTATION2_IP), shell="bash")
    time.sleep(60)

    mac_learnt_flag = check_mac_learning(sw1, VLAN_10, WORKSTATION1_MAC,
                                         WORKSTATION2_MAC, str(p1), str(p2))
    assert mac_learnt_flag, "MAC Learning failed"

    # ------------------------------------------------------
    # Case 2        MAC Move
    # ------------------------------------------------------

    # Configure MAC address to trigger MAC Move
    configure_workstation_mac(hs1, WORKSTATION2_MAC)
    configure_workstation_mac(hs2, WORKSTATION1_MAC)

    # Ping from workstation1 to workstation2 to update the MAC table in
    # database
    hs1("ping -c %s %s" % (PING_COUNT, WORKSTATION2_IP), shell="bash")
    time.sleep(60)

    mac_learnt_flag = check_mac_learning(sw1, VLAN_10, WORKSTATION2_MAC,
                                         WORKSTATION1_MAC, str(p1), str(p2))
    assert mac_learnt_flag, "MAC Learning for MAC Move failed"
