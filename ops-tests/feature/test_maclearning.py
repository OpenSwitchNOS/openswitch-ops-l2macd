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


def configure_ip_get_mac(workstation, ip):
    eth1 = re.search(REGEX_ETH1, workstation("ifconfig"))
    if eth1:
        workstation("ifconfig eth1 0.0.0.0")
    workstation("ip addr add %s/%s dev eth1" %
                (ip, WORKSTATION_MASK))
    workstn_config = workstation("ifconfig")
    eth = re.findall(r'HWaddr [\S:]+', workstn_config)
    mac = str(eth[1].split(" ")[1])

    return mac


def check_mac_learning(switch, vlan, mac1, mac2, p1, p2):
    macs_learnt_flag = [False, False]
    show_mac_table = switch(
        "show mac-address-table".format(**locals()),
        shell='vtysh')

    macs_learnt = show_mac_table.split("\n")

    assert len(macs_learnt) != 2, "MACs not learnt correctly"

    for line in macs_learnt:
        if "dynamic" in line:
            line = line.split()
            if line[0] == mac1:
                if any([line[1] != vlan, line[3] != p1]):
                    break
                else:
                    macs_learnt_flag[0] = True
            elif line[0] == mac2:
                if any([line[1] != vlan, line[3] != p2]):
                    break
                else:
                    macs_learnt_flag[1] = True

    if False in macs_learnt_flag:
        return False
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

    # Get the mac addresses of workstations in the topology
    mac1 = configure_ip_get_mac(hs1, WORKSTATION1_IP)
    mac2 = configure_ip_get_mac(hs2, WORKSTATION2_IP)

    # Configure the switch for vlan and interfaces
    configure_switch(sw1, p1, p2)

    # ------------------------------------------------------
    # Case 1        Dynamically learnt MAC addresses
    # ------------------------------------------------------

    # Ping from workstation1 to workstation2 to update the MAC table in
    # database
    hs1("ping -c %s %s" % (PING_COUNT, WORKSTATION2_IP), shell="bash")
    time.sleep(60)

    mac_learnt_flag = check_mac_learning(sw1, VLAN_10, mac1, mac2,
                                         str(p1), str(p2))
    assert mac_learnt_flag, "MAC Learning failed"

    # ------------------------------------------------------
    # Case 2        MAC Move
    # ------------------------------------------------------

    configure_workstation_mac(hs1, mac2)
    configure_workstation_mac(hs2, mac1)

    # Ping from workstation1 to workstation2 to update the MAC table in
    # database
    hs1("ping -c %s %s" % (PING_COUNT, WORKSTATION2_IP), shell="bash")
    time.sleep(60)

    mac_learnt_flag = check_mac_learning(sw1, VLAN_10, mac2, mac1,
                                         str(p1), str(p2))
    assert mac_learnt_flag, "MAC Learning for MAC Move failed"
