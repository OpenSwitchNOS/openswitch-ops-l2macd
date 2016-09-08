# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
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
OpenSwitch Test for MAC Learning and Flush.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from pytest import mark

import time

TOPOLOGY = """
#                    +-----------+
#      +------------>|7   ops1  8|<------------+
#      |             +-----------+            |
#      |                                      |
#+-----v-----+                           +----v-----+
#|   hs1     |                           |    hs2   |
#+-----------+                           +----------+
#
# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
hs1:1 -- ops1:7
hs2:1 -- ops1:8
"""

# Variables
VLAN = '10'
REGEX_ETH1 = "eth1\s*Link encap:\w+\s+HWaddr [\S:]+\s*inet addr:[\d.]+"
HOST_IFNAME = 'eth1'
INTERFACE1 = '7'
INTERFACE2 = '8'
MAC_DB_UPDATE_INTERVAL_SECONDS = (60 + 5)


def wait_until_interface_up(switch, portlbl, timeout=30, polling_frequency=1):
    """
    Wait until the interface, as mapped by the given portlbl, is marked as up.

    :param switch: The switch node.
    :param str portlbl: Port label that is mapped to the interfaces.
    :param int timeout: Number of seconds to wait.
    :param int polling_frequency: Frequency of the polling.
    :return: None if interface is brought-up. If not, an assertion is raised.
    """
    for i in range(timeout):
        status = switch.libs.vtysh.show_interface(portlbl)
        if status['interface_state'] == 'up':
            break
        time.sleep(polling_frequency)
    else:
        assert False, (
            'Interface {}:{} never brought-up after '
            'waiting for {} seconds'.format(
                switch.identifier, portlbl, timeout
            )
        )


def enable_l2port(ops, port):
    with ops.libs.vtysh.ConfigInterface(port) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def ops_get_mac_table(ops):
    result = ops.libs.vtysh.show_mac_address_table()
    return result


def ops_get_host_mac_address(hs):

    words = hs("ifconfig " + HOST_IFNAME).split()

    if "HWaddr" in words:
        return words[words.index("HWaddr") + 1]
    else:
        return 'No MAC Address Found!'


def ops_get_hw_learned_mac_address(ops):
    # Validate MAC table entries in the ASIC
    hw_mactable = ops('ovs-appctl plugin/dump-mac-table'
                      .format(**locals()), shell='bash')
    return hw_mactable


def verify_port_down_mac_flush(ops, hs1, hs2):

    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    with ops.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.shutdown()

    with ops.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.shutdown()

    time.sleep(MAC_DB_UPDATE_INTERVAL_SECONDS)

    print("############# Verify Port Down #################")
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    show_mactable = ops_get_mac_table(ops)
    print(show_mactable)
    print("#################################################")

    hs1_mac = ops_get_host_mac_address(hs1)
    hs2_mac = ops_get_host_mac_address(hs2)

    if hs1_mac in show_mactable or hs2_mac in show_mactable:
        assert False, "Port_down: Host MAC not Flushed"
    else:
        print("Learnt MACs flushed after port down event")

    # Bring up interfaces
    with ops.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.no_shutdown()


def verify_port_routing_mac_flush(ops, hs1, hs2):
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    with ops.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.routing()

    with ops.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.routing()

    time.sleep(MAC_DB_UPDATE_INTERVAL_SECONDS)

    print("########## Verify Port Moved to routing #########")
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    show_mactable = ops_get_mac_table(ops)
    print(show_mactable)
    print("#################################################")

    hs1_mac = ops_get_host_mac_address(hs1)
    hs2_mac = ops_get_host_mac_address(hs2)

    if hs1_mac in show_mactable or hs2_mac in show_mactable:
        assert False, "Port_routing: Host MAC not Flushed"
    else:
        print("Learnt MACs flushed after routing was enabled on the port")

    # Moving port back to no routing
    with ops.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.no_routing()

    with ops.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.no_routing()

    with ops.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.vlan_access(VLAN)

    with ops.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.vlan_access(VLAN)


def verify_vlan_down_mac_flush(ops, hs1, hs2):
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    with ops.libs.vtysh.ConfigVlan(VLAN) as ctx:
        ctx.shutdown()

    time.sleep(MAC_DB_UPDATE_INTERVAL_SECONDS)

    print("############# Verify VLAN Down #################")
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    show_mactable = ops_get_mac_table(ops)
    print(show_mactable)
    print("#################################################")

    hs1_mac = ops_get_host_mac_address(hs1)
    hs2_mac = ops_get_host_mac_address(hs2)

    if show_mactable is not None:
        assert(show_mactable[hs1_mac]['vlan_id'] != VLAN,
               "Learnt MACs not flushed after VLAN down event")
        assert(show_mactable[hs2_mac]['vlan_id'] != VLAN,
               "Learnt MACs not flushed after VLAN down event")
    else:
        print("Learnt MACs flushed after VLAN down event")

    # Bring up VLAN
    with ops.libs.vtysh.ConfigVlan(VLAN) as ctx:
        ctx.no_shutdown()

    with ops.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.vlan_access(VLAN)

    with ops.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.vlan_access(VLAN)


def verify_vlan_delete_mac_flush(ops, hs1, hs2):
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    # Delete the VLAN
    ops("configure terminal".format(**locals()), shell="vtysh")
    no_vlan_cmd = "no vlan " + VLAN
    ops(no_vlan_cmd.format(**locals()), shell="vtysh")
    ops("exit".format(**locals()), shell="vtysh")

    time.sleep(MAC_DB_UPDATE_INTERVAL_SECONDS)

    print("############# Verify VLAN Delete #################")
    hw_mactable = ops_get_hw_learned_mac_address(ops)
    print(hw_mactable)

    show_mactable = ops_get_mac_table(ops)
    print(show_mactable)
    print("##################################################")

    hs1_mac = ops_get_host_mac_address(hs1)
    hs2_mac = ops_get_host_mac_address(hs2)

    if show_mactable is not None:
        assert(show_mactable[hs1_mac]['vlan_id'] != VLAN,
               "Learnt MACs not flushed after VLAN removed event")
        assert(show_mactable[hs2_mac]['vlan_id'] != VLAN,
               "Learnt MACs not flushed after VLAN removed event")
    else:
        print("Learnt MACs flushed after VLAN removed event")


def configure_hosts_and_ping(hs1, hs2):
    # Configure host interfaces
    hs1.libs.ip.interface('1', up=False)
    hs2.libs.ip.interface('1', up=False)

    hs1.libs.ip.interface('1', addr='10.0.10.1/24', up=True)
    hs2.libs.ip.interface('1', addr='10.0.10.2/24', up=True)

    time.sleep(10)

    # ping both hosts
    hs1.libs.ping.ping(10, '10.0.10.2')
    hs2.libs.ping.ping(10, '10.0.10.1')


@mark.timeout(1500)
@mark.platform_incompatible(['docker'])
def test_mac_flush(topology):
    """
    Test MAC learning functionality with a OpenSwitch switch.
    Build a topology of one switch with two hosts like connection made as
    shown in topology.

    Configure the interface in the switch and configure IP address
    for the hosts.Now host1 and host2 starts ping each other, verify
    the host1 and host2 mac address learned on the switch.

    Bring down the interface/VLAN and Make sure learnt MAC address
    are flushed from the switch as per
    expectation.
    """
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    p7 = ops1.ports[INTERFACE1]
    p8 = ops1.ports[INTERFACE2]

    # Mark interfaces as enabled
    # Note: It is possible that this test fails here with
    #       pexpect.exceptions.TIMEOUT. There not much we can do, OpenSwitch
    #       may have a race condition or something that makes this command to
    #       freeze or to take more than 60 seconds to complete.
    iface_enabled = ops1(
        'set interface {p7} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not iface_enabled

    iface_enabled = ops1(
        'set interface {p8} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not iface_enabled

    # Configure interfaces
    with ops1.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    # Configure vlan and switch interfaces
    with ops1.libs.vtysh.ConfigVlan(VLAN) as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface(INTERFACE1) as ctx:
        ctx.vlan_access(VLAN)

    with ops1.libs.vtysh.ConfigInterface(INTERFACE2) as ctx:
        ctx.vlan_access(VLAN)

    # Wait until interfaces are up
    for portlbl in [INTERFACE1, INTERFACE2]:
        wait_until_interface_up(ops1, portlbl)

    # Configure Hosts
    configure_hosts_and_ping(hs1, hs2)

    time.sleep(MAC_DB_UPDATE_INTERVAL_SECONDS)

    show_mactable = ops_get_mac_table(ops1)

    hs1_mac = ops_get_host_mac_address(hs1)
    hs2_mac = ops_get_host_mac_address(hs2)

    print("##################################################")
    print(show_mactable)
    print("##################################################")

    if hs1_mac not in show_mactable or hs2_mac not in show_mactable:
        assert False, "Host MACs not learnt"

    assert(show_mactable[hs1_mac]['vlan_id'] == VLAN,
           "Learnt MACs on invalid VLAN")

    assert(show_mactable[hs2_mac]['vlan_id'] == VLAN,
           "Learnt MACs on invalid VLAN")

    # Step1: Verify Port Down MAC Flush case
    verify_port_down_mac_flush(ops1, hs1, hs2)

    # Step2: Verify Port Changed to routing
    configure_hosts_and_ping(hs1, hs2)
    verify_port_routing_mac_flush(ops1, hs1, hs2)

    # Step3: Verify VLAN Down MAC flush case
    configure_hosts_and_ping(hs1, hs2)
    verify_vlan_down_mac_flush(ops1, hs1, hs2)

    # Step4: Verify VLAN Delete MAC flush case
    configure_hosts_and_ping(hs1, hs2)
    verify_vlan_delete_mac_flush(ops1, hs1, hs2)
