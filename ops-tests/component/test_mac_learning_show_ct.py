# -*- coding: utf-8 -*-
# (C) Copyright 2015 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
##########################################################################

"""
OpenSwitch Test for L2 mac related configurations.
"""
import pytest
from pytest import mark

TOPOLOGY = """
#
#  +-------+
#  | sw1   |
#  +-------+
#

# Nodes
[type=openswitch name="OpenSwitch 1"] sw1
"""

#@pytest.mark.skipif(True, reason="Disabling")
@mark.gate
def test_show_mac(topology):
    sw1 = topology.get('sw1')
    assert sw1 is not None

    # Configure IP and bring UP switch 1 interfaces
    with sw1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    # Configure IP and bring UP switch 1 interfaces
    with sw1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    # Configure IP and bring UP switch 1 interfaces
    with sw1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    # Configure vlan 2
    with sw1.libs.vtysh.ConfigVlan('2') as ctx:
        ctx.no_shutdown()

    # Configure vlan 3
    with sw1.libs.vtysh.ConfigVlan('3') as ctx:
        ctx.no_shutdown()

    mac_entry = sw1.libs.vtysh.show_mac_address_table()
    assert not mac_entry

    # add mac address
    sw1("ovs-vsctl add-mac 00:00:00:00:00:01 1 1 dynamic", shell="bash")
    sw1("ovs-vsctl add-mac 00:00:00:00:00:02 2 2 dynamic", shell="bash")
    sw1("ovs-vsctl add-mac 00:00:00:00:00:03 3 3 dynamic", shell="bash")
    sw1("ovs-vsctl add-mac 00:00:00:00:00:04 1 1 dynamic", shell="bash")
    sw1("ovs-vsctl add-mac 00:00:00:00:00:05 2 1 dynamic", shell="bash")
    sw1("ovs-vsctl add-mac 00:00:00:00:00:06 1 3 dynamic", shell="bash")
    sw1("ovs-vsctl add-mac 00:00:00:00:00:07 1 2 dynamic", shell="bash")

    mac_entry = sw1.libs.vtysh.show_mac_address_table()
    assert mac_entry is not None
    assert mac_entry['00:00:00:00:00:01']['vlan_id'] == '1'
    assert mac_entry['00:00:00:00:00:01']['port'] == '1'
    assert mac_entry['00:00:00:00:00:01']['from'] == 'dynamic'

    assert mac_entry['00:00:00:00:00:02']['vlan_id'] == '2'
    assert mac_entry['00:00:00:00:00:02']['port'] == '2'
    assert mac_entry['00:00:00:00:00:02']['from'] == 'dynamic'

    assert mac_entry['00:00:00:00:00:03']['vlan_id'] == '3'
    assert mac_entry['00:00:00:00:00:03']['port'] == '3'
    assert mac_entry['00:00:00:00:00:03']['from'] == 'dynamic'

    assert mac_entry['00:00:00:00:00:04']['vlan_id'] == '1'
    assert mac_entry['00:00:00:00:00:04']['port'] == '1'
    assert mac_entry['00:00:00:00:00:04']['from'] == 'dynamic'

    assert mac_entry['00:00:00:00:00:05']['vlan_id'] == '2'
    assert mac_entry['00:00:00:00:00:05']['port'] == '1'
    assert mac_entry['00:00:00:00:00:05']['from'] == 'dynamic'

    assert mac_entry['00:00:00:00:00:06']['vlan_id'] == '1'
    assert mac_entry['00:00:00:00:00:06']['port'] == '3'
    assert mac_entry['00:00:00:00:00:06']['from'] == 'dynamic'

    assert mac_entry['00:00:00:00:00:07']['vlan_id'] == '1'
    assert mac_entry['00:00:00:00:00:07']['port'] == '2'
    assert mac_entry['00:00:00:00:00:07']['from'] == 'dynamic'
