# MAC Learning Feature Test Cases

## Contents

- [Verify MAC learning](#verify-mac-learning)
    - [Objective](#objective)
    - [Requirements](#requirements)
    - [Setup](#setup)
        - [Topology diagram](#topology-diagram)
        - [Test setup](#test-setup)

## Verify MAC Learning on Switch
### Objective
Verify the MAC Learning feature working as expected.
### Requirements
The requirements for this test case are:
 - Physical switch/workstations test setup.
 - FT File: ops-l2macd/ops-tests/feature/test_maclearning.py
 - FT File: ops-l2macd/ops-tests/feature/test_mac_flush.py

## Setup
### Topology diagram
```ditaa

  +-------+                   +-------+
  |       |     +-------+     |       |
  |  hs1  <----->  sw1  <----->  hs2  |
  |       |     +-------+     |       |
  +-------+                   +-------+

```
### Test setup
AS5712 switch instance connected with two workstations.

### Description
This test is used to ensure that MAC Learning is working on switch.

1. Connect Host-1 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.1/24 dev eth1
    ```

2. Connect Host-2 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.2/24 dev eth1
    ```
4. Configure the interfaces on the switch that are connected to these hosts.
    ```
    switch# configure terminal
    switch(config)# vlan 10
    switch(config)# no shut
    switch(config)# interface 1
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    switch(config)# interface 2
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    ```
5. Ping between Host-1 and the Host-2.
    ```
    ping 10.1.1.2 -c 200
    ```
6. Wait for 120 seconds to update the MACs learnt to update OVSDB.

7. Execute CLI command to view the list of MACs learnt by the switch
    ```
    show mac-address-table
    ```

### Test result criteria

#### Test pass criteria

- Verify Host-1 and Host-2 MACs present in the CLI command output
- Verify the Host-1 and Host-2 MACs learnt on the correct PORT and VLAN

#### Test fail criteria

- This test fails if the Host-1 or Host-2 MACs are not in the CLI command output.
- This test fails if the Host-1 or Host-2 MACs are not learnt on the correct PORT or VLAN.

### Description
This test is used to ensure that MAC moves work in the switch.

1. Swap the Host-1 and Host-2 Mac address and Configure IP address.
    ```
    ifconfig eth1 hw ether <Host-2 MAC>
    ip addr add 10.1.1.1/24 dev eth1
    ```
    ```
    ifconfig eth1 hw ether <Host-1 MAC>
    ip addr add 10.1.1.2/24 dev eth1
    ```

2. Ping between Host-1 and the Host-2.
    ```
    ping 10.1.1.2 -c 200
    ```
3. Wait for 120 seconds to update the MACs learnt to update OVSDB.

4. Execute CLI command to view the list of MACs learnt by the switch.
    ```
    show mac-address-table
    ```

### Test result criteria

#### Test pass criteria

- Verify that the Host-1 and Host-2 MACs are learnt on the correct PORT and VLAN

#### Test fail criteria
- This test fails if the Host-1 or Host-2 MACs are not in the CLI command output.
- This test fails if the Host-1 or Host-2 MACs are not learnt/moved on the new PORT.

### Description
This test verifies that MACs learnt on a port get flushed when the port goes down.

1. Connect Host-1 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.1/24 dev eth1
    ```

2. Connect Host-2 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.2/24 dev eth1
    ```
4. Configure the interfaces on the switch that are connected to these hosts.
    ```
    switch# configure terminal
    switch(config)# vlan 10
    switch(config)# no shut
    switch(config)# interface 1
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    switch(config)# interface 2
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    ```
5. Ping between Host-1 and the Host-2.
    ```
    ping 10.1.1.2 -c 200
    ```
6. Wait for 120 seconds to update the MACs learnt to update OVSDB.

7. Execute CLI command to view the list of MACs learnt by the switch.
    ```
    show mac-address-table
    ```
8. Shutdown the interfaces on the switch.
    ```
    switch# configure terminal
    switch(config)# interface 1
    switch(config-if)# shut
    switch(config-if)# exit
    switch(config)# interface 2
    switch(config-if)# shut
    switch(config-if)# exit
    ```
9. Execute CLI command to view the MACs learnt flushed.
    ```
    show mac-address-table
    ```

### Test result criteria

#### Test pass criteria

- Verify that the host MACs are removed/not seen in the CLI command output.

#### Test fail criteria

- This test fails if the Host-1 or Host-2 MACs are present in the CLI command output.

### Description
This test verifies that MACs learnt get properly flushed on a port when routing is
enabled on that port.

1. Connect Host-1 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.1/24 dev eth1
    ```

2. Connect Host-2 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.2/24 dev eth1
    ```
4. Configure the interfaces on the switch that are connected to these hosts.
    ```
    switch# configure terminal
    switch(config)# vlan 10
    switch(config)# no shut
    switch(config)# interface 1
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    switch(config)# interface 2
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    ```
5. Ping between Host-1 and the Host-2.
    ```
    ping 10.1.1.2 -c 200
    ```
6. Wait for 120 seconds to update the MACs learnt to update OVSDB.

7. Execute CLI command to view the list of MACsearnt MACs by the switch.
    ```
    show mac-address-table
    ```
8. Shutdown the interfaces on the switch.
    ```
    switch# configure terminal
    switch(config)# interface 1
    switch(config-if)# routing
    switch(config-if)# exit
    switch(config)# interface 2
    switch(config-if)# routing
    switch(config-if)# exit
    ```
9. Execute CLI command to MACs learnt flushed.
    ```
    show mac-address-table
    ```

### Test result criteria

#### Test pass criteria

- Verify that the host MACs are removed/not seen in the CLI command output..

#### Test fail criteria

- This test fails if the Host-1 or Host-2 MACs are present in the CLI command output.

### Description
This test verifies that MACs learnt on a VLAN get properly flushed when that
VLAN is administratively shut down or deleted on the switch.

1. Connect Host-1 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.1/24 dev eth1
    ```

2. Connect Host-2 to the switch. Configure IP address.
    ```
    ip addr add 10.1.1.2/24 dev eth1
    ```
4. Configure the interfaces on the switch that are connected to these hosts.
    ```
    switch# configure terminal
    switch(config)# vlan 10
    switch(config)# no shut
    switch(config)# interface 1
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    switch(config)# interface 2
    switch(config-if)# no routing
    switch(config-if)# vlan 10 access
    switch(config-if)# no shut
    switch(config-if)# exit
    ```
5. Ping between Host-1 and the Host-2.
    ```
    ping 10.1.1.2 -c 200
    ```

6. Wait for 120 seconds to update the MACs learnt to update OVSDB.

7. Execute CLI command to view the list of MACs learnt by the switch.
    ```
    show mac-address-table
    ```
8. Shutdown/Remove the configured VLAN on the switch.
    ```
    switch# configure terminal
    switch(config)#vlan 10
    switch(config-vlan)# shut
    switch(config-if)# exit
    ```

    ```
    switch# configure terminal
    switch(config)# no vlan 10
    switch(config-if)# exit
    ```
9. Execute CLI command to view the MACs learnt flushed from the old vlan.
    ```
    show mac-address-table
    ```

### Test result criteria

#### Test pass criteria

- Verify the Host-1 and Host-2 MACs is not with old VLAN in the CLI command output.

#### Test fail criteria

- Verify the Host-1 and Host-2 MACs are present on the old VLAN in
  the CLI command output.
