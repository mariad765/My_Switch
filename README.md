1 2 3
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////MY_README////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

# SWITCH

**Description**  
Implementation of a network switch capable of receiving and processing Ethernet frames, maintaining a MAC address table for learning and forwarding, handling BPDUs (Bridge Protocol Data Units) for STP, and managing VLAN tagging for frames. It simulates switch behavior in a network where loops can be formed, which STP helps prevent by dynamically managing port states.

## Table of Contents
1. [Data_Structures](#structures)
2. [VLAN](#vlan)
3. [STP](#stp)
4. [Contributing](#contributing)
5. [License](#license)

## Data Structures

### 1. `mac_table`
- **Type**: `dict`
- **Description**: A table mapping MAC addresses to the interface from which they were learned.
- **Key**: `str` (MAC address)
- **Value**: `int` (interface number)

### 2. `port_configs`
- **Type**: `dict`
- **Description**: A dictionary holding configuration details for each port.
- **Key**: `str` (port identifier,  `r-0`, `rr-01`)
- **Value**: `dict` with keys:
  - `mode`: `str` (`"access"` or `"trunk"`)
  - `vlan_id`: `int` (for access ports, VLAN ID)
  - `state`: `str` (for trunk ports, STP state like `"default"`, `"blocking"`, `"listening"`)

### 4. `interfaces`
- **Type**: `list`
- **Description**: A list of all interface numbers available on the switch.
- **Elements**: `int` (interface number)

### 5. `root_bridge_id`
- **Type**: `int`
- **Description**: The ID of the current root bridge in the STP topology.

### 6. `root_port`
- **Type**: `int`
- **Description**: The interface number designated as the root port in STP.

### 7. `sender_bridge_id`
- **Type**: `int`
- **Description**: The ID of the bridge sending the BPDU.

### 8. `root_path_cost`
- **Type**: `int`
- **Description**: The cumulative path cost from the current switch to the root bridge.

### 9. `own_bridge_id`
- **Type**: `int`
- **Description**: The unique identifier of the current switch.

### 10. `switch_priority`
- **Type**: `int`
- **Description**: The priority value used for determining the bridge ID in STP.

## VLAN

### Overview
Virtual LANs (VLANs) allow network administrators to create distinct broadcast domains within a single physical switch.
### Implementation Logic

1. **Parsing and Configuring VLANs**
   - The switch reads its configuration from a `.cfg` file (e.g., `switch1.cfg`).
   - Each port is defined in `port_configs`, which includes:
     - **Mode**: Either `"access"` (assigned to a specific VLAN) or `"trunk"` (capable of carrying traffic for multiple VLANs).
     - **VLAN ID**: Only applicable to access ports, defining which VLAN they belong to.
   - Trunk ports are configured to carry traffic tagged with VLAN IDs, allowing them to handle multiple VLANs simultaneously.

2. **Packet Parsing and VLAN Identification**
   - The `parse_ethernet_header` function extracts source MAC, destination MAC, EtherType, and VLAN ID (if present).
   - When a packet is received on a port:
     - If it is an **access port**, it implicitly assigns the packet to the port's configured VLAN.
     - If it is a **trunk port**, it reads the VLAN ID from the VLAN tag in the frame header.

3. **Creating and Inserting VLAN Tags**
   - VLAN tags are added to Ethernet frames using the `create_vlan_tag` function:
     - **Ethertype 0x8100**: Indicates a VLAN-tagged frame.
     - **VLAN ID**: The field representing the VLAN the frame belongs to.
   - Tagged frames are created by inserting the VLAN tag after the source MAC and destination MAC in the frame.

4. **Forwarding Logic**
   - For **unicast** frames:
     - If the destination MAC is known and located on a **trunk port**, the frame is tagged with its VLAN ID before forwarding.
     - If the destination is on an **access port**, the tag is removed, ensuring the frame is sent as a regular Ethernet frame.
   - For **broadcast** or unknown destination frames:
     - The frame is forwarded to all appropriate ports:
       - **Trunk ports**: The frame is tagged with the VLAN ID before being sent.
       - **Access ports**: The frame is only forwarded to ports within the same VLAN, and the tag is removed if it was added.
   - VLAN tags are preserved on trunk ports to allow VLAN-aware switches to maintain traffic separation.

5. **VLAN Tag Stripping**
   - When forwarding a frame from a **trunk port** to an **access port**, the VLAN tag is stripped to ensure the frame is compatible with non-VLAN-aware devices.
   - The code handles this by slicing the data to remove the tag: `data = data[0:12] + data[16:]`.

## STP

### Overview
The Spanning Tree Protocol (STP) is implemented to prevent loops in Ethernet networks.
### Implementation Logic

1. **BPDU (Bridge Protocol Data Unit) Creation and Parsing**
   - **BPDU Structure**: A BPDU packet is constructed with the following:
     - **Destination MAC**: `01:80:C2:00:00:00` (STP multicast address)
     - **Source MAC**: MAC of the sending switch.
     - **BPDU Fields**: 
       - **Root Bridge ID**: The ID of the current root bridge.
       - **Root Path Cost**: The cost to reach the root bridge.
       - **Sender Bridge ID**: The ID of the bridge sending the BPDU.
   - **BPDU Creation**: The `create_bpdu` function constructs BPDUs to announce the bridge’s status to other switches.
   - **BPDU Parsing**: The `parse_bpdu` function extracts these fields from received BPDUs for comparison and decision-making.

2. **Root Bridge**
   - The switch initially considers itself the root bridge by setting `root_bridge_id` to its own bridge ID.
   - Upon receiving a BPDU with a lower `root_bridge_id`, the switch updates its knowledge:
     - Sets the new `root_bridge_id` to the one received.
     - Adjusts the `root_path_cost` by adding the cost to the sending switch.
     - Updates the `root_port` to the interface on which the superior BPDU was received.
   - If a BPDU with a higher `root_bridge_id` is received, it is ignored.

3. **Port States**
   - Ports are assigned one of three states:
     - **Listening**: The port is receiving and analyzing BPDUs but not forwarding frames.
     - **Forwarding**: The port is actively forwarding traffic and participating in learning.
     - **Blocking**: The port is not forwarding traffic or learning MAC addresses but is still receiving BPDUs.
   - **Port Transition Logic**:
     - When a superior BPDU is received, non-root ports transition to `blocking` if they are trunk ports.
     - The `root_port` is set to `listening` or `forwarding` based on its role.
   
4. **BPDU Transmission**
   - The `send_bdpu_every_sec` function sends BPDUs periodically to maintain STP updates across the network.
   - When a switch is determined to be the root bridge, it sends BPDUs with `root_path_cost` set to `0` and itself as the `root_bridge_id`.
   - Non-root switches propagate BPDUs with updated path costs and the current known root bridge information.

5. **Handling Received BPDUs**
   - The `on_receive` function processes incoming BPDUs:
     - Compares the received `root_bridge_id` with the current `root_bridge_id`.
     - Updates bridge variables and port states as necessary based on the BPDU's information.
     - Creates and forwards new BPDUs if the network topology changes.
   
6. **Port Configuration**
   - **Trunk Ports**: The switch only forwards BPDUs on trunk ports and adjusts their state based on received BPDUs.
   - **Access Ports**: Do not participate in STP but forward frames within their configured VLAN.

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Scheleton for the Hub implementation.

## Running

```bash
sudo python3 checker/topo.py
```

This will open 9 terminals, 6 hosts and 3 for the switches. On the switch terminal you will run 

```bash
make run_switch SWITCH_ID=X # X is 0,1 or 2
```

The hosts have the following IP addresses.
```
host0 192.168.1.1
host1 192.168.1.2
host2 192.168.1.3
host3 192.168.1.4
host4 192.168.1.5
host5 192.168.1.6
```

We will be testing using the ICMP. For example, from host0 we will run:

```
ping 192.168.1.2
```

Note: We will use wireshark for debugging. From any terminal you can run `wireshark&`.

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# My_Switch
