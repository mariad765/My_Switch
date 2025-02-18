#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# MAC table
mac_table = {}
switch_priority = -1
port_configs = {}
trunk_ports1 = {}
root_bridge_id = -1
root_port = -1
sender_bridge_id = -1
root_path_cost = -1
interfaces = []
own_bridge_id = -1


def parse_bpdu(bpdu):
    # Unpack the BPDU fields from the byte array
    bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_sender_bridge_id = struct.unpack('!QQQ', bpdu[17:17+24])
    return bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_sender_bridge_id

def create_bpdu(bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_sender_bridge_id):
    # dest mac
    dest_mac = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
    # src mac
    src_mac = get_switch_mac()
    # llc length
    llc_length = bytes([0x00, 0x00])
    # llc
    llc = bytes([0x42, 0x42, 0x03])
    # add the 3 parmeters to the bpdu
    bpdu = dest_mac + src_mac + llc_length + llc + struct.pack('!QQQ', bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_sender_bridge_id)
    # add bpdu_datta
    #bpdu = bpdu + struct.pack('!QIH6s', bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_sender_bridge_id)
    return bpdu



def on_receive(interface, data, length):
    global root_bridge_id, root_path_cost, sender_bridge_id, trunk_ports1, switch_priority, interfaces, root_port, own_bridge_id
    # Parse the BPDU
    bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_sender_bridge_id = parse_bpdu(data)
    prev_ceva = root_bridge_id
    
    # Check if the received BPDU is better than the current BPDU
    if bpdu_root_bridge_id < root_bridge_id :
        # Update the root_bridge_id, root_path_cost, sender_bridge_id
        root_bridge_id = bpdu_root_bridge_id
        root_path_cost = bpdu_root_path_cost+10
      
        # Update the root_port
        root_port = get_interface_name(interface)

        if(own_bridge_id == prev_ceva):
           # for all trunck prorts set     from state default to blocked
          for i in interfaces:
            if port_configs[get_interface_name(i)]['mode'] == 'trunk' and get_interface_name(i) != root_port:
                trunk_ports1[get_interface_name(i)]['state'] = 'blocking'

        if(port_configs[get_interface_name(interface)]['mode'] == 'trunk' and port_configs[get_interface_name(interface)]['state'] == 'blocking'):
            # Set the state of the root_port to forwarding
            trunk_ports1[root_port]['state'] = 'listening'

        # Create a new BPDU with the updated values
        bpdu = create_bpdu(root_bridge_id, root_path_cost, own_bridge_id)
        #  send on all trunck
        for port in interfaces:
            if port_configs[get_interface_name(port)]['mode'] == 'trunk' :
                if get_interface_name(port) != root_port:
                    send_to_link(port, len(bpdu), bpdu)
               
        

    elif bpdu_root_bridge_id == root_bridge_id:
        if get_interface_name(interface) == root_port :
            if bpdu_root_path_cost + 10 < root_path_cost:
                # Update the root_path_cost
                root_path_cost = bpdu_root_path_cost + 10
                # Create a new BPDU with the updated values
        elif get_interface_name(interface) != root_port:
            if bpdu_root_path_cost  > root_path_cost:
               #if ports are not listening
                if port_configs[get_interface_name(port)]['mode'] == 'trunk'  and port_configs[get_interface_name(interface)]['state'] != 'listening':
                    # Set the state of the port to listening
                    port_configs[get_interface_name(interface)]['state'] = 'listening'
    elif bpdu_root_bridge_id == own_bridge_id:
        #set port state to blocking
        port_configs[get_interface_name(interface)]['state'] = 'blocking'
    else:
        pass

    if own_bridge_id == root_bridge_id:
        # for all trunck prorts set     from state default to blocked
       for i in interfaces:
            if port_configs[get_interface_name(i)]['mode'] == 'trunk' :
                port_configs[get_interface_name(i)]['state'] = 'listening'
          

    


def parse_switch_config(config_file):
    global root_bridge_id
    lines= config_file.strip().split('\n')
    switch_priority = int(lines[0].strip())
    
    for line in lines[1:]:
        parts = line.strip().split()
        if parts[0].startswith('r-'):
            # Access Port Configuration (e.g., r-0 1 for access port in VLAN 1)
            port_id = parts[0]
            vlan_id = int(parts[1])  # Assume the second part is the VLAN ID for access ports
            port_configs[port_id] = {'mode': 'access', 'vlan_id': vlan_id}
        elif parts[0].startswith('rr-'):
            # Trunk Port Configuration (e.g., rr-0-1 T)
            port_id = parts[0]
            port_configs[port_id] = {'mode': 'trunk', 'state': 'default'}
    
    root_bridge_id = switch_priority

    return switch_priority, port_configs


def is_unicast(mac):
    # Split the MAC address string and convert the first byte to an integer
    first_byte = int(mac.split(":")[0], 16)
    # Check if the second least significant bit of the first byte is 0 (indicating unicast)
    return (first_byte & 0x01) == 0


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)



def send_bdpu_every_sec():
    global root_bridge_id, sender_bridge_id, root_path_cost, trunk_ports1, interfaces, own_bridge_id, switch_priority
 
    while True:
        print("Sending BPDU")
        if own_bridge_id == root_bridge_id:
            root_bridge_id = own_bridge_id
            sender_bridge_id = own_bridge_id
            root_path_cost = 0
            bpdu = create_bpdu(root_bridge_id, root_path_cost, sender_bridge_id)
            # Send the BPDU on all trunk ports
            for port in interfaces:
                if port_configs[get_interface_name(port)]['mode'] == 'trunk' :
                 send_to_link(port, len(bpdu), bpdu)
        time.sleep(1)  # Wait 1 second between BPDU transmissions

def check_if_bpdu(data):
    # Check if the frame is a BPDU
    return data[0] == 0x01 and data[1] == 0x80 and data[2] == 0xC2 and data[3] == 0x00 and data[4] == 0x00 and data[5] == 0x00

def get_trunk_ports(port_configs):   # return the portconfigs without the access ports
    return {port: config for port, config in port_configs.items() if config['mode'] == 'trunk'}

def get_access_ports(port_configs):
    return [port for port, config in port_configs.items() if config['mode'] == 'access']




def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    global switch_priority, port_configs, trunk_ports1, root_bridge_id, interfaces, own_bridge_id, root_path_cost
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    root_port = None
    
    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    switch_priority, port_configs = parse_switch_config(open(f'./configs/switch{switch_id}.cfg').read())
    # trunk_ports = get_trunk_ports(port_configs)
  
    own_bridge_id = switch_priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    trunk_ports1 = get_trunk_ports(port_configs)
    # # print trunk ports
    # print("Trunk ports are ", trunk_ports1)

    t = threading.Thread(target=send_bdpu_every_sec, args=())
    t.start()


    # printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        if check_if_bpdu(data):
            print("Received BPDU ")
            on_receive(interface, data, length)
            continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # get originals
        original_data = data
        original_length = length

        if port_configs[get_interface_name(interface)]['mode'] == 'access':
            #the the corresponding vlan id
            vlan_id = port_configs[get_interface_name(interface)]['vlan_id']
        # check if the pachet came from a trunk port
        if port_configs[get_interface_name(interface)]['mode'] == 'trunk' :
            # the vlan id is the one from the vlan tag
            vlan_id = vlan_id
        
        # print all header
        print("Header is ", data)
        # TODO: Implement forwarding with learning
        # check if src mac is in the MAC table
        if src_mac not in mac_table:
            # if it is not, add it to the MAC table
            mac_table[src_mac] = interface
            print("Added MAC to table")
        else:
            # print macul sursa este in tabela
            print("MAC src in table")
         # check if it is unicast
        if dest_mac != 'ff:ff:ff:ff:ff:ff' :
            # check if dest mac is in the MAC table
            if dest_mac in mac_table:
                # if it is, send the frame to the corresponding interface
                if(port_configs[get_interface_name(mac_table[dest_mac])]['mode'] == 'trunk' ):
                    # add the vlan tag if it came from an acess port
                    if port_configs[get_interface_name(interface)]['mode'] == 'access':
                        data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                        length = length + 4
                    send_to_link(mac_table[dest_mac], length, data)
                    data = original_data
                    length = original_length
                if(port_configs[get_interface_name(mac_table[dest_mac])]['mode'] == 'access'):
                        if port_configs[get_interface_name(interface)]['mode'] == 'trunk' :
                            data = data[0:12] + data[16:]
                            length = length - 4
                        send_to_link(mac_table[dest_mac], length, data)
                        data = original_data
                        length = original_length    
            else:
                # print nu e in tabela mac
                print("MAC dest not in table")
                # do flooding
                # when i have flooding, take into account the vlan_id
                for i in interfaces:
                    if i != interface:
                        # can't send on an access port, only on Trunk ports
                        # send only to trunck interfaces using portconfigs
                        if port_configs[get_interface_name(i)]['mode'] == 'trunk' and trunk_ports1[get_interface_name(i)]['state'] != 'blocking':
                            #check port not blocked
                            # add the vlan tag if it came from an acess port
                            if port_configs[get_interface_name(interface)]['mode'] == 'access':
                                data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                                length = length + 4
                            send_to_link(i, length, data)
                            data = original_data
                            length = original_length
                            print ("Sent to trunk")
                        elif port_configs[get_interface_name(i)]['mode'] == 'access':
                            # check if the vlan id is the same
                            if port_configs[get_interface_name(i)]['vlan_id'] == vlan_id:
                                # extract the vlan tag if it comes from a trunk
                                if port_configs[get_interface_name(interface)]['mode'] == 'trunk' :
                                    data = data[0:12] + data[16:]
                                    length = length - 4
                                send_to_link(i, length, data)
                                data = original_data
                                length = original_length
                                print ("Sent to access")
        else:
            # do flooding
                for i in interfaces:
                    if i != interface:
                        if port_configs[get_interface_name(i)]['mode'] == 'trunk' and trunk_ports1[get_interface_name(i)]['state'] != 'blocking':
                            # add the vlan tag
                            if port_configs[get_interface_name(interface)]['mode'] == 'access':
                                data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                                length = length + 4
                                send_to_link(i, length, data)
                                data = original_data
                                length = original_length
                                print ("Sent to trunk from acess")
                            if port_configs[get_interface_name(interface)]['mode'] == 'trunk' :
                                send_to_link(i, length, data)
                                print ("Sent to trunk fron trunk")
                        elif port_configs[get_interface_name(i)]['mode'] == 'access':
                            if port_configs[get_interface_name(i)]['vlan_id'] == vlan_id:
                                # extract the vlan tag
                                data = data[0:12] + data[16:]
                                length = length - 4
                                send_to_link(i, length, data)
                                print ("Sent to access")
                                length = original_length
                                data = original_data
                        else:
                            print("Port mode not supported")


if __name__ == "__main__":
    main()