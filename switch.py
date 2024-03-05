#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import re
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

BLOCKING = 0
LISTENING = 1
ROOT_PORT = 2
DESIGNATED_PORT = 3
BPDU_DESTINATION_MAC = "01:80:C2:00:00:00"
LLC_LENGTH = int(52).to_bytes(2, 'big')
LLC_HEADER = b'\x42\x42\x03'
BPDU_HEADER = int(0).to_bytes(4,'big')

FLAGS = int(0).to_bytes(1,'big')
MESSAGE_AGE = int(1).to_bytes(2, 'big')
MAX_AGE = int(20).to_bytes(2, 'big')
HELLO_TIME = int(2).to_bytes(2, 'big')
FORWARD_DELAY = int(15).to_bytes(2, 'big')

own_bridge_id = 0
root_bridge_id = 0
root_path_cost = 0
root_port = 0
interface_to_vlan_copy = {}
interfaces_copy = range(0,1)
interfaces_state_copy = {}
priority = 0

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

def make_bdpu(port):
    package =  bytearray()

    # convert the bpdu specific mac from string to bytes
    for group in BPDU_DESTINATION_MAC.split(":"):
        nr = int(group, 16)
        bt = nr.to_bytes(1, 'big')
        package.extend(bt)

    # add each component to the package
    package.extend(get_switch_mac())
    package.extend(LLC_LENGTH + LLC_HEADER + FLAGS + BPDU_HEADER)
    package.extend(int(root_bridge_id).to_bytes(8, 'big'))
    package.extend(int(root_path_cost).to_bytes(4, 'big'))
    package.extend(int(own_bridge_id).to_bytes(8, 'big'))
    package.extend(int(port).to_bytes(2, 'big'))
    package.extend(MESSAGE_AGE + MAX_AGE + HELLO_TIME + FORWARD_DELAY)
    return bytes(package)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        if own_bridge_id == root_bridge_id:
            for i in interfaces_copy:
                if interface_to_vlan_copy[get_interface_name(i)] == 'T':
                    bts = make_bdpu(i)
                    send_to_link(i, bts, 52)
        time.sleep(1)

def read_config_file(switch_id, interface_to_vlan, num_interfaces):
    
    # open the file corresponding to the current switch
    with open("./configs/switch{}.cfg".format(switch_id), "r") as f:
        
        # get the first line, convert it to int and set the switch's priority
        # to the respective value
        line = f.readline()
        global priority
        priority = int(line.strip(" \n\r\t"))

        # read the other lines that represent the binding between an interface and a VLAN
        # or the fact that an interface is a trunk port
        for i in range(0, num_interfaces):
            line = f.readline()
            line = line.strip(" \n\r\t")

            # regex that matches the format used for interfaces in the config files
            # the first group(name) matches any character one or more times and is used
            # to extract the name of the interface
            # the second group(tp) matches either the character 'T' for trunk ports
            # or any digit one or more times for the VLAN id corresponding to that
            # access port
            type = re.search(r"(?P<name>\S+) (?P<tp>[0-9]+|T)", line)

            # where tp is a number, store it as a number, not as a string representing a number
            interface_to_vlan[type.group('name')] = type.group('tp') if type.group('tp') == 'T' else int(type.group('tp'))
            
def broadcast(interfaces, interface, data, length, interface_to_vlan, vlan_id):
    vid = interface_to_vlan[get_interface_name(interface)]
    for o in interfaces:
        # i used continue instructions to keep the code somewhat clean

        # don't send to blocked ports or to the port i received on
        if o == interface:
            continue
        if interfaces_state_copy[o] == BLOCKING:
            continue

        # the port i received data on is trunk
        if interface_to_vlan[get_interface_name(interface)] == 'T':
            # the port i am going to send to is trunk
            if interface_to_vlan[get_interface_name(o)] == 'T':
                send_to_link(o, data, length)
                continue
            # the port i am going to send to is access
            if interface_to_vlan[get_interface_name(o)] == vlan_id:
                # remove the vlan tag
                send_to_link(o, data[0:12] + data[16:], length - 4)
            continue

        # the port i received data on is access

        # the port i am going to send to is trunk
        if interface_to_vlan[get_interface_name(o)] == 'T':
            # add the vlan tag 
            send_to_link(o, data[0:12] + create_vlan_tag(vid) + data[12:], length + 4)
            continue
        # the port i am going to send to is access
        if interface_to_vlan[get_interface_name(o)] == vid:
            send_to_link(o, data, length)
            continue

def send_to_mac(MAC_TABLE, src_mac, dest_mac, data, length, interface_to_vlan, vlan_id):
    # same logic used in broadcast

    # if i received on a trunk port
    if interface_to_vlan[get_interface_name(MAC_TABLE[src_mac])] == 'T':
        # if i am sending on a trunk port i send the package as is
        if interface_to_vlan[get_interface_name(MAC_TABLE[dest_mac])] == 'T':
            send_to_link(MAC_TABLE[dest_mac], data, length)
            return
        # if i am sending on an access port
        # i check the vlan id to see if they correspond and if they do
        # i remove the vlag tag
        if interface_to_vlan[get_interface_name(MAC_TABLE[dest_mac])] == vlan_id:
            send_to_link(MAC_TABLE[dest_mac], data[0:12] + data[16:], length - 4)
        return

    # if i received on an access port
    vid = interface_to_vlan[get_interface_name(MAC_TABLE[src_mac])]
    
    # if i am sending on a trunk port i add the vlan tag
    if interface_to_vlan[get_interface_name(MAC_TABLE[dest_mac])] == 'T':
        send_to_link(MAC_TABLE[dest_mac], data[0:12] + create_vlan_tag(vid) + data[12:], length + 4)
        return
    
    #if i am sending on an access port i send the package as is is the vlan ids correspond
    if interface_to_vlan[get_interface_name(MAC_TABLE[dest_mac])] == vid:
        send_to_link(MAC_TABLE[dest_mac], data, length)
        return
    
def do_stp_stuff(interface, data):

    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global interface_to_vlan_copy
    global interfaces_copy
    global interfaces_state_copy
    global root_port

    # extract the relevant data from the received package
    # i assume that the package is not malformed and thus
    # i know exactly what each group of bytes represents
    other_switch_root_id = int.from_bytes(data[22:30], 'big')
    sender_path_cost = int.from_bytes(data[30:34], 'big')
    other_switch_id = int.from_bytes(data[34:42], 'big')

    # i wouldn't have used a ternary operator for this
    # but i hate this language and don't trust simple equality to
    # return a boolean
    has_been_root = True if root_bridge_id == own_bridge_id else False

    # i just translated the pseudocode in the description and don't really have something
    # more to say
    if other_switch_root_id < root_bridge_id:
        root_bridge_id = other_switch_root_id
        root_path_cost = sender_path_cost + 10
        root_port = interface

        if has_been_root:
            for i in interfaces_copy:
                if interface_to_vlan_copy[get_interface_name(i)] == 'T' and i != root_port:
                    interfaces_state_copy[i] = BLOCKING

        if interfaces_state_copy[root_port] == BLOCKING:
            interfaces_state_copy[root_port] = LISTENING

        for i in interfaces_copy:
            if i != interface and interface_to_vlan_copy[get_interface_name(i)] == 'T':
                # make a new package with the right values set to the required fields and send it on
                new_data = data[0:30] + int(root_path_cost).to_bytes(4, 'big') + int(own_bridge_id).to_bytes(8, 'big') + data[42:]
                send_to_link(i, new_data, 52)
    elif other_switch_root_id == root_bridge_id:
        if interface == root_port and sender_path_cost + 10 < root_path_cost:
            root_path_cost = sender_path_cost + 10
        elif interface != root_port:
            if sender_path_cost > root_path_cost:
                if interfaces_state_copy[interface] != LISTENING:
                    interfaces_state_copy[interface] = LISTENING
    elif other_switch_id == own_bridge_id:
        interfaces_state_copy[interface] = BLOCKING

    # i translated discard bpdu into do nothing
    else:
        return
    
    if own_bridge_id == root_bridge_id:
        for i in interfaces_copy:
            interfaces_state_copy[i] = LISTENING

    return

def initialize(interfaces, interfaces_state, interface_to_vlan, priority):
    # mark every trunk port as blocked
    for i in interfaces:
        if interface_to_vlan[get_interface_name(i)] == 'T':
            interfaces_state[i] = BLOCKING
    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    own_bridge_id = priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    # mark every port on the root bridge as listening
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            interfaces_state[i] = LISTENING

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
    
    global priority
    interface_to_vlan = dict()
    interfaces_state = dict()

    # extract relevant data from the config file
    read_config_file(switch_id, interface_to_vlan, num_interfaces)
    

    initialize(interfaces, interfaces_state, interface_to_vlan, priority)

    # when i first did this i only used local variables and passed them as
    # arguments but then i realized that it would be easier to have them as
    # global variables so i used global references to the local objects that i had
    global interface_to_vlan_copy
    global interfaces_copy
    global interfaces_state_copy
    interfaces_copy = interfaces
    interface_to_vlan_copy = interface_to_vlan
    interfaces_state_copy = interfaces_state

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    MAC_TABLE = dict()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        MAC_TABLE[src_mac] = interface

        # separate cases for each destination MAC address
        if dest_mac == "01:80:c2:00:00:00":
            do_stp_stuff(interface, data)
            a = 5
        elif dest_mac != "ff:ff:ff:ff:ff:ff":
            if dest_mac in MAC_TABLE:
                send_to_mac(MAC_TABLE, src_mac, dest_mac, data, length, interface_to_vlan, vlan_id)
                continue
            broadcast(interfaces, interface, data, length, interface_to_vlan, vlan_id)
        else:
            broadcast(interfaces, interface, data, length, interface_to_vlan, vlan_id)
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
