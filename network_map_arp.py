from scapy.all import ARP, Ether, srp
import netifaces as ni
import networkx as nx
import matplotlib.pyplot as plt
import os

def scan_local_network(ip_range="192.168.1.1/24"):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # srp - Send and Receive Packets
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def get_arp_table():
    arp_table = os.popen('arp -a').read()
    return arp_table

def get_default_gateway():
    gateways = ni.gateways()
    default_gateway = gateways['default'][ni.AF_INET][0]
    return default_gateway

def visualize_network(devices, default_gateway, working_station):
    G = nx.Graph()

    # Add the current working machine
    working_station_label =  f"Working Station \n({working_station})"
    G.add_node(working_station_label, mac="Working Station")

    for device in devices:
        if device['ip'] == default_gateway:
            gateway_label = f"Default Gateway \n({device['ip']})"
            G.add_node(gateway_label, mac=device['mac'])
            # Use the gateway label for connection to ensure it matches the node
            G.add_edge(working_station_label, gateway_label)
        else:
            device_label = device['ip']
            G.add_node(device_label, mac=device['mac'])
            # Connect the device to the working station
            G.add_edge(working_station_label, device_label)


    positions = nx.spring_layout(G)

    # Draw the network
    nx.draw_networkx_nodes(G, positions, node_size=700, node_color='skyblue')
    nx.draw_networkx_edges(G, positions)
    nx.draw_networkx_labels(G, positions, font_weight='bold')

    plt.title("Home Network Map")
    plt.axis('off')  # Turn off the axis
    plt.show()



if __name__ == "__main__":
    default_gateway = get_default_gateway()
    ip_range = "192.168.1.1/24"  # local network range
    devices = scan_local_network(ip_range)
    print("Devices found on the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    
    # arp_table = get_arp_table()
    # print("\nARP Table:")
    # print(arp_table)
    
    # visualize the network
    visualize_network(devices, default_gateway, '192.168.1.184')
