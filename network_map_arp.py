from scapy.all import ARP, Ether, srp
import networkx as nx
import matplotlib.pyplot as plt
import os

def scan_local_network(ip_range="192.168.1.1/24"):
    """
    Scan the local network to find active devices.
    """
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def get_arp_table():
    """
    Retrieve the ARP table from the system.
    """
    # This command might change depending on the operating system
    # For Windows, you might use 'arp -a'
    arp_table = os.popen('arp -a').read()
    return arp_table

def visualize_network(devices):
    """
    Visualize the network using networkx and matplotlib.
    """
    G = nx.Graph()
    for device in devices:
        G.add_node(device['ip'], mac=device['mac'])
    
    # You might need to add edges based on your network's specifics
    nx.draw(G, with_labels=True, font_weight='bold')
    plt.show()

if __name__ == "__main__":
    ip_range = "192.168.1.1/24"  # Adjust this to your local network range
    devices = scan_local_network(ip_range)
    print("Devices found on the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    
    arp_table = get_arp_table()
    print("\nARP Table:")
    print(arp_table)
    
    # Optionally, visualize the network
    visualize_network(devices)