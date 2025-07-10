import matplotlib.pyplot as plt
from scapy.all import rdpcap

def visualize_packets(pcap_file):
    packets = rdpcap(pcap_file)
    protocol_counts = {}

    for packet in packets:
        if packet.haslayer('IP'):
            proto = packet['IP'].proto
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.bar(protocols, counts)
    plt.xlabel('Protocols')
    plt.ylabel('Packet Count')
    plt.title('Packet Count per Protocol')
    plt.show()

if __name__ == "__main__":
    visualize_packets('packets.pcap')
