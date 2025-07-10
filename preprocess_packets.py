import numpy as np
from scapy.all import rdpcap

def preprocess_packets(pcap_file):
    packets = rdpcap(pcap_file)
    features = []

    for packet in packets:
        if packet.haslayer('IP'):
            features.append([packet['IP'].len, packet['IP'].proto])

    return np.array(features)

if __name__ == "__main__":
    features = preprocess_packets('packets.pcap')
    print(features)
