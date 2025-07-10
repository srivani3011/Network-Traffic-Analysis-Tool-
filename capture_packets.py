from scapy.all import sniff, wrpcap

def capture_packets(packet_count, output_file):
    packets = sniff(count=packet_count)
    wrpcap(output_file, packets)
    print(f"Captured {packet_count} packets and saved to {output_file}")

if __name__ == "__main__":
    capture_packets(packet_count=100, output_file='packets.pcap')
