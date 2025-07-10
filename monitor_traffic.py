import time
import logging
import numpy as np
from scapy.all import sniff, wrpcap, rdpcap
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from plyer import notification

logging.basicConfig(filename='alerts.log', level=logging.INFO)

def capture_packets(packet_count, output_file):
    packets = sniff(count=packet_count)
    wrpcap(output_file, packets)
    print(f"Captured {packet_count} packets and saved to {output_file}")

def preprocess_packets(pcap_file):
    packets = rdpcap(pcap_file)
    features = []

    for packet in packets:
        if packet.haslayer('IP'):
            features.append([packet['IP'].len, packet['IP'].proto])

    return np.array(features), packets

def detect_anomalies(features):
    model = IsolationForest(contamination=0.1)
    model.fit(features)
    predictions = model.predict(features)

    anomalies = features[predictions == -1]
    return anomalies

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

def send_alert(message):
    notification.notify(
        title="Network Traffic Alert",
        message=message,
        timeout=5
    )

def log_anomalies(anomalies, packets):
    with open('anomalies.log', 'a') as f:
        for anomaly in anomalies:
            for packet in packets:
                if packet.haslayer('IP') and packet['IP'].len == anomaly[0] and packet['IP'].proto == anomaly[1]:
                    f.write(f"Anomaly detected: {packet.summary()}\n")
                    break

def monitor_traffic(packet_count, capture_duration, contamination_rate):
    while True:
        capture_packets(packet_count=packet_count, output_file='live_packets.pcap')
        features, packets = preprocess_packets('live_packets.pcap')
        model = IsolationForest(contamination=contamination_rate)
        model.fit(features)
        predictions = model.predict(features)

        anomalies = features[predictions == -1]
        if len(anomalies) > 0:
            message = f"{len(anomalies)} anomalies detected"
            logging.info(message)
            print(message)
            send_alert(message)
            log_anomalies(anomalies, packets)

        visualize_packets('live_packets.pcap')
        time.sleep(capture_duration)  # Wait before next capture

# Run the traffic monitoring tool with default values
if __name__ == "__main__":
    monitor_traffic(packet_count=100, capture_duration=10, contamination_rate=0.1)
