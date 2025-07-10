import tkinter as tk
from tkinter import messagebox
from threading import Thread, Event
import time
import logging
import numpy as np
from scapy.all import sniff, wrpcap, rdpcap
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from plyer import notification
import queue
import sys

logging.basicConfig(filename='alerts.log', level=logging.INFO)

class NetworkTrafficMonitor:
    def __init__(self, queue):
        self.stop_event = Event()
        self.queue = queue

    def capture_packets(self, packet_count, output_file):
        packets = sniff(count=packet_count)
        wrpcap(output_file, packets)
        print(f"Captured {packet_count} packets and saved to {output_file}")

    def preprocess_packets(self, pcap_file):
        packets = rdpcap(pcap_file)
        features = []

        for packet in packets:
            if packet.haslayer('IP'):
                features.append([packet['IP'].len, packet['IP'].proto])

        return np.array(features), packets

    def detect_anomalies(self, features, contamination_rate):
        model = IsolationForest(contamination=contamination_rate)
        model.fit(features)
        predictions = model.predict(features)

        anomalies = features[predictions == -1]
        return anomalies

    def visualize_packets(self, pcap_file):
        packets = rdpcap(pcap_file)
        protocol_counts = {}

        for packet in packets:
            if packet.haslayer('IP'):
                proto = packet['IP'].proto
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        fig, ax = plt.subplots()
        ax.bar(protocols, counts)
        ax.set_xlabel('Protocols')
        ax.set_ylabel('Packet Count')
        ax.set_title('Packet Count per Protocol')
        plt.tight_layout()
        self.queue.put(fig)

    def send_alert(self, message):
        notification.notify(
            title="Network Traffic Alert",
            message=message,
            timeout=5
        )

    def log_anomalies(self, anomalies, packets):
        with open('anomalies.log', 'a') as f:
            for anomaly in anomalies:
                for packet in packets:
                    if packet.haslayer('IP') and packet['IP'].len == anomaly[0] and packet['IP'].proto == anomaly[1]:
                        f.write(f"Anomaly detected: {packet.summary()}\n")
                        break

    def monitor_traffic(self, packet_count, capture_duration, contamination_rate):
        while not self.stop_event.is_set():
            self.capture_packets(packet_count=packet_count, output_file='live_packets.pcap')
            features, packets = self.preprocess_packets('live_packets.pcap')
            anomalies = self.detect_anomalies(features, contamination_rate)

            if len(anomalies) > 0:
                message = f"{len(anomalies)} anomalies detected"
                logging.info(message)
                print(message)
                self.send_alert(message)
                self.log_anomalies(anomalies, packets)

            self.visualize_packets('live_packets.pcap')
            time.sleep(capture_duration)  # Wait before next capture

    def stop_monitoring(self):
        self.stop_event.set()

def start_monitoring():
    packet_count = int(packet_count_entry.get())
    capture_duration = int(capture_duration_entry.get())
    contamination_rate = float(contamination_rate_entry.get())

    global monitor
    monitor = NetworkTrafficMonitor(queue)
    monitoring_thread = Thread(target=monitor.monitor_traffic, args=(packet_count, capture_duration, contamination_rate))
    monitoring_thread.daemon = True
    monitoring_thread.start()

def stop_monitoring():
    if monitor:
        monitor.stop_monitoring()
        messagebox.showinfo("Information", "Network Traffic Monitoring Stopped")
        sys.exit()  # Terminate the program after stopping monitoring

def update_graph():
    try:
        fig = queue.get_nowait()
        for widget in graph_frame.winfo_children():
            widget.destroy()
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()
    except queue.Empty:
        pass
    root.after(1000, update_graph)

# Create the GUI
root = tk.Tk()
root.title("Network Traffic Analysis Tool")

queue = queue.Queue()

tk.Label(root, text="Packet Count:").pack()
packet_count_entry = tk.Entry(root)
packet_count_entry.pack()
packet_count_entry.insert(0, "100")

tk.Label(root, text="Capture Duration (s):").pack()
capture_duration_entry = tk.Entry(root)
capture_duration_entry.pack()
capture_duration_entry.insert(0, "10")

tk.Label(root, text="Contamination Rate:").pack()
contamination_rate_entry = tk.Entry(root)
contamination_rate_entry.pack()
contamination_rate_entry.insert(0, "0.1")

start_button = tk.Button(root, text="Start Monitoring", command=start_monitoring)
start_button.pack(pady=10)

stop_button = tk.Button(root, text="Stop Monitoring", command=stop_monitoring)
stop_button.pack(pady=10)

graph_frame = tk.Frame(root)
graph_frame.pack(pady=20)

root.after(1000, update_graph)
root.mainloop()