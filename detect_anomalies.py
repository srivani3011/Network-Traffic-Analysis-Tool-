import numpy as np
from sklearn.ensemble import IsolationForest

def detect_anomalies(features):
    model = IsolationForest(contamination=0.1)
    model.fit(features)
    predictions = model.predict(features)

    anomalies = features[predictions == -1]
    return anomalies

if __name__ == "__main__":
    from preprocess_packets import preprocess_packets
    features = preprocess_packets('packets.pcap')
    anomalies = detect_anomalies(features)
    print(f"Detected {len(anomalies)} anomalies")
