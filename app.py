from flask import Flask, render_template, jsonify
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import io
import base64
import random

app = Flask(__name__)

# Example function to simulate packet capturing and anomaly detection
def capture_and_detect_anomalies(packet_count=100, contamination_rate=0.1):
    # Simulate packet lengths as features
    features = np.random.randint(60, 1514, packet_count)
    
    # Detect anomalies
    model = IsolationForest(contamination=contamination_rate)
    features_reshaped = features.reshape(-1, 1)
    model.fit(features_reshaped)
    anomalies = model.predict(features_reshaped)
    
    return features, anomalies

@app.route('/')
def index():
    features, anomalies = capture_and_detect_anomalies()

    # Create plot
    fig, ax = plt.subplots()
    ax.plot(features, label='Packet Lengths')
    ax.plot(np.where(anomalies == -1, features, np.nan), 'ro', label='Anomalies')
    ax.legend()
    
    # Save plot to a string in base64 format
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    
    return render_template('index.html', image_base64=image_base64, anomalies=anomalies.tolist())

if __name__ == '__main__':
    app.run(debug=True)
