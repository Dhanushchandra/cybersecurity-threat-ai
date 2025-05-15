from scapy.all import sniff, IP, TCP, Raw
import requests
import time
from collections import defaultdict, deque

API_URL = "http://192.168.31.50:5000/predict"

# Map port to service IDs (basic example)
SERVICE_PORT_MAP = {
    80: 1,     # HTTP
    21: 2,     # FTP
    22: 3,     # SSH
    25: 4,     # SMTP
    53: 5,     # DNS
    443: 6,    # HTTPS
    5000: 7,   # Flask app (custom)
}

# TCP flag map (simplified)
TCP_FLAG_MAP = {
    'S': 1,    # SYN
    'SA': 2,   # SYN-ACK
    'FA': 3,   # FIN-ACK
    'PA': 4,   # PSH-ACK
}

# Track IP-based histories
connection_history = defaultdict(deque)  # ip: deque of (timestamp, service)
start_times = {}

def is_http_get_root(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        return payload.startswith("GET / ") or payload.startswith("POST / ")
    return False

def get_tcp_flag_id(flags):
    f = str(flags)
    return TCP_FLAG_MAP.get(f, 0)

def extract_features(packet):
    ip = packet[IP]
    tcp = packet[TCP]
    src_ip = ip.src
    dst_port = tcp.dport
    now = time.time()

    # Duration
    flow_key = (str(ip.src), str(ip.dst), int(tcp.sport), int(tcp.dport))

    print(flow_key)

    if flow_key not in start_times:
        start_times[flow_key] = now
    duration = now - start_times[flow_key]

    # Maintain 2-second window history
    recent_connections = connection_history[src_ip]
    recent_connections.append((now, dst_port))
    while recent_connections and now - recent_connections[0][0] > 2:
        recent_connections.popleft()

    count = len(recent_connections)
    srv_count = sum(1 for t, port in recent_connections if port == dst_port)
    same_srv_rate = srv_count / count if count > 0 else 0.0
    diff_srv_rate = 1.0 - same_srv_rate

    return {
        "duration": round(duration, 2),
        "protocol_type": 1,  # TCP
        "service": SERVICE_PORT_MAP.get(dst_port, 0),
        "flag": get_tcp_flag_id(tcp.flags),
        "src_bytes": len(packet),
        "dst_bytes": 0,
        "land": int(ip.src == ip.dst and tcp.sport == tcp.dport),
        "wrong_fragment": 0,
        "urgent": tcp.urgptr,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0
    }

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if is_http_get_root(packet):
            features = extract_features(packet)
            try:
                features["source_ip"] = packet[IP].src
                response = requests.post(API_URL, json=features)
                result = response.json()
                prediction = result['prediction']
                if isinstance(prediction, list) and len(prediction) == 1:
                    prediction = prediction[0]

                confidence = result['confidence']
                if isinstance(confidence, list) and len(confidence) == 1:
                    confidence = confidence[0]

                label = prediction  # just reuse prediction variable

                label_map = {
                    0: "Normal",
                    1: "DoS",
                    2: "Probe",
                    3: "R2L",
                    4: "U2R"
                }

                print(f"⚠️ Threat Detected: {prediction} | Confidence: {confidence}")
                print(f"⚠️ Prediction: {label_map.get(label, 'Unknown')} ({label}) | Confidence: {confidence}")
            except Exception as e:
                print(f"❌ Error: {e}")

print("🚨 Monitoring HTTP GET / on port 5000...")
sniff(filter="tcp port 5000", iface="\\Device\\NPF_{26EA21C1-F13C-4F6D-AC1D-E79F82D3C718}", prn=packet_callback, store=0)
