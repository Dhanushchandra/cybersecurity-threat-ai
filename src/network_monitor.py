from scapy.all import sniff, IP, TCP, Raw
import requests

API_URL = "http://localhost:5000/predict"

def is_http_get_root(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        return payload.startswith("GET / ") or payload.startswith("POST / ")
    return False

def extract_features(packet):
    ip_layer = packet[IP]
    return {
        "duration": 0,
        "protocol_type": 1,
        "service": 38,
        "flag": 2,
        "src_bytes": len(packet),
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
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
        "count": 100,
        "srv_count": 100,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
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
                response = requests.post(API_URL, json=features)
                result = response.json()
                print(f"⚠️ Threat Detected: {result['prediction']} | Confidence: {result['confidence']}")
            except Exception as e:
                print(f"❌ Error: {e}")

# Only sniff traffic on port 5000 (Flask default)
print("🚨 Monitoring HTTP GET / on port 5000...")
sniff(filter="tcp port 5000", iface="\\Device\\NPF_Loopback", prn=packet_callback, store=0)


