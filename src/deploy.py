from flask import Flask, request, jsonify
import joblib
import pandas as pd
import json
from datetime import datetime
from flask import send_file

app = Flask(__name__)

# Load the trained model
model = joblib.load("models/threat_detector_rf.pkl")

# Get the exact feature order used during training
FEATURE_COLUMNS = list(model.feature_names_in_)

LOG_PATH = "logs/predictions.jsonl"
BLOCKED_IPS = set()

def log_prediction(input_data, prediction, confidence, user_ip):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "input": input_data,
        "prediction": int(prediction[0]),
        "confidence": float(confidence[0]),
        "user_ip": user_ip
    }
    
    # Log to file
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"Logged prediction: {log_entry}")

@app.route('/predict', methods=['POST'])
def predict():
    try:

        input_data = request.get_json()
        # Get the IP address of the user
        # user_ip = request.json.get("source_ip")
        user_ip = input_data.pop("source_ip", None)

        print("📦 Received JSON:", input_data)

        # Get input JSON data from the POST request

        # Convert to DataFrame
        input_df = pd.DataFrame([input_data]) if isinstance(input_data, dict) else pd.DataFrame(input_data)

        # Reorder columns to match training data
        input_df = input_df[FEATURE_COLUMNS]
        input_df.columns.name = None  # Clear index name if it exists

        # Make prediction and get probabilities
        prediction = model.predict(input_df)
        confidence = model.predict_proba(input_df).max(axis=1)

        # Log prediction with the IP address
        log_prediction(input_data, prediction, confidence, user_ip)

        # Return both prediction and confidence
        return jsonify({
            "prediction": prediction.tolist(),
            "confidence": confidence.tolist()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
@app.route("/logs", methods=["GET"])
def get_logs():
    try:
        with open(LOG_PATH, "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
        return jsonify(logs[-100:])  # return last 100 logs
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/block_user/<ip>", methods=["POST"])
def block_user(ip):
    try:
        BLOCKED_IPS.add(ip)  # Add the IP to the blocklist
        return jsonify({"message": f"IP {ip} is now blocked."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["GET"])
def home():
    user_ip = request.remote_addr
    if user_ip in BLOCKED_IPS:
        return "Access denied: Your IP is blocked by the admin.", 403  # Return 403 Forbidden if blocked

    return send_file("index.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    # Admin dashboard to view and block IPs
    return  send_file("dashboard.html")


# Run the Flask app
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000,debug=True)

 
