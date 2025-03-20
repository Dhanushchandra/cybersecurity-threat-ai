
# 🚀 AI-Powered Cybersecurity Threat Detection System

This project uses **Machine Learning & Security Logs** to detect cyber threats in real time.  
It classifies **intrusions, malware, phishing, and DDoS attacks** using AI.

---

## 🔹 Features
✅ AI-powered **intrusion detection**  
✅ Detects **malware, phishing, DDoS attacks**  
✅ Uses **Splunk, TensorFlow, AWS Security**  
✅ Live dashboard for **real-time threat monitoring**  

---

## 🔹 Installation & Setup
### 1️⃣ **Clone the repository:**
   ```cmd
   git clone https://github.com/mahasweta99/cybersecurity-threat-ai.git
   cd cybersecurity-threat-ai

---
## 2️⃣ Install dependencies:

cmd
Copy code
pip install -r requirements.txt
3️⃣ Run data preprocessing:

cmd
Copy code
python src/preprocess.py
🔹 Data Preprocessing
🔹 Loads security logs (data/security_logs.csv)
🔹 Cleans missing data & formats timestamps
🔹 Extracts important threat features

Run the script:

cmd
Copy code
python src/preprocess.py
🔹 Model Training
🔹 Trains a Machine Learning model to classify security threats.
🔹 Uses Random Forest, Deep Learning (TensorFlow), Anomaly Detection.
🔹 Saves trained models to models/ directory.

Run the script:

cmd
Copy code
python src/train.py
🔹 Threat Prediction (Real-Time)
🔹 Uses trained AI model to analyze new security logs.
🔹 Outputs predicted threat categories (e.g., "Phishing", "DDoS", "Normal").

Run the script:

cmd
Copy code
python src/predict.py
🔹 Deployment
This system is deployed as a Flask API for real-time security threat analysis.

Start the API server:

cmd
Copy code
python src/deploy.py
Test the API with sample input:

cmd
Copy code
curl -X POST -H "Content-Type: application/json" -d '{"log": "Suspicious login attempt detected"}' http://localhost:5000/predict
🔹 Contributors
🚀 Mahasweta - GitHub

Want to contribute? Open an Issue or submit a Pull Request!