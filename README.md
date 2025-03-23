# AI-Powered Cybersecurity Threat Detection System

This project uses Machine Learning and Security Logs to detect cyber threats in real time. It classifies intrusions such as DoS, Probe, R2L, U2R, and Normal traffic using AI.

---

## Features
- AI-powered intrusion detection
- Detects malware, phishing, DoS, Probe, and unauthorized access attacks
- Uses Scikit-learn and Flask for training and API deployment
- Real-time threat predictions with confidence scores

---

## Project Structure
```
cybersecurity-threat-ai/
├── data/                    # Raw and processed datasets
│   └── full-d/             # Source ARFF files
│   └── KDDTrain+Multi.csv  # Preprocessed training data
├── models/                 # Saved machine learning models
│   └── threat_detector_rf.pkl
├── src/                    # Source code files
│   ├── preprocess.py       # Data loading and preprocessing
│   ├── train.py            # Model training
│   ├── predict.py          # Local batch prediction testing
│   └── deploy.py           # Flask API for real-time predictions
├── requirements.txt        # Project dependencies
├── README.md               # Project overview
└── .gitignore              # Files to ignore in Git
```

---

## Installation & Setup

### 1. Clone the repository:
```cmd
git clone https://github.com/mahasweta99/cybersecurity-threat-ai.git
cd cybersecurity-threat-ai
```

### 2. Create and activate a virtual environment (optional but recommended):
```cmd
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies:
```cmd
pip install -r requirements.txt
```

---

## Step-by-Step Usage

### A. Preprocess the Data
Converts ARFF to CSV, applies label encoding.
```cmd
python src\preprocess.py
```

### B. Train the Model
Trains a Random Forest classifier on the preprocessed data.
```cmd
python src\train.py
```

### C. Test the Model Locally (Optional)
```cmd
python src\predict.py
```

### D. Deploy the API
Runs the Flask server for real-time predictions.
```cmd
python src\deploy.py
```

### E. Send a Test Request
Use curl or Postman to test the model API.
```cmd
curl -X POST http://127.0.0.1:5000/predict ^
-H "Content-Type: application/json" ^
-d "{\"duration\": 0, \"protocol_type\": 0, \"service\": 11, ... }"
```

---

## API Response Example
```json
{
  "prediction": ["normal"],
  "confidence": [1.0]
}
```

---

## Author
**Mahasweta** — [GitHub Profile](https://github.com/mahaswetaroy1)

Want to contribute? Open an Issue or submit a Pull Request!

---
## License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

```
MIT License

Copyright (c) 2025 Mahasweta

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```