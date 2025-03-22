from flask import Flask, request, jsonify
import joblib
import pandas as pd

app = Flask(__name__)

# Load the trained model
model = joblib.load("models/threat_detector_rf.pkl")

# Get the exact feature order used during training
FEATURE_COLUMNS = list(model.feature_names_in_)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get input JSON data from the POST request
        input_data = request.get_json()

        # Convert to DataFrame
        input_df = pd.DataFrame([input_data]) if isinstance(input_data, dict) else pd.DataFrame(input_data)

        # Reorder columns to match training data
        input_df = input_df[FEATURE_COLUMNS]
        input_df.columns.name = None  # Clear index name if it exists

        # Make prediction and get probabilities
        prediction = model.predict(input_df)
        confidence = model.predict_proba(input_df).max(axis=1)

        # Return both prediction and confidence
        return jsonify({
            "prediction": prediction.tolist(),
            "confidence": confidence.tolist()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)

 
