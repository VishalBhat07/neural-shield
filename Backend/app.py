from flask import Flask, request, jsonify
from flask_cors import CORS
from pe_feature_extractor import extract_pe_features_from_bytes
import joblib
import pandas as pd
import pickle
import os
import time

# Create directory for model files if it doesn't exist
os.makedirs('model', exist_ok=True)

# Load the trained model - update path if your model is located elsewhere
MODEL_PATH = "malwareclassifier-V2.pkl"  # Change this to your model's path
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join('model', 'malwareclassifier-V2.pkl')

# Try to load the model
try:
    clf = joblib.load(MODEL_PATH)
    print(f"Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"Error loading model: {e}")
    print("Please ensure the model file is in the correct location")
    exit(1)

# Define the feature list expected by the model
# These are the features extracted in the pe_feature_extractor.py file
FEATURES_LIST = [
    'MajorLinkerVersion', 'MinorOperatingSystemVersion', 'MajorSubsystemVersion',
    'SizeOfStackReserve', 'TimeDateStamp', 'MajorOperatingSystemVersion',
    'Characteristics', 'ImageBase', 'Subsystem', 'MinorImageVersion',
    'MinorSubsystemVersion', 'SizeOfInitializedData', 'DllCharacteristics',
    'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'CheckSum',
    'DirectoryEntryImportSize', 'SectionMaxChar', 'MajorImageVersion',
    'AddressOfEntryPoint', 'SectionMinEntropy', 'SizeOfHeaders',
    'SectionMinVirtualsize'
]

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"])

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        start_time = time.time()
        # Check if file was sent in request
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400
            
        file = request.files['file']
        
        # Check if a file was selected
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        file_size = len(file.read())
        file.seek(0)  # Reset file pointer after reading size
        file_data = file.read()
        
        # Extract features
        features = extract_pe_features_from_bytes(file_data, file.filename)
        if features is None:
            return jsonify({"error": "Failed to process PE file"}), 400

        # Extract only the required features in the correct order
        input_features = []
        for feat in FEATURES_LIST:
            input_features.append(features.get(feat, 0))  # Use 0 if feature missing

        # Convert to DataFrame for model
        input_df = pd.DataFrame([input_features], columns=FEATURES_LIST)

        # Predict
        prediction = clf.predict(input_df)[0]
        proba = clf.predict_proba(input_df)[0][1] if hasattr(clf, "predict_proba") else None

        processing_time = time.time() - start_time

        result = {
            "message": "File processed successfully",
            "file_name": file.filename,
            "file_size": file_size,
            "malware_prediction": bool(prediction == 1),  # 1 = malware, 0 = benign (adjust if needed)
            "prediction_class": int(prediction),
            "features_used": input_features,
            "feature_list": FEATURES_LIST,
            "processing_time": processing_time,
        }
        if proba is not None:
            result["probability"] = float(proba)

        return jsonify(result)

    except Exception as e:
        import traceback
        print(f"Error processing file: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=8080)