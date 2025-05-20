from flask import Flask, request, jsonify
from pe_feature_extractor import extract_pe_features_from_bytes, save_features_to_csv
import joblib
import pandas as pd
import numpy as np
import os
from cleaner import cleaner

# Load the trained model and scaler
model = joblib.load("rf_malware_detector.joblib")
scaler = joblib.load("scaler.joblib")

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        # Check if file was sent in request
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400
            
        file = request.files['file']
        
        # Check if a file was selected
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        # Read the file data
        file_data = file.read()
        
        # Extract features
        features = extract_pe_features_from_bytes(file_data, file.filename)
        if features is None:
            return jsonify({"error": "Failed to process PE file"}), 400
            
        # Save extracted features to CSV
        save_features_to_csv([features], output_file="uploaded_file_features.csv")
        
        # Run the cleaner function to process the features
        processed_df = cleaner()  # This processes the uploaded_file_features.csv and creates output.csv
        
        # Get the scaler's feature names for consistency
        scaler_features = scaler.feature_names_in_ if hasattr(scaler, 'feature_names_in_') else None
        
        # Read the cleaned data
        new_data = pd.read_csv("output.csv")
        
        # Ensure all values are numeric
        for col in new_data.columns:
            new_data[col] = pd.to_numeric(new_data[col], errors='coerce').fillna(0)
        
        # Handle feature name mismatch if needed
        if scaler_features is not None:
            # Add missing columns with zeros
            for feature in scaler_features:
                if feature not in new_data.columns:
                    new_data[feature] = 0
            
            # Select only the features the model knows, in the right order
            new_data = new_data[scaler_features]
        
        # Scale the data
        try:
            new_data_scaled = scaler.transform(new_data)
        except ValueError as e:
            # Handle potential errors with more detailed information
            return jsonify({
                "error": f"Scaling error: {str(e)}",
                "details": {
                    "data_shape": new_data.shape,
                    "columns": list(new_data.columns)
                }
            }), 500
        
        # Make prediction
        predictions = model.predict(new_data_scaled)
        probabilities = model.predict_proba(new_data_scaled)[:, 1] if hasattr(model, 'predict_proba') else None
        
        # Clean up temporary files
        for temp_file in ["uploaded_file_features.csv", "pipe1.csv", "pipe2.csv", "output.csv"]:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        # Return results
        result = {
            "message": "File processed successfully",
            "malware_prediction": bool(predictions[0]),
            "prediction_class": int(predictions[0])
        }

        print("Result :",result)
        
        # Add probability if available
        if probabilities is not None:
            result["probability"] = float(probabilities[0])
            
        return jsonify(result)
        
    except Exception as e:
        # Log the error for debugging
        import traceback
        print(f"Error processing file: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=8080)