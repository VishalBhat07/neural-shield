# app.py
from flask import Flask, request, jsonify
from pe_feature_extractor import extract_pe_features_from_bytes, save_features_to_csv

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    # Your existing code
    file = request.files['file']
    file_data = file.read()
    features = extract_pe_features_from_bytes(file_data, file.filename)

    print(features)
    
    if features is None:
        return jsonify({"error": "Failed to process PE file"}), 400

    save_features_to_csv([features], output_file="uploaded_file_features.csv")

    # Model

    return jsonify({"message": "File processed successfully", "features": features})

if __name__ == "__main__":
    app.run(debug=True, port=8080)
