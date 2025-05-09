
import pefile
import math
import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from joblib import Parallel, delayed
from collections import Counter

# Feature extraction functions
def get_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_byte_frequencies(data):
    byte_counts = Counter(data)
    total_bytes = len(data)
    frequencies = {f"byte_freq_{i:02x}": byte_counts.get(i, 0) / total_bytes for i in range(256)}
    return frequencies

def extract_api_calls(pe):
    api_calls = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                api_calls.append(imp.name.decode('utf-8') if imp.name else "")
    return ' '.join(api_calls)

def extract_pe_features(filepath):
    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return None

    features = {}

    # File size
    features["file_size"] = os.path.getsize(filepath)

    # Entry point
    features["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # File entropy
    try:
        file_data = open(filepath, "rb").read()
        features["file_entropy"] = get_entropy(file_data)
        features.update(extract_byte_frequencies(file_data))
    except Exception as e:
        print(f"Error reading file data for {filepath}: {e}")
        features["file_entropy"] = 0
        features.update({f"byte_freq_{i:02x}": 0 for i in range(256)})

    # Section entropy
    for i, section in enumerate(pe.sections[:5]):
        section_name = section.Name.decode(errors="ignore").strip("\x00")
        section_entropy = get_entropy(section.get_data())
        features[f"section_{i}_entropy"] = section_entropy

    # API calls
    features["api_calls"] = extract_api_calls(pe)

    return features

# Parallel processing of files
def process_file(filepath):
    features = extract_pe_features(filepath)
    return features

def process_files_in_parallel(filepaths, num_jobs=4):
    return Parallel(n_jobs=num_jobs)(delayed(process_file)(f) for f in filepaths)

def save_to_csv(features_list, output_filename="malware_features_test.csv"):
    df = pd.DataFrame([f for f in features_list if f is not None])
    df.to_csv(output_filename, index=False)

# Main function
def generate_features_for_multiple_files(filepaths):
    all_features = process_files_in_parallel(filepaths)
    save_to_csv(all_features)

# Example usage
if __name__ == "__main__":
    file_list = ["sample1.exe"]  # Replace with your actual file paths
    generate_features_for_multiple_files(file_list)
