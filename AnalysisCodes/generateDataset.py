import pefile
import math
import os
import pandas as pd
import warnings
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from joblib import Parallel, delayed
from collections import Counter
import shutil

def get_entropy(data):
    if not data:
        return 0.0
    byte_counts = Counter(data)
    total_bytes = len(data)
    return -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_counts.values())

def extract_byte_frequencies(data):
    byte_counts = Counter(data)
    total_bytes = len(data)
    return {f"byte_freq_{i:02x}": byte_counts.get(i, 0) / total_bytes for i in range(256)}

def extract_api_calls(pe):
    api_calls = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                try:
                    if imp.name:
                        api_calls.append(imp.name.decode('utf-8', errors='ignore'))
                except Exception:
                    continue
    return ' '.join(api_calls)

def extract_pe_features(filepath):
    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        warnings.warn(f"Error processing {filepath}: {e}")
        invalid_folder = Path("invalid-files")
        invalid_folder.mkdir(exist_ok=True)
        try:
            shutil.move(str(filepath), invalid_folder / filepath.name)
        except Exception as move_err:
            warnings.warn(f"Failed to move invalid file {filepath}: {move_err}")
        return None

    features = {
        "file_path": str(filepath),
        "file_size": os.path.getsize(filepath),
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint
    }

    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
            features["file_entropy"] = get_entropy(file_data)
            features.update(extract_byte_frequencies(file_data))
    except Exception as e:
        warnings.warn(f"Error reading file data for {filepath}: {e}")
        features["file_entropy"] = 0.0
        features.update({f"byte_freq_{i:02x}": 0.0 for i in range(256)})

    for i, section in enumerate(pe.sections):
        section_name = section.Name.decode(errors="ignore").rstrip("\x00")
        entropy = get_entropy(section.get_data())
        features[f"section_{i}_name"] = section_name
        features[f"section_{i}_entropy"] = entropy

    features["api_calls"] = extract_api_calls(pe)

    return features

def validate_file_paths(filepaths):
    valid_files = [str(path) for path in filepaths if Path(path).exists()]
    for path in filepaths:
        if not Path(path).exists():
            warnings.warn(f"File not found: {path}")
    return valid_files

def process_file(filepath):
    print(f"Processing: {filepath}")
    return extract_pe_features(filepath)

def process_files_in_parallel(filepaths, num_jobs=2):
    print(f"Processing {len(filepaths)} files with {num_jobs} jobs ...")
    return Parallel(n_jobs=num_jobs)(delayed(process_file)(f) for f in filepaths)

def save_to_csv(features_list, output_file):
    valid = [f for f in features_list if f]
    if valid:
        df = pd.DataFrame(valid)
        df.to_csv(output_file, mode='w', index=False)
        print(f"Saved {len(valid)} entries to {output_file}")
    else:
        print("No valid features extracted.")

def generate_features_for_folder(folder_path="virus-files", batch_size=2000):
    folder = Path(folder_path)
    filepaths = [f for f in folder.iterdir() if f.is_file()]
    filepaths.sort()  # Ensure consistent ordering

    total_files = len(filepaths)
    if total_files == 0:
        print("No files found.")
        return

    print(f"Total files found: {total_files}")

    for batch_index in range(0, total_files, batch_size):
        batch_number = batch_index // batch_size
        output_csv = Path(f"csv_output/malware_features_{batch_number}.csv")

        # ✅ Skip batch if output CSV already exists
        if output_csv.exists():
            print(f"Skipping batch {batch_number + 1}: {output_csv.name} already exists.")
            continue

        batch_files = filepaths[batch_index:batch_index + batch_size]
        print(f"\nProcessing batch {batch_number + 1} ({len(batch_files)} files)...")

        valid_files = validate_file_paths(batch_files)
        if not valid_files:
            print("No valid files in this batch.")
            continue

        features = process_files_in_parallel(valid_files, num_jobs=1)
        save_to_csv(features, output_csv)

    print("\nAll batches processed.")

if __name__ == "__main__":
    print("Generating PE file feature dataset...\n")
    generate_features_for_folder("virus-files")
    print("\nDone.")
