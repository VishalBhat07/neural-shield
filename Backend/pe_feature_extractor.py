import pefile
import math
import pandas as pd
import warnings
from collections import Counter
from pathlib import Path
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

def extract_pe_features_from_bytes(file_data, file_name="uploaded_file"):
    if not file_data:
        warnings.warn(f"Empty data received for {file_name}")
        return None

    try:
        pe = pefile.PE(data=file_data)
    except Exception as e:
        warnings.warn(f"Error processing {file_name}: {type(e).__name__} - {e}")
        # Optionally, you can save invalid files for inspection here
        invalid_folder = Path("invalid-files")
        invalid_folder.mkdir(exist_ok=True)
        invalid_path = invalid_folder / file_name
        with open(invalid_path, "wb") as f:
            f.write(file_data)
        return None

    features = {
        "file_name": file_name,
        "file_size": len(file_data),
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint
    }

    features["file_entropy"] = get_entropy(file_data)
    features.update(extract_byte_frequencies(file_data))

    for i, section in enumerate(pe.sections):
        try:
            section_name = section.Name.decode('utf-8', errors="ignore").rstrip("\x00")
            entropy = get_entropy(section.get_data())
            features[f"section_{i}_name"] = section_name
            features[f"section_{i}_entropy"] = entropy
        except Exception as e:
            warnings.warn(f"Failed to extract section {i} from {file_name}: {e}")

    features["api_calls"] = extract_api_calls(pe)

    return features

def save_features_to_csv(features_list, output_file="output_features.csv"):
    valid = [f for f in features_list if f]
    if valid:
        df = pd.DataFrame(valid)
        df.to_csv(output_file, mode='w', index=False)
        print(f"Saved {len(valid)} entries to {output_file}")
    else:
        print("No valid features extracted.")
