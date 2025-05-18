import pandas as pd
from pathlib import Path

def merge_csv_files(input_folder="csv_output", output_file="dataset/benign-files.csv"):
    input_path = Path(input_folder)
    csv_files = sorted(input_path.glob("benign-files*.csv"))

    if not csv_files:
        print("No CSV files found to merge.")
        return

    print(f"Found {len(csv_files)} files to merge...")

    # Merge all CSVs
    merged_df = pd.concat((pd.read_csv(f) for f in csv_files), ignore_index=True)
    
    # Save merged CSV
    merged_df.to_csv(output_file, index=False)
    print(f"Merged CSV saved to {output_file}")

if __name__ == "__main__":
    merge_csv_files()
