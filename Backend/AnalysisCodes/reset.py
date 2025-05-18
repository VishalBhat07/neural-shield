import os
from pathlib import Path
import shutil

# Base folder
BASE_FOLDER = Path("virus-files")

# Find all subfolders starting with 'batch_'
batch_folders = [f for f in BASE_FOLDER.iterdir() if f.is_dir() and f.name.startswith("batch_")]

# Move all files from each batch folder back to the main virus-files folder
for batch_folder in batch_folders:
    for file in batch_folder.iterdir():
        if file.is_file():
            destination = BASE_FOLDER / file.name
            # Ensure no overwrite
            if destination.exists():
                print(f"File already exists in base folder: {file.name}, skipping...")
                continue
            shutil.move(str(file), destination)
    print(f"Moved files from {batch_folder.name} back to base folder.")

# Optionally, remove empty batch folders
for batch_folder in batch_folders:
    try:
        batch_folder.rmdir()
        print(f"Removed empty folder: {batch_folder.name}")
    except OSError:
        print(f"Could not remove {batch_folder.name} (not empty?)")

print("\nUndo complete.")
