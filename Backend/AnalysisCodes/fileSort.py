import os
from pathlib import Path
import shutil

# Set the source and destination folders
SOURCE_FOLDER = Path("smaller-files")
DEST_FOLDER = Path("smallest-files")
SIZE_THRESHOLD_MB = 1  # Size threshold in megabytes

# Ensure destination folder exists
DEST_FOLDER.mkdir(exist_ok=True)

# Convert MB to bytes
size_threshold_bytes = SIZE_THRESHOLD_MB * 1024 * 1024

# Iterate and move small files
moved_count = 0
for file in SOURCE_FOLDER.iterdir():
    if file.is_file() and file.stat().st_size < size_threshold_bytes:
        destination = DEST_FOLDER / file.name
        try:
            shutil.move(str(file), destination)
            moved_count += 1
            print(f"Moved: {file.name} ({file.stat().st_size} bytes)")
        except Exception as e:
            print(f"Failed to move {file.name}: {e}")

print(f"\nTotal files moved: {moved_count}")
