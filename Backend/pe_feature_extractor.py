import pefile
import math
import warnings
from pathlib import Path

def calculate_entropy(data):
    """Calculate Shannon entropy of the data."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_pe_features_from_bytes(file_data, file_name="uploaded_file"):
    """Extract features from PE file bytes to match the format needed by the model."""
    if not file_data:
        warnings.warn(f"Empty data received for {file_name}")
        return None

    try:
        pe = pefile.PE(data=file_data)
    except Exception as e:
        warnings.warn(f"Error processing {file_name}: {type(e).__name__} - {e}")
        # Save invalid files for inspection
        invalid_folder = Path("invalid-files")
        invalid_folder.mkdir(exist_ok=True)
        invalid_path = invalid_folder / file_name
        with open(invalid_path, "wb") as f:
            f.write(file_data)
        return None

    # Extract the features in the order expected by the model
    features = {
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'DirectoryEntryExport': 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
        'ImageDirectoryEntryExport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'DirectoryEntryImportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
        'SectionMaxChar': len(pe.sections),
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
    }

    # Calculate entropy for each section
    entropies = []
    virtual_sizes = []
    for section in pe.sections:
        try:
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            entropies.append(entropy)
            virtual_sizes.append(section.Misc_VirtualSize)
        except Exception as e:
            warnings.warn(f"Error processing section in {file_name}: {e}")
            # Add default values if we can't process the section
            entropies.append(0)
            virtual_sizes.append(0)

    # Add section-related features
    if entropies:
        features['SectionMinEntropy'] = min(entropies)
    else:
        features['SectionMinEntropy'] = 0
    
    if virtual_sizes:
        features['SectionMinVirtualsize'] = min(virtual_sizes)
    else:
        features['SectionMinVirtualsize'] = 0

    return features