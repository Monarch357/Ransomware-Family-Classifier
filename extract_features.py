import pefile
import math
import csv
import os
import sys
import json

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_features(filepath, family_label):
    features = {}
    features['filename'] = os.path.basename(filepath)
    features['family'] = family_label

    try:
        pe = pefile.PE(filepath)

        # Basic PE header features
        features['machine_type'] = pe.FILE_HEADER.Machine
        features['num_sections'] = pe.FILE_HEADER.NumberOfSections
        features['timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['characteristics'] = pe.FILE_HEADER.Characteristics

        # Optional header
        features['imagebase'] = pe.OPTIONAL_HEADER.ImageBase
        features['entrypoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['dll_characteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['file_size'] = os.path.getsize(filepath)

        # Section features
        section_entropies = []
        section_sizes = []
        for section in pe.sections:
            data = section.get_data()
            section_entropies.append(calculate_entropy(data))
            section_sizes.append(section.SizeOfRawData)

        features['num_sections'] = len(pe.sections)
        features['mean_section_entropy'] = sum(section_entropies) / len(section_entropies) if section_entropies else 0
        features['max_section_entropy'] = max(section_entropies) if section_entropies else 0
        features['min_section_entropy'] = min(section_entropies) if section_entropies else 0
        features['mean_section_size'] = sum(section_sizes) / len(section_sizes) if section_sizes else 0

        # Import features
        imported_dlls = []
        num_imports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.append(entry.dll.decode(errors='ignore').lower())
                num_imports += len(entry.imports)

        features['num_imported_dlls'] = len(imported_dlls)
        features['num_imports'] = num_imports

        # Flag common DLLs used by ransomware
        features['imports_cryptsp'] = int('cryptsp.dll' in imported_dlls)
        features['imports_advapi32'] = int('advapi32.dll' in imported_dlls)
        features['imports_kernel32'] = int('kernel32.dll' in imported_dlls)
        features['imports_wininet'] = int('wininet.dll' in imported_dlls)
        features['imports_ws2_32'] = int('ws2_32.dll' in imported_dlls)
        features['imports_vssapi'] = int('vssapi.dll' in imported_dlls)

        # Export features
        features['num_exports'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        # Overall file entropy
        with open(filepath, 'rb') as f:
            raw = f.read()
        features['file_entropy'] = calculate_entropy(raw)
        features['parse_error'] = 0

    except Exception as e:
        print(f"  [!] Error parsing {filepath}: {e}")
        features['parse_error'] = 1

    return features

def process_folder(folder_path, family_label, output_csv):
    results = []
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    print(f"[*] Processing {len(files)} files for family: {family_label}")

    for fname in files:
        fpath = os.path.join(folder_path, fname)
        print(f"  -> {fname}")
        features = extract_features(fpath, family_label)
        results.append(features)

    if results:
        keys = results[0].keys()
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Saved {len(results)} records to {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 extract_features.py <samples_folder> <family_label> <output_csv>")
        sys.exit(1)

    folder = sys.argv[1]
    label = sys.argv[2]
    output = sys.argv[3]
    process_folder(folder, label, output)
