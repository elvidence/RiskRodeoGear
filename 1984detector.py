#!/usr/bin/env python3

"""
Author: A.R.
Version: 0.001b Raw Beta ;-)
Date: 13 October 2024
License: MIT
"""

import os
import math
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

# Define file signatures for known file types
FILE_SIGNATURES = {
    '.exe': [b'MZ'],
    '.dll': [b'MZ'],
    '.jpg': [b'\xFF\xD8\xFF'],
    '.png': [b'\x89PNG\r\n\x1a\n'],
    '.pdf': [b'%PDF'],
    '.zip': [b'PK\x03\x04'],
    '.txt': [],  # Text files usually don't have a signature
    '.tar': [b'ustar'],  # POSIX tar archives
    '.gz': [b'\x1F\x8B'],  # GZIP files
    '.bz2': [b'BZh'],  # BZIP2 files
    '.7z': [b'7z\xBC\xAF\x27\x1C'],  # 7z files
    '.mp3': [b'ID3'],  # MP3 files with ID3v2 header
    '.mp4': [b'\x00\x00\x00\x18ftypmp42'],  # MP4/M4A files
    '.iso': [b'CD001'],  # ISO image files
    '.dmg': [b'koly'],  # Apple Disk Image files
    '.sqlite': [b'SQLite format 3\x00'],  # SQLite database file
    '.deb': [b'!<arch>\ndebian-binary'],  # Debian package files
    '.rpm': [b'\xed\xab\xee\xdb'],  # RPM package files
    '.sh': [],  # Shell script files
    '.py': [],  # Python script files
    '.js': [],  # JavaScript files
    '.html': [b'<!DOCTYPE HTML'],  # HTML files
    '.xml': [b'<?xml version="1.0"'],  # XML files
    # Add more signatures as needed
}

def scan_files(directory):
    """Recursively scan the directory and return a list of file paths."""
    file_paths = []
    for root, _, files in os.walk(directory):
        for filename in files:
            file_paths.append(os.path.join(root, filename))
    return file_paths

def get_file_signature(file_path):
    """Read the file and return its signature."""
    max_sig_length = max((len(sig) for sigs in FILE_SIGNATURES.values() for sig in sigs if sigs), default=0)
    try:
        with open(file_path, 'rb') as f:
            file_header = f.read(max_sig_length)
        return file_header
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return b''

def identify_file_extension_by_signature(file_signature):
    """Identify the file extension based on its signature."""
    for ext, signatures in FILE_SIGNATURES.items():
        if not signatures:
            continue
        for sig in signatures:
            if file_signature.startswith(sig):
                return ext
    return None  # Unknown signature

def group_files_by_actual_extension(file_paths):
    """Group files by their actual extension determined by signature."""
    file_groups = defaultdict(list)
    for file_path in file_paths:
        _, ext = os.path.splitext(file_path)
        ext = ext.lower() if ext else "[no extension]"

        file_signature = get_file_signature(file_path)
        actual_ext = identify_file_extension_by_signature(file_signature)

        if actual_ext == ext or actual_ext is None:
            # Signature matches extension or signature is unknown
            sig_label = "[no file sig confirmed]" if actual_ext is None else ""
            group_key = f"{ext} {sig_label}".strip()
        else:
            # Signature mismatch; group by actual extension
            sig_label = "[signature mismatch]"
            group_key = f"{actual_ext} {sig_label}"

        file_groups[group_key].append(file_path)
    return file_groups

def create_shingles(byte_data, k):
    """Create shingles (subsequences) of length k from byte data."""
    shingles = [byte_data[i:i+k] for i in range(len(byte_data) - k + 1)]
    return shingles

def compute_distances(i_indices, shingles, m, r):
    """Compute match counts for a chunk of indices."""
    match_count_m = 0
    match_count_m1 = 0
    n = len(shingles)
    for i in i_indices:
        shingle_i_m = shingles[i][:m]
        shingle_i_m1 = shingles[i][:m+1]
        for j in range(i + 1, n - m):
            shingle_j_m = shingles[j][:m]
            shingle_j_m1 = shingles[j][:m+1]

            # Compare sequences of length m
            distance_m = sum(
                shingle_i_m[k] != shingle_j_m[k]
                for k in range(m)
            ) / m
            if distance_m <= r:
                match_count_m += 1

                # Compare sequences of length m+1
                distance_m1 = sum(
                    shingle_i_m1[k] != shingle_j_m1[k]
                    for k in range(m + 1)
                ) / (m + 1)
                if distance_m1 <= r:
                    match_count_m1 += 1

    return match_count_m, match_count_m1

def sample_entropy_shingles_parallel(shingles, m, r):
    """Calculate sample entropy for a list of shingles using parallel processing."""
    n = len(shingles)
    if n < m + 1:
        return float('inf')  # Not enough data to calculate entropy

    num_processes = os.cpu_count()

    # Divide indices among processes
    indices = list(range(n - m))
    chunk_size = max(1, len(indices) // num_processes)
    chunks = [indices[i:i + chunk_size] for i in range(0, len(indices), chunk_size)]

    total_match_count_m = 0
    total_match_count_m1 = 0

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = []
        for chunk in chunks:
            futures.append(executor.submit(compute_distances, chunk, shingles, m, r))

        for future in futures:
            match_count_m, match_count_m1 = future.result()
            total_match_count_m += match_count_m
            total_match_count_m1 += match_count_m1

    try:
        return -math.log(total_match_count_m1 / total_match_count_m)
    except (ZeroDivisionError, ValueError):
        return float('inf')

def calculate_mean(values):
    """Calculate the mean of a list of values."""
    return sum(values) / len(values) if values else 0.0

def calculate_std(values, mean):
    """Calculate the standard deviation of a list of values."""
    variance = sum((x - mean) ** 2 for x in values) / len(values) if values else 0.0
    return math.sqrt(variance)

def compute_entropy_profiles(file_groups, k, m, r):
    """Compute entropy profiles for each file group."""
    entropy_profiles = {}
    for group_key, files in file_groups.items():
        print(f"Processing {len(files)} files with extension {group_key}")
        entropies = []
        for file_path in files:
            try:
                with open(file_path, 'rb') as f:
                    byte_data = f.read()
                if len(byte_data) < k + m:
                    print(f"Skipping {file_path}: File too small for analysis")
                    continue  # Skip files that are too small
                shingles = create_shingles(byte_data, k)

                entropy = sample_entropy_shingles_parallel(shingles, m, r)
                entropies.append((file_path, entropy))
                print(f"Calculated entropy for {file_path}: {entropy}")
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
        entropy_profiles[group_key] = entropies
    return entropy_profiles

def detect_anomalies(entropy_profiles, threshold=1.5):
    """Detect anomalies based on entropy values."""
    anomalies = {}
    for group_key, entropies in entropy_profiles.items():
        entropy_values = [entropy for _, entropy in entropies if math.isfinite(entropy)]
        if not entropy_values:
            continue
        mean_entropy = calculate_mean(entropy_values)
        std_entropy = calculate_std(entropy_values, mean_entropy)
        print(f"\nFile group: {group_key}")
        print(f"Mean entropy: {mean_entropy}")
        print(f"Standard deviation: {std_entropy}")
        anomalies_in_group = []
        for file_path, entropy in entropies:
            if math.isfinite(entropy):
                z_score = (entropy - mean_entropy) / std_entropy if std_entropy > 0 else 0
                if abs(z_score) > threshold:
                    anomalies_in_group.append((file_path, entropy, z_score))
                    print(f"Anomaly detected: {file_path}, Entropy: {entropy}, Z-score: {z_score}")
            else:
                anomalies_in_group.append((file_path, entropy, float('inf')))
                print(f"Anomaly detected (Infinite entropy): {file_path}")
        if anomalies_in_group:
            anomalies[group_key] = anomalies_in_group
    return anomalies

def check_file_signature(file_path, ext):
    """Check if the file signature matches the expected signature for the extension."""
    signatures = FILE_SIGNATURES.get(ext, [])
    if not signatures:
        return True  # If no signature is defined, assume it's correct
    try:
        with open(file_path, 'rb') as f:
            file_header = f.read(max(len(sig) for sig in signatures))  # Read enough bytes for the longest signature
        return any(file_header.startswith(sig) for sig in signatures)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return False

def main(directory, shingle_size):
    file_paths = scan_files(directory)
    if not file_paths:
        print("No files found in the directory.")
        return
    file_groups = group_files_by_actual_extension(file_paths)
    k = shingle_size  # Shingle length set by user
    m = 2  # Sequence length for sample entropy
    r = 0.2  # Tolerance for accepting matches

    entropy_profiles = compute_entropy_profiles(file_groups, k, m, r)
    anomalies = detect_anomalies(entropy_profiles)

    if not anomalies:
        print("\nNo anomalies detected.")
    else:
        for group_key, files in anomalies.items():
            print(f"\nAnomalies detected in {group_key} files:")
            for file_path, entropy, z_score in files:
                # Extract extension from group key
                ext = group_key.split()[0]
                signature_match = check_file_signature(file_path, ext)
                status = "Signature Match" if signature_match else "Signature Mismatch"
                print(f"File: {file_path}")
                print(f"Entropy: {entropy}")
                print(f"Z-score: {z_score}")
                print(f"{status}\n")

if __name__ == "__main__":
    import sys
    import platform
    if platform.system() == 'Darwin':  # macOS specific fix for multiprocessing
        import multiprocessing
        multiprocessing.set_start_method('fork')

    if len(sys.argv) != 3:
        print("Usage: python scanner.py <directory> <shingle_size>")
        sys.exit(1)
    directory = sys.argv[1]
    try:
        shingle_size = int(sys.argv[2])
    except ValueError:
        print("Shingle size must be an integer.")
        sys.exit(1)
    main(directory, shingle_size)
