#!/usr/bin/env python3

"""
Author: A.R.
Version: 0.003b Raw Beta ;-)
Date: 26 October 2024
License: MIT
"""

import os
import math
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

# Define file signatures for known file types
FILE_SIGNATURES = {
    '.exe': [b'MZ'],  # Windows executable
    '.dll': [b'MZ'],  # Windows DLL
    '.jpg': [b'\xFF\xD8\xFF'],  # JPEG image
    '.jpeg': [b'\xFF\xD8\xFF'],  # JPEG image
    '.png': [b'\x89PNG\r\n\x1a\n'],  # PNG image
    '.pdf': [b'%PDF'],  # PDF document
    '.zip': [b'PK\x03\x04'],  # ZIP archive
    '.tar': [b'ustar'],  # TAR archive
    '.gz': [b'\x1F\x8B'],  # GZIP
    '.bz2': [b'BZh'],  # BZIP2
    '.7z': [b'7z\xBC\xAF\x27\x1C'],  # 7z archive
    '.rar': [b'Rar!\x1A\x07\x00'],  # RAR archive
    '.mp3': [b'ID3'],  # MP3 audio
    '.mp4': [b'\x00\x00\x00\x18ftypmp42'],  # MP4 video
    '.dmg': [b'koly'],  # Apple Disk Image
    '.sqlite': [b'SQLite format 3\x00'],  # SQLite database
    '.deb': [b'!<arch>\ndebian-binary'],  # Debian package
    '.rpm': [b'\xed\xab\xee\xdb'],  # RPM package
    '.ps': [b'%!PS'],  # PostScript
    '.psd': [b'8BPS'],  # Adobe Photoshop
    '.flv': [b'FLV\x01'],  # Flash Video
    '.swf': [b'CWS', b'FWS'],  # Shockwave Flash
    '.midi': [b'MThd'],  # MIDI
    '.mov': [b'\x00\x00\x00\x14ftypqt'],  # QuickTime MOV
    '.avi': [b'RIFF'],  # AVI video
    '.bmp': [b'BM'],  # Bitmap image
    '.gif': [b'GIF87a', b'GIF89a'],  # GIF image
    '.ogg': [b'OggS'],  # OGG audio
    '.flac': [b'fLaC'],  # FLAC audio
    '.mkv': [b'\x1A\x45\xDF\xA3'],  # Matroska video
    '.epub': [b'PK\x03\x04'],  # ePub
    '.jar': [b'PK\x03\x04'],  # Java Archive
    '.class': [b'\xCA\xFE\xBA\xBE'],  # Java Class
    '.apk': [b'PK\x03\x04'],  # Android package
    '.crx': [b'Cr24'],  # Chrome extension
    '.vmdk': [b'KDMV'],  # VMware virtual disk
    '.vhd': [b'conectix'],  # Virtual Hard Disk
    '.pem': [b'-----BEGIN '],  # PEM certificates
    '.der': [b'\x30\x82'],  # DER certificate
    '.pfx': [b'\x30\x82'],  # PKCS#12 certificate
    '.csr': [b'-----BEGIN CERTIFICATE REQUEST-----'],  # Certificate request
    '.xz': [b'\xFD7zXZ\x00'],  # XZ compressed
    '.zst': [b'\x28\xB5\x2F\xFD'],  # Zstandard compressed
    '.vcf': [b'BEGIN:VCARD'],  # vCard
    '.pcap': [b'\xD4\xC3\xB2\xA1'],  # Packet capture
    '.bat': [b'@echo'],  # Batch file
    '.ics': [b'BEGIN:VCALENDAR'],  # Calendar file
    '.m3u': [b'#EXTM3U'],  # Playlist file
    '.cab': [b'MSCF'],  # Microsoft Cabinet
    '.asf': [b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'],  # ASF/WMV
    '.wav': [b'RIFF', b'WAVE'],  # WAV audio
    '.tar.gz': [b'\x1F\x8B'],  # Compressed tar
    '.pkg': [b'\x1F\xA0'],  # Package format (varies)
    '.svg': [b'<?xml '],  # Scalable Vector Graphics
    '.eps': [b'%!PS-Adobe'],  # Encapsulated PostScript
    '.m4a': [b'\x00\x00\x00\x18ftypM4A'],  # M4A audio
    '.crt': [b'-----BEGIN CERTIFICATE-----'],  # X.509 cert
    '.p12': [b'\x30\x82'],  # PKCS#12 cert
    '.elf': [b'\x7FELF'],  # ELF executable
    '.ico': [b'\x00\x00\x01\x00'],  # Icon file
    '.qbw': [b'\x00\x00\x00\x00\x00\x00\x01\x00\x4D\x44\x4D\x50'],  # QuickBooks
    '.vcxproj': [b'<?xml'],  # Visual Studio project
    '.vsd': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],  # Visio document
    '.mdb': [b'\x00\x01\x00\x00Standard Jet DB'],  # Access DB
    '.pub': [b'\x30\x82'],  # Public key (DER)
    '.ova': [b'\x4F\x56\x46\x09\x00\x00\x00\x00'],  # Open Virtual Appliance
    '.vdi': [b'\x3C\x3F\x78\x6D\x6C'],  # VirtualBox disk image
    '.vhdx': [b'\x76\x68\x64\x78\x62\x64\x66'],  # Hyper-V VHDX
    '.inf': [b'[Version]'],  # Installation info file
    '.hlp': [b'0x0F1F'],  # Windows help file
    '.cfg': [b'\x3C\x3F\x78\x6D\x6C'],  # Config file (XML-based)
    '.iso': [b'\x43\x44\x30\x30\x31'],  # ISO 9660 CD
    '.bz': [b'\x42\x5A\x68'],  # BZip archive
    '.pak': [b'\x55\x4E\x52\x45\x41\x4C'],  # Packed file
    '.arj': [b'\x60\xEA'],  # ARJ archive
    '.ace': [b'\x2A\x2A\x41\x43\x45\x2A\x2A'],  # ACE archive
    '.bin': [b'\xCA\xFE\xBA\xBE'],  # Binary
    '.mac': [b'\x00\x00\x00\x0C\x4D\x41\x43\x20\x54\x49\x4D\x45'],  # Macintosh format
    '.dylib': [b'\xCF\xFA\xED\xFE'],  # Mac OS library
    '.jnlp': [b'<?xml version="1.0'],  # Java Network Launch
    '.m4v': [b'\x00\x00\x00\x18ftypM4V'],  # iTunes video
    '.m2ts': [b'\x47'],  # MPEG transport stream
    '.ts': [b'\x47'],  # MPEG transport stream
    '.cda': [b'\x43\x44\x30\x30\x31'],  # CD Audio
    '.ram': [b'\x2E\x52\x4D\x46\x00\x00\x00'],  # Real Audio
    '.ra': [b'\x2E\x52\x4D\x46'],  # Real Audio
    '.rv': [b'\x2E\x52\x4D\x46'],  # Real Video
    '.pdb': [b'Microsoft C/C++ MSF'],  # Program Database
    '.lnk': [b'\x4C\x00\x00\x00'],  # Shortcut file
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
