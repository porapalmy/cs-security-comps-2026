import ppdeep
import os
import csv
import sqlite3
from tqdm import tqdm

# --- CONFIG ---
MISSED_FILES_LOG = "/home/ubuntu/malware-lab/rachel-tests/target_files_for_fuzzy.txt"
FUZZY_REPORT = "/home/ubuntu/malware-lab/rachel-tests/fuzzy_matches.csv"
DB_PATH = "/home/ubuntu/malware-lab/rachel-tests/malware_fuzzy.db"
SIMILARITY_THRESHOLD = 50  # Only report matches > 50%

def get_fuzzy_hash(filepath):
    """Calculates the CTPH (fuzzy hash) for a given file."""
    try:
        # ppdeep uses Adler-32 rolling hash and FNV-1a piecewise hashing
        return ppdeep.hash_from_file(filepath)
    except Exception as e:
        return None

#  LOAD AND HASH ---
if not os.path.exists(MISSED_FILES_LOG):
    print(f"[!] Error: {MISSED_FILES_LOG} not found. Run baseline_check.py first!")
    exit()

with open(MISSED_FILES_LOG, 'r') as f:
    # Clean up paths and ensure they exist on disk
    file_list = [line.strip() for line in f if os.path.exists(line.strip())]

print(f"[+] Generating fuzzy hashes for {len(file_list)} files...")
hashes = []
for path in tqdm(file_list, desc="Hashing"):
    h = get_fuzzy_hash(path)
    if h:
        hashes.append({'path': path, 'hash': h})

# DATABASE INDEXING (For Fallback)
print(f"[+] Syncing results to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Create table with chunk_size for faster lookups
cursor.execute('''
    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT,
        file_name TEXT,
        chunk_size INTEGER,
        fuzzy_hash TEXT
    )
''')

# Clear old data to ensure the DB reflects the latest 'Misses'
cursor.execute("DELETE FROM signatures") 

for item in hashes:
    h = item['hash']
    # Extract Chunk Size (the context-trigger threshold)
    try:
        chunk_size = int(h.split(':')[0])
        cursor.execute(
            "INSERT INTO signatures (file_path, file_name, chunk_size, fuzzy_hash) VALUES (?, ?, ?, ?)",
            (item['path'], os.path.basename(item['path']), chunk_size, h)
        )
    except (ValueError, IndexError):
        continue

conn.commit()
conn.close()

# CROSS-COMPARE (All-vs-all) ---
print(f"[+] Comparing hashes (Threshold: {SIMILARITY_THRESHOLD}%)...")
matches = []

# Using nested loops to compare every file against every other file
for i in range(len(hashes)):
    for j in range(i + 1, len(hashes)):
        # Calculate similarity score based on edit distance (Levenshtein)
        score = ppdeep.compare(hashes[i]['hash'], hashes[j]['hash'])
        
        if score >= SIMILARITY_THRESHOLD:
            matches.append([
                hashes[i]['path'], 
                hashes[j]['path'], 
                score,
                os.path.basename(hashes[i]['path']) == os.path.basename(hashes[j]['path'])
            ])

# SAVE CSV REPORT (for after_fuzzy.py) 
with open(FUZZY_REPORT, 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(['File_1', 'File_2', 'Similarity_Score', 'Same_Filename'])
    writer.writerows(matches)

print(f"\n{'='*60}")
print(f"FUZZY ANALYSIS COMPLETE")
print(f"Total Files Indexed in DB: {len(hashes)}")
print(f"Relationships Found: {len(matches)}")
print(f"Database saved to: {DB_PATH}")
print(f"CSV saved to: {FUZZY_REPORT}")
print(f"{'='*60}")