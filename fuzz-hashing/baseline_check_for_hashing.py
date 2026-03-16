import os
import yara
import csv
import py7zr
from tqdm import tqdm

# --- paths need to note for code ---
SAMPLES_DIR = "/home/ubuntu/malware-lab/samples/extracted"
BICLUSTER_DIR = "/home/ubuntu/malware-lab/yara-rules/web-yara"
YARGEN_DIR = "/home/ubuntu/yara-lab/rule_library/generated"
OUTPUT_CSV = "/home/ubuntu/malware-lab/rachel-tests/baseline_deep_comparison.csv"
MISSED_FILES_LOG = "/home/ubuntu/malware-lab/rachel-tests/target_files_for_fuzzy.txt"

def load_rules(name, directory):
    print(f"[+] Loading {name} rules...")
    valid_rules = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith((".yar", ".yara")):
                full_path = os.path.join(root, f)
                try:
                    yara.compile(filepath=full_path)
                    valid_rules.append(full_path)
                except:
                    continue
    if not valid_rules: return None
    yara_map = {f"ns_{i}": path for i, path in enumerate(valid_rules)}
    return yara.compile(filepaths=yara_map)

# --- initialise groups of yara rules ---
rules_bi = load_rules("Bi-clustering", BICLUSTER_DIR)
rules_gen = load_rules("yarGen", YARGEN_DIR)

stats = {"total": 0, "bi_hits": 0, "gen_hits": 0, "both": 0, "misses": 0}
category_stats = {} 

os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

# --- scanning yara against amwlare ---
with open(OUTPUT_CSV, 'w', newline='') as csv_file, open(MISSED_FILES_LOG, 'w') as missed_log:
    writer = csv.writer(csv_file)
    writer.writerow(['File_Path', 'Grouping', 'BiCluster_Hit', 'yarGen_Hit', 'Status'])

    physical_files = []
    for root, _, files in os.walk(SAMPLES_DIR):
        for f in files:
            physical_files.append(os.path.join(root, f))

    for file_path in tqdm(physical_files, desc="Running Baseline"):
        # FIXED: Use os.path.relpath
        grouping = os.path.relpath(file_path, SAMPLES_DIR).split(os.sep)[0]
        if grouping not in category_stats:
            category_stats[grouping] = {"total": 0, "misses": 0}

        def check_content(content, display_name, group):
            stats["total"] += 1
            category_stats[group]["total"] += 1
            
            # check for Bi-Clustering Rules
            if rules_bi:
                matches_bi = rules_bi.match(data=content)
                h_bi = bool(matches_bi)
            else:
                h_bi = False

            # check for yarGen Rules
            if rules_gen:
                matches_gen = rules_gen.match(data=content)
                h_gen = bool(matches_gen)
            else:
                h_gen = False
            
            if h_bi: stats["bi_hits"] += 1
            if h_gen: stats["gen_hits"] += 1
            if h_bi and h_gen: stats["both"] += 1
            
            if not h_bi and not h_gen:
                stats["misses"] += 1
                category_stats[group]["misses"] += 1
                missed_log.write(f"{display_name}\n")
                writer.writerow([display_name, group, 0, 0, "MISS"])
            else:
                writer.writerow([display_name, group, int(h_bi), int(h_gen), "DETECTED"])

        try:
            if file_path.endswith(".7z"):
                with py7zr.SevenZipFile(file_path, mode='r') as archive:
                    for name, data in archive.readall().items():
                        check_content(data.read(), f"{os.path.basename(file_path)}/{name}", grouping)
            else:
                with open(file_path, 'rb') as f:
                    check_content(f.read(), file_path, grouping)
        except:
            continue

# --- final output of report ---
print("\n" + "="*70)
print(f"{'THREAT CATEGORY':<25} | {'TOTAL FILES':<12} | {'MISSES':<10} | {'DETECTION %'}")
print("-" * 70)

for cat, data in category_stats.items():
    det_rate = ((data['total'] - data['misses']) / data['total'] * 100) if data['total'] > 0 else 0
    print(f"{cat:<25} | {data['total']:<12} | {data['misses']:<10} | {det_rate:.2f}%")

print("-" * 70)
print(f"GRAND TOTAL MISSES (Target for Fuzzy): {stats['misses']}")
print("="*70)