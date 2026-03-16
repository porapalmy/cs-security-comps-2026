import pandas as pd
import os

# --- CONFIG ---
FUZZY_REPORT = "/home/ubuntu/malware-lab/rachel-tests/fuzzy_matches.csv"
SMOKING_GUN_OUTPUT = "/home/ubuntu/malware-lab/rachel-tests/smoking_guns_summary.txt"
MIN_SCORE = 70  # about 70 because not too low or high may change later
MAX_SCORE = 100

def find_renamed_mutations():
    if not os.path.exists(FUZZY_REPORT):
        print(f"[!] Error: {FUZZY_REPORT} not found. Run the fuzzy analysis first!")
        return

    # load the CSV results from previous script
    df = pd.read_csv(FUZZY_REPORT)

    # need to filter different filenames AND Similarity between 75-100
    results = df[
        (df['Similarity_Score'] >= MIN_SCORE) & 
        (df['Same_Filename'] == False)
    ].sort_values(by='Similarity_Score', ascending=False)

    with open(SMOKING_GUN_OUTPUT, 'w') as f:
        f.write("="*80 + "\n")
        f.write(f"EVASION REPORT: DIFFERENT FILENAMES WITH SIMILAR CONTENT ({MIN_SCORE}-{MAX_SCORE}%)\n")
        f.write("="*80 + "\n\n")
        
        if results.empty:
            f.write("No renamed mutations found in this range.\n")
        else:
            f.write(f"{'SCORE':<7} | {'FILENAME A':<25} | {'FILENAME B':<25}\n")
            f.write("-" * 80 + "\n")
            
            for _, row in results.iterrows():
                name_a = os.path.basename(row['File_1'])
                name_b = os.path.basename(row['File_2'])
                score = row['Similarity_Score']
                
                f.write(f"{score:<7}% | {name_a:<25} | {name_b:<25}\n")
                f.write(f"      PATH A: {row['File_1']}\n")
                f.write(f"      PATH B: {row['File_2']}\n")
                f.write("-" * 80 + "\n")

    print(f"[+] Found {len(results)} suspicious renamed pairs.")
    print(f"[+] Detailed report saved to: {SMOKING_GUN_OUTPUT}")

if __name__ == "__main__":
    find_renamed_mutations()