#!/usr/bin/env python3
"""
Benchmark script for YARA rule performance
Measures detection rates and false positives across malware samples
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime
import argparse

class YARARuleBenchmark:
    def __init__(self, samples_dir, rules_dir, output_dir=None):
        self.samples_dir = Path(samples_dir)
        self.rules_dir = Path(rules_dir)
        self.output_dir = Path(output_dir) if output_dir else Path("benchmark_results")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "rules_tested": [],
            "samples_scanned": 0,
            "total_detections": 0,
            "performance": {}
        }
        
    def setup(self):
        """Create output directory"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def get_yara_rules(self):
        """Get all YARA rule files"""
        return sorted(self.rules_dir.glob("*.yar"))
    
    def scan_sample(self, sample_path, rule_path):
        """Scan a sample with a specific rule"""
        try:
            cmd = ["yara", "-r", str(rule_path), str(sample_path)]
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            return result.stdout.decode('utf-8', errors='ignore'), result.returncode
        except subprocess.TimeoutExpired:
            return "TIMEOUT", -1
        except Exception as e:
            return str(e), -1
    
    def benchmark_rule(self, rule_path):
        """Benchmark a single rule against all samples"""
        rule_name = rule_path.name
        detections = 0
        false_positives = 0
        scan_times = []
        
        if not self.samples_dir.exists():
            print(f"Warning: Samples directory not found: {self.samples_dir}")
            return None
        
        for sample in self.samples_dir.rglob("*"):
            if sample.is_file():
                start_time = time.time()
                output, returncode = self.scan_sample(sample, rule_path)
                elapsed = time.time() - start_time
                scan_times.append(elapsed)
                
                if returncode == 0:  # Match found
                    detections += 1
                    # Simple heuristic: if it's in a 'benign' folder, it's FP
                    if "benign" in str(sample):
                        false_positives += 1
        
        if scan_times:
            avg_time = sum(scan_times) / len(scan_times)
            max_time = max(scan_times)
        else:
            avg_time = 0
            max_time = 0
        
        return {
            "rule": rule_name,
            "detections": detections,
            "false_positives": false_positives,
            "avg_scan_time": avg_time,
            "max_scan_time": max_time
        }
    
    def run_benchmark(self):
        """Run full benchmark"""
        self.setup()
        rules = self.get_yara_rules()
        
        print(f"[*] Benchmarking {len(rules)} YARA rules")
        print(f"[*] Samples directory: {self.samples_dir}")
        print(f"[*] Results will be saved to: {self.output_dir}")
        print()
        
        for rule_path in rules:
            print(f"[*] Benchmarking {rule_path.name}...", end=" ", flush=True)
            result = self.benchmark_rule(rule_path)
            
            if result:
                self.results["rules_tested"].append(result)
                self.results["total_detections"] += result["detections"]
                print(f"✓ ({result['detections']} detections, {result['false_positives']} FP)")
            else:
                print("✗ (skipped)")
        
        # Save results
        output_file = self.output_dir / "benchmark_results.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[✓] Results saved to {output_file}")
        self.print_summary()
        
    def print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*60)
        print("YARA RULE BENCHMARK SUMMARY")
        print("="*60)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Rules tested: {len(self.results['rules_tested'])}")
        print(f"Total detections: {self.results['total_detections']}")
        
        if self.results['rules_tested']:
            print("\nTop performing rules:")
            sorted_rules = sorted(self.results['rules_tested'], 
                                  key=lambda x: x['detections'], 
                                  reverse=True)
            for rule in sorted_rules[:5]:
                print(f"  • {rule['rule']}: {rule['detections']} detections, " + 
                      f"{rule['false_positives']} FP, ~{rule['avg_scan_time']:.3f}s/sample")

def main():
    parser = argparse.ArgumentParser(description="Benchmark YARA rules")
    parser.add_argument("samples_dir", help="Directory containing samples to scan")
    parser.add_argument("rules_dir", help="Directory containing YARA rules")
    parser.add_argument("-o", "--output", help="Output directory for results")
    
    args = parser.parse_args()
    
    benchmark = YARARuleBenchmark(args.samples_dir, args.rules_dir, args.output)
    benchmark.run_benchmark()

if __name__ == "__main__":
    main()
