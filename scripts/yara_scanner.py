#!/usr/bin/env python3
"""
YARA Threat Scanner
Scans files/directories using ALL YARA rules in a folder
Author: Tolstiak Marharyta 
"""

import os
import sys
import subprocess
import json
from datetime import datetime
from pathlib import Path

# ============================================================
# FUNCTIONS
# ============================================================

def check_yara_installed():
    """Check if YARA is installed on the system"""
    try:
        subprocess.run(["yara", "--version"], 
                      capture_output=True, 
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(" ERROR: YARA is not installed or not in PATH")
        print("   Download from: https://github.com/VirusTotal/yara/releases")
        return False

def get_all_rules(rules_dir):
    """
    Get all .yar files from the rules directory
    
    Args:
        rules_dir: Path to directory containing YARA rules
    
    Returns:
        List of rule file paths
    """
    rules_dir = Path(rules_dir)
    if not rules_dir.exists():
        return []
    
    # Find all .yar and .yara files
    rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    return rule_files

def scan_with_rule(rule_path, target):
    """
    Scan target with a specific YARA rule
    
    Args:
        rule_path: Path to .yar file
        target: File or directory to scan
    
    Returns:
        List of matches, each match is a dict
    """
    matches = []
    
    try:
        # Run YARA command
        cmd = ["yara", "-r", str(rule_path), str(target)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Parse output
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                # YARA output format: "rule_name file_path"
                parts = line.split()
                if len(parts) >= 2:
                    matches.append({
                        "rule": parts[0],
                        "file": parts[1],
                        "rule_file": rule_path.name
                    })
                    
    except subprocess.TimeoutExpired:
        print(f"   Timeout scanning with {rule_path.name}")
    except Exception as e:
        print(f"   Error with {rule_path.name}: {e}")
    
    return matches

def scan_all(rules_dir, target):
    """
    Scan target with ALL rules found in rules_dir
    
    Args:
        rules_dir: Directory containing YARA rules
        target: File or directory to scan
    
    Returns:
        List of all matches
    """
    all_matches = []
    
    # Get all rule files
    rule_files = get_all_rules(rules_dir)
    
    if not rule_files:
        print(f"    No .yar files found in {rules_dir}")
        return []
    
    print(f"    Found {len(rule_files)} rule(s):")
    for rf in rule_files:
        print(f"      - {rf.name}")
    print()
    
    for rule_path in rule_files:
        print(f"   🔍 Scanning with: {rule_path.name}")
        matches = scan_with_rule(rule_path, target)
        
        if matches:
            print(f"       Found {len(matches)} match(es)!")
            for match in matches:
                # Add basic metadata
                match["severity"] = "HIGH"  # Default severity
                match["mitre"] = "TBD"
                match["recommendation"] = "Review file and investigate"
            all_matches.extend(matches)
    
    return all_matches

def print_alert(match):
    """Print a formatted alert to console"""
    print()
    print("=" * 60)
    print(f" [{match.get('severity', 'MEDIUM')}] ALERT: {match['rule']}")
    print("=" * 60)
    print(f"   File: {match['file']}")
    print(f"   Rule: {match['rule_file']}")
    print(f"   MITRE: {match.get('mitre', 'N/A')}")
    print(f"   Recommendation: {match.get('recommendation', 'Investigate immediately')}")
    print("=" * 60)

def save_report(matches, target, output_file):
    """
    Save scan results to JSON file for SIEM integration
    """
    report = {
        "scan_target": str(target),
        "scan_time": datetime.now().isoformat(),
        "total_matches": len(matches),
        "matches": matches
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n Report saved to: {output_file}")

def print_summary(matches, target):
    """Print scan summary"""
    print()
    print("=" * 60)
    print(" SCAN SUMMARY")
    print("=" * 60)
    print(f"   Target: {target}")
    print(f"   Total matches: {len(matches)}")
    
    if matches:
        print("\n   Matches by rule:")
        rule_counts = {}
        for m in matches:
            rule_name = m.get("rule", "UNKNOWN")
            rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
        for rule, count in rule_counts.items():
            print(f"      - {rule}: {count} match(es)")
    else:
        print("\n   No threats found!")
    
    print("=" * 60)

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="YARA Threat Scanner - Scan files/directories for malware"
    )
    parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    parser.add_argument(
        "--rules-dir",
        default="./yara_rules",
        help="Directory containing YARA rules (default: ./yara_rules)"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="scan_report.json",
        help="Output JSON file (default: scan_report.json)"
    )
    
    args = parser.parse_args()
    
    # Check if YARA is installed
    if not check_yara_installed():
        return 1
    
    # Check if target exists
    target = Path(args.target)
    if not target.exists():
        print(f" ERROR: Target not found: {target}")
        return 1
    
    # Check if rules directory exists
    rules_dir = Path(args.rules_dir)
    if not rules_dir.exists():
        print(f" ERROR: Rules directory not found: {rules_dir}")
        return 1
    
    print("\n" + "=" * 60)
    print("  YARA THREAT SCANNER")
    print("=" * 60)
    print(f"   Target: {target}")
    print(f"   Rules directory: {rules_dir}")
    print()
    
    # Run scan
    matches = scan_all(rules_dir, target)
    
    # Print alerts for each match
    for match in matches:
        print_alert(match)
    
    # Print summary
    print_summary(matches, target)
    
    # Save report
    if matches:
        save_report(matches, target, args.output)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
