#!/usr/bin/env python3
"""
YARA Rule Generator
Creates YARA rules from IOCs (IPs, domains, hashes, strings)
Author: Tolstiak Marharyta
"""

import re
import os
from datetime import datetime

def sanitize_rule_name(name):
    """Make rule name safe for YARA"""
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if name and name[0].isdigit():
        name = f"rule_{name}"
    return name

def escape_string(s):
    """Escape quotes and backslashes for YARA"""
    s = s.replace('"', '\\"')
    s = s.replace('\\', '\\\\')
    return s

def detect_ioc_type(ioc):
    """Detect what type of IOC this is"""
    ioc = ioc.strip()
    
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, ioc):
        return 'ip', ioc
    
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(domain_pattern, ioc):
        return 'domain', ioc
    
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return 'md5', ioc.lower()
    
    if re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return 'sha1', ioc.lower()
    
    if re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return 'sha256', ioc.lower()
    
    return 'string', ioc

def format_hash_for_yara(hash_value):
    """Convert hash string to YARA hex format"""
    pairs = [hash_value[i:i+2] for i in range(0, len(hash_value), 2)]
    return ' '.join(pairs).upper()

def generate_yara_rule(rule_name, iocs, author="SOC Analyst", severity="Medium"):
    """Generate a YARA rule from a list of IOCs"""
    rule_name = sanitize_rule_name(rule_name)
    
    string_lines = []
    condition_parts = []
    string_counter = 0
    
    for ioc in iocs:
        ioc_type, value = detect_ioc_type(ioc)
        
        if ioc_type == 'ip':
            string_name = f"$ip_{string_counter}"
            string_lines.append(f'        {string_name} = "{value}"')
            condition_parts.append(string_name)
            
            hex_ip = ''.join(f'{int(octet):02X}' for octet in value.split('.'))
            string_name_hex = f"$ip_hex_{string_counter}"
            string_lines.append(f'        {string_name_hex} = {{ {hex_ip} }}')
            condition_parts.append(string_name_hex)
            string_counter += 1
            
        elif ioc_type == 'domain':
            string_name = f"$domain_{string_counter}"
            string_lines.append(f'        {string_name} = "{value}"')
            condition_parts.append(string_name)
            
            string_name_wide = f"$domain_wide_{string_counter}"
            string_lines.append(f'        {string_name_wide} = "{value}" wide')
            condition_parts.append(string_name_wide)
            string_counter += 1
            
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            string_name = f"${ioc_type}_{string_counter}"
            hex_pattern = format_hash_for_yara(value)
            string_lines.append(f'        {string_name} = {{ {hex_pattern} }}')
            condition_parts.append(string_name)
            string_counter += 1
            
        else:
            string_name = f"$str_{string_counter}"
            escaped = escape_string(value)
            string_lines.append(f'        {string_name} = "{escaped}"')
            condition_parts.append(string_name)
            string_counter += 1
    
    if len(condition_parts) == 1:
        condition = condition_parts[0]
    else:
        condition = " or ".join(condition_parts)
    
    today = datetime.now().strftime("%Y-%m-%d")
    
    rule = f'''rule {rule_name} {{
    meta:
        description = "Generated YARA rule from IOCs"
        author = "{author}"
        date = "{today}"
        severity = "{severity}"
        
    strings:
'''
    
    rule += "\n".join(string_lines)
    
    rule += f'''
        
    condition:
        {condition}
}}
'''
    
    return rule

def save_rule(rule, filename, output_dir=None):
    """
    Save rule to a file
    
    Args:
        rule: The YARA rule text
        filename: Name of the file
        output_dir: Directory to save to (default: current directory)
    """
    # If output_dir is specified, use it
    if output_dir:
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
    else:
        # Use current directory
        filepath = filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(rule)
    
    print(f" Rule saved to: {filepath}")
    return filepath

# ============================================================
# MAIN - CREATE RULES IN THE CORRECT FOLDER
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print(" YARA RULE GENERATOR")
    print("=" * 60)
    
    # Define the output directory (yara_rules folder in the project)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)  # Go up one level to YARA Toolkit
    output_dir = os.path.join(project_dir, "yara_rules")
    
    # Example 1: Banking threat IOCs
    print(" Example 1: Creating Banking Threat rule\n")
    
    iocs = [
        "185.67.12.34",
        "malicious-c2.xyz",
        "d41d8cd98f00b204e9800998ecf8427e",
        "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
    ]
    
    rule1 = generate_yara_rule(
        rule_name="Banking_Threat_IOCs",
        iocs=iocs,
        author="Tolstiak Marharyta",
        severity="Critical"
    )
    
    print(rule1)
    save_rule(rule1, "banking_threat_iocs.yar", output_dir)
    
    # Example 2: Simple domain rule
    print("\n Example 2: Creating Simple Domain rule\n")
    
    rule2 = generate_yara_rule(
        rule_name="Suspicious_Domain",
        iocs=["evil-domain.com"],
        author="Tolstiak Marharyta",
        severity="High"
    )
    
    print(rule2)
    save_rule(rule2, "suspicious_domain.yar", output_dir)
    
    print("\n" + "=" * 60)
    print(" DONE! Files created in:")
    print(f"   {output_dir}")
    print("=" * 60)