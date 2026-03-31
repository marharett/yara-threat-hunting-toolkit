rule Banking_Threat_IOCs {
    meta:
        description = "Generated YARA rule from IOCs"
        author = "Tolstiak Marharyta"
        date = "2026-03-31"
        severity = "Critical"
        
    strings:
        $ip_0 = "185.67.12.34"
        $ip_hex_0 = { B9430C22 }
        $domain_1 = "malicious-c2.xyz"
        $domain_wide_1 = "malicious-c2.xyz" wide
        $md5_2 = { D4 1D 8C D9 8F 00 B2 04 E9 80 09 98 EC F8 42 7E }
        $str_3 = "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0"
        
    condition:
        $ip_0 or $ip_hex_0 or $domain_1 or $domain_wide_1 or $md5_2 or $str_3
}
