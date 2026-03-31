rule Suspicious_Domain {
    meta:
        description = "Generated YARA rule from IOCs"
        author = "Tolstiak Marharyta"
        date = "2026-03-31"
        severity = "High"
        
    strings:
        $domain_0 = "evil-domain.com"
        $domain_wide_0 = "evil-domain.com" wide
        
    condition:
        $domain_0 or $domain_wide_0
}
