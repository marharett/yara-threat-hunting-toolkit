rule Banking_Trojan_Indicators {
    meta:
        description = "Detects banking trojans (Emotet, Trickbot, Qakbot)"
        author = "Tolstiak Marharyta"
        severity = "Critical"
        
    strings:
        // Emotet patterns
        $emotet1 = "emotet" ascii wide
        $emotet2 = "mswin" ascii
        
        // Trickbot patterns
        $trickbot1 = "trickbot" ascii wide
        $trickbot2 = "inject.dll" ascii
        
        // Qakbot patterns
        $qakbot1 = "qakbot" ascii
        $qakbot2 = "qb" ascii wide
        
        // Common banking trojan strings
        $banking = "webinject" ascii
        $banking2 = "formgrabber" ascii
        
    condition:
        ($emotet1 or $trickbot1 or $qakbot1) 
        or (2 of ($banking*))
}
