rule Suspicious_PowerShell_Command {
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Tolstiak Marharyta"
        severity = "High"
        mitre_attack = "T1059.001"
        
    strings:
        $ps1 = /powershell\s+\-enc/i
        $ps2 = /powershell\s+\-e\s+[A-Za-z0-9+\/]{50,}/i
        $ps3 = "IEX(New-Object Net.WebClient).DownloadString"
        $ps4 = "-WindowStyle Hidden"
        $ps5 = "-ExecutionPolicy Bypass"
        
    condition:
        2 of ($ps*)
}
