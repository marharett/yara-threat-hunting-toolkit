rule Suspicious_Crypto_API_Calls {
    meta:
        description = "Detects suspicious cryptographic API calls"
        author = "Tolstiak Marharyta"
        severity = "Medium"
        
    strings:
        // Windows Crypto API
        $crypt_acquire = "CryptAcquireContextA" ascii
        $crypt_derive = "CryptDeriveKey" ascii
        $crypt_encrypt = "CryptEncrypt" ascii
        $crypt_decrypt = "CryptDecrypt" ascii
        
        // CNG API
        $bcrypt_encrypt = "BCryptEncrypt" ascii
        $bcrypt_decrypt = "BCryptDecrypt" ascii
        
        // Ransomware specific
        $ransom_note = "DECRYPT" ascii wide
        $ransom_ext = ".encrypted" ascii
        
    condition:
        (3 of ($crypt*) or 2 of ($bcrypt*)) 
        and ($ransom_note or $ransom_ext)
}

