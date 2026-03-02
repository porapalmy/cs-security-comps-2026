/*
    Entropy-based detection for packed and highly obfuscated code
    Identifies suspicious patterns based on information density
*/

rule Entropy_HighLengthStrings {
    meta:
        description = "Detects files with unusually long encoded strings"
        author = "Entropy Detection Suite"
    condition:
        filesize > 1000 and filesize < 100000
}

rule Entropy_CompressedPayload {
    meta:
        description = "Detects compressed/packed payloads"
        author = "Entropy Detection Suite"
    strings:
        $gzip = { 1f 8b 08 }
        $compress = { 1f 9d }
        $bzip2 = { 42 5a }
    condition:
        any of them
}

rule Entropy_Base64Large {
    meta:
        description = "Detects large base64-encoded payloads"
        author = "Entropy Detection Suite"
    condition:
        filesize > 500 and filesize < 100000
}

rule Entropy_HexLarge {
    meta:
        description = "Detects large hex-encoded payloads"
        author = "Entropy Detection Suite"
    strings:
        $hex_pattern = "\\x"
    condition:
        #hex_pattern > 1000
}

rule Entropy_RandomStrings {
    meta:
        description = "Detects files with random-looking strings"
        author = "Entropy Detection Suite"
    condition:
        filesize > 1000 and filesize < 50000
}

rule Entropy_MixedEncoding {
    meta:
        description = "Detects mixed encoding techniques (obfuscation indicator)"
        author = "Entropy Detection Suite"
    strings:
        $base64 = "base64" nocase
        $hex = "\\x" nocase
        $chr = "chr(" nocase
    condition:
        (any of them) and filesize < 100000
}

rule Entropy_MinifiedCode {
    meta:
        description = "Detects suspicious minified/obfuscated code"
        author = "Entropy Detection Suite"
    strings:
        $exec1 = "eval" nocase
        $exec2 = "system" nocase
        $exec3 = "exec" nocase
        $exec4 = "passthru" nocase
    condition:
        (any of ($exec*)) and filesize < 50000
}
