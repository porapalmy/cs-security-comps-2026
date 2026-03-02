/*
    Obfuscation detection rules for web malware
    Identifies common encoding and obfuscation techniques
*/

rule Obfuscation_Base64Decoded {
    meta:
        description = "Detects base64_decode execution patterns"
        author = "Obfuscation Suite"
    strings:
        $base64 = "base64_decode" nocase
        $sus1 = "eval" nocase
        $sus2 = "system" nocase
        $sus3 = "passthru" nocase
        $sus4 = "exec" nocase
        $sus5 = "assert" nocase
        $sus6 = "create_function" nocase
    condition:
        $base64 and (any of ($sus*))
}

rule Obfuscation_EvalExecution {
    meta:
        description = "Detects eval() function usage"
        author = "Obfuscation Suite"
    strings:
        $eval = "eval(" nocase
        $base64 = "base64" nocase
        $gzuncompress = "gzuncompress" nocase
        $gzdeflate = "gzdeflate" nocase
        $chr = "chr(" nocase
        $ord = "ord(" nocase
    condition:
        $eval and (any of ($base64, $gzuncompress, $gzdeflate, $chr, $ord))
}

rule Obfuscation_VariableVariables {
    meta:
        description = "Detects PHP variable variables exploitation"
        author = "Obfuscation Suite"
    strings:
        $request1 = "$_REQUEST" nocase
        $request2 = "$_GET" nocase
        $request3 = "$_POST" nocase
        $request4 = "$_COOKIE" nocase
        $request5 = "$_FILES" nocase
        $varvar = "$$" nocase
    condition:
        $varvar and (any of ($request*))
}

rule Obfuscation_HexEncoded {
    meta:
        description = "Detects hex-encoded commands"
        author = "Obfuscation Suite"
    strings:
        $hex_pattern = "\\x"
        $eval1 = "eval" nocase
        $eval2 = "system" nocase
        $eval3 = "exec" nocase
        $eval4 = "passthru" nocase
        $eval5 = "assert" nocase
    condition:
        $hex_pattern and (any of ($eval*))
}

rule Obfuscation_StrReplaceChain {
    meta:
        description = "Detects str_replace chains used for obfuscation"
        author = "Obfuscation Suite"
    strings:
        $str_replace = "str_replace" nocase
    condition:
        #str_replace > 3
}

rule Obfuscation_CreateFunction {
    meta:
        description = "Detects create_function for dynamic code execution"
        author = "Obfuscation Suite"
    strings:
        $create = "create_function" nocase
    condition:
        $create
}

rule Obfuscation_Compression {
    meta:
        description = "Detects compressed code execution"
        author = "Obfuscation Suite"
    strings:
        $gzuncompress = "gzuncompress" nocase
        $gzdeflate = "gzdeflate" nocase
        $exec1 = "eval" nocase
        $exec2 = "system" nocase
        $exec3 = "passthru" nocase
        $exec4 = "exec" nocase
    condition:
        (any of ($gzuncompress, $gzdeflate)) and (any of ($exec*))
}
