/*
    Global definitions and shared patterns for web malware detection
*/

// Global variables and shared strings
private rule GlobalPatterns {
    strings:
        // PHP tags and variants
        $php_open = "<?php" nocase
        $php_short = "<?" nocase
        $php_short2 = "<?=" nocase
        
        // Common obfuscation functions
        $base64 = "base64_decode" nocase
        $eval = "eval" nocase
        $system = "system" nocase
        $exec = "exec" nocase
        $passthru = "passthru" nocase
        $shell_exec = "shell_exec" nocase
        $proc_open = "proc_open" nocase
        
        // File operations
        $file_get = "file_get_contents" nocase
        $file_put = "file_put_contents" nocase
        $fopen = "fopen" nocase
        $fwrite = "fwrite" nocase
        
        // String manipulation
        $preg_replace = "preg_replace" nocase
        $str_replace = "str_replace" nocase
        $strrev = "strrev" nocase
        $chr = "chr(" nocase
        
    condition:
        any of them
}

// Common web malware hosting patterns
private rule WebMalwareIndicators {
    strings:
        $http_get = "http_get" nocase
        $curl = "curl" nocase
        $fsockopen = "fsockopen" nocase
        $socket_create = "socket_create" nocase
        
    condition:
        any of them
}
