/*
    Injection attacks and iframe-based exploitation detection
    Identifies HTML injection, JavaScript injection, and iframe exploitation
*/

rule Injection_HTMLInjection {
    meta:
        description = "Detects HTML injection attacks"
        author = "Injection Detection Suite"
    strings:
        $req1 = "$_GET" nocase
        $req2 = "$_POST" nocase
        $req3 = "$_REQUEST" nocase
        $req4 = "$_COOKIE" nocase
        $inj1 = "<script" nocase
        $inj2 = "<iframe" nocase
        $inj3 = "<object" nocase
        $inj4 = "<embed" nocase
        $inj5 = "onclick=" nocase
        $inj6 = "onerror=" nocase
    condition:
        (any of ($req*)) and (any of ($inj*))
}

rule Injection_JavaScriptInjection {
    meta:
        description = "Detects JavaScript injection patterns"
        author = "Injection Detection Suite"
    strings:
        $req1 = "$_GET" nocase
        $req2 = "$_POST" nocase
        $req3 = "$_REQUEST" nocase
        $js1 = "<script>" nocase
        $js2 = "eval(" nocase
        $js3 = "Function(" nocase
        $js4 = "setTimeout" nocase
        $js5 = "setInterval" nocase
    condition:
        (any of ($req*)) and (any of ($js*))
}

rule Injection_SQLInjection {
    meta:
        description = "Detects SQL injection patterns"
        author = "Injection Detection Suite"
    strings:
        $req1 = "$_GET" nocase
        $req2 = "$_POST" nocase
        $req3 = "$_REQUEST" nocase
        $req4 = "$_COOKIE" nocase
        $sql1 = "UNION" nocase
        $sql2 = "SELECT" nocase
        $sql3 = "INSERT" nocase
        $sql4 = "UPDATE" nocase
        $sql5 = "DELETE" nocase
        $sql6 = "DROP" nocase
    condition:
        (any of ($req*)) and (any of ($sql*))
}

rule Injection_CommandInjection {
    meta:
        description = "Detects command injection patterns"
        author = "Injection Detection Suite"
    strings:
        $req1 = "$_GET" nocase
        $req2 = "$_POST" nocase
        $req3 = "$_REQUEST" nocase
        $shell1 = "system" nocase
        $shell2 = "exec" nocase
        $shell3 = "passthru" nocase
        $shell4 = "shell_exec" nocase
        $pipe1 = "|" nocase
        $pipe2 = ";" nocase
        $pipe3 = "&&" nocase
        $pipe4 = "||" nocase
    condition:
        (any of ($req*)) and (any of ($shell*)) and (any of ($pipe*))
}

rule Iframe_Malicious {
    meta:
        description = "Detects malicious iframe injections"
        author = "Iframe Detection Suite"
    strings:
        $iframe = "<iframe" nocase
        $hid1 = "display:none" nocase
        $hid2 = "visibility:hidden" nocase
        $hid3 = "width:0" nocase
        $hid4 = "height:0" nocase
        $src1 = "src=" nocase
        $src2 = "srcdoc=" nocase
    condition:
        $iframe and (any of ($hid*)) and (any of ($src*))
}

rule Iframe_Redirection {
    meta:
        description = "Detects iframe-based redirection exploits"
        author = "Iframe Detection Suite"
    strings:
        $iframe = "<iframe" nocase
        $loc1 = "window.location" nocase
        $loc2 = "top.location" nocase
        $loc3 = "parent.location" nocase
    condition:
        $iframe and (any of ($loc*))
}

rule Injection_FileInclusion {
    meta:
        description = "Detects Local File Inclusion (LFI) attacks"
        author = "Injection Detection Suite"
    strings:
        $inc1 = "include(" nocase
        $inc2 = "require(" nocase
        $inc3 = "include_once(" nocase
        $inc4 = "require_once(" nocase
        $req1 = "$_GET" nocase
        $req2 = "$_POST" nocase
        $req3 = "$_REQUEST" nocase
        $path1 = "../../../" nocase
        $path2 = "....\\" nocase
    condition:
        (any of ($inc*)) and (any of ($req*)) and (any of ($path*))
}

rule Injection_RemoteFileInclusion {
    meta:
        description = "Detects Remote File Inclusion (RFI) attacks"
        author = "Injection Detection Suite"
    strings:
        $inc1 = "include(" nocase
        $inc2 = "require(" nocase
        $inc3 = "include_once(" nocase
        $inc4 = "require_once(" nocase
        $req1 = "$_GET" nocase
        $req2 = "$_POST" nocase
        $req3 = "$_REQUEST" nocase
        $req4 = "$_COOKIE" nocase
        $rem1 = "http://" nocase
        $rem2 = "https://" nocase
        $rem3 = "ftp://" nocase
    condition:
        (any of ($inc*)) and (any of ($req*)) and (any of ($rem*))
}
