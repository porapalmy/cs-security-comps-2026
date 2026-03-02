/*
    Core webshell detection rules
    Detects common webshell patterns and implementations
*/

rule Webshell_BasicPHPBehavior {
    meta:
        description = "Detects basic PHP webshell command execution behavior"
        author = "Webshell Detection Suite"
    strings:
        $php = "<?php" nocase
        $request1 = "$_REQUEST" nocase
        $request2 = "$_POST" nocase
        $request3 = "$_GET" nocase
        $request4 = "$_COOKIE" nocase
        $exec1 = "eval" nocase
        $exec2 = "system" nocase
        $exec3 = "passthru" nocase
        $exec4 = "exec" nocase
        $exec5 = "shell_exec" nocase
        $exec6 = "proc_open" nocase
    condition:
        $php and (any of ($request*)) and (any of ($exec*))
}

rule Webshell_FileUpload {
    meta:
        description = "Detects webshell file upload functionality"
        author = "Webshell Detection Suite"
    strings:
        $php = "<?php" nocase
        $files = "$_FILES" nocase
        $moved = "move_uploaded_file" nocase
        $copy = "copy(" nocase
        $rename = "rename(" nocase
        $ext1 = ".php" nocase
        $ext2 = ".phtml" nocase
        $ext3 = ".php3" nocase
        $ext4 = ".php4" nocase
        $ext5 = ".php5" nocase
    condition:
        $php and (any of ($files, $moved, $copy, $rename)) and (any of ($ext*))
}

rule Webshell_ReverseShell {
    meta:
        description = "Detects reverse shell creation"
        author = "Webshell Detection Suite"
    strings:
        $socket = "socket_create" nocase
        $connect = "socket_connect" nocase
        $connect2 = "fsockopen" nocase
        $dup2 = "dup2" nocase
        $proc = "proc_open" nocase
    condition:
        ($socket and $connect) or ($connect2) or ($dup2 and $proc)
}

rule Webshell_DatabaseAccess {
    meta:
        description = "Detects webshell using database access for backdoor"
        author = "Webshell Detection Suite"
    strings:
        $query1 = "mysqli_query" nocase
        $query2 = "mysql_query" nocase
        $query3 = "PDO::" nocase
        $query4 = "mysql_" nocase
        $query5 = "mysqli_" nocase
        $exec1 = "eval" nocase
        $exec2 = "system" nocase
        $exec3 = "passthru" nocase
        $exec4 = "exec" nocase
        $php = "<?php" nocase
    condition:
        $php and (any of ($query*)) and (any of ($exec*))
}

rule Webshell_CommonName {
    meta:
        description = "Detects commonly named webshell files"
        author = "Webshell Detection Suite"
    strings:
        $shell = "shell.php" nocase
        $test = "test.php" nocase
        $upload = "upload.php" nocase
        $admin = "admin.php" nocase
        $config = "config.php" nocase
        $index = "index.php" nocase
        $connect = "connect.php" nocase
    condition:
        any of them
}
