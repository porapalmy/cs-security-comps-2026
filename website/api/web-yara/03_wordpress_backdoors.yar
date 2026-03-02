/*
    WordPress-specific backdoor detection rules
    Targets WP plugins, themes, and core file modifications
*/

rule WordPress_BadPlugin {
    meta:
        description = "Detects malicious WordPress plugin patterns"
        author = "WordPress Security Suite"
    strings:
        $header = "Plugin Name:" nocase
        $exec1 = "eval" nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $exec4 = "exec(" nocase
        $exec5 = "shell_exec(" nocase
        $hook = "add_action" nocase
    condition:
        $header and (any of ($exec*)) and $hook
}

rule WordPress_BadTheme {
    meta:
        description = "Detects malicious WordPress theme patterns"
        author = "WordPress Security Suite"
    strings:
        $header = "Theme Name:" nocase
        $exec1 = "eval" nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $exec4 = "exec(" nocase
        $exec5 = "shell_exec(" nocase
    condition:
        $header and (any of ($exec*))
}

rule WordPress_FunctionsPhpBackdoor {
    meta:
        description = "Detects backdoors injected in functions.php"
        author = "WordPress Security Suite"
    strings:
        $file = "functions.php" nocase
        $sus1 = "eval" nocase
        $sus2 = "system(" nocase
        $sus3 = "$_REQUEST" nocase
        $sus4 = "$_GET" nocase
        $sus5 = "$_POST" nocase
    condition:
        $file and (any of ($sus*))
}

rule WordPress_WpConfigModified {
    meta:
        description = "Detects malicious modifications to wp-config.php"
        author = "WordPress Security Suite"
    strings:
        $config = "wp-config.php" nocase
        $exec1 = "eval" nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $exec4 = "exec(" nocase
    condition:
        $config and (any of ($exec*))
}

rule WordPress_PluginVulnerability {
    meta:
        description = "Detects exploitation of known WordPress vulnerabilities"
        author = "WordPress Security Suite"
    strings:
        $plugin = "wp-content/plugins/" nocase
        $lfi1 = "../../../etc/passwd" nocase
        $lfi2 = "../../wp-config.php" nocase
        $rfi1 = "http://" nocase
        $rfi2 = "https://" nocase
    condition:
        $plugin and ((any of ($lfi*)) or (any of ($rfi*)))
}

rule WordPress_AdminUserCreation {
    meta:
        description = "Detects creation of hidden WordPress admin users"
        author = "WordPress Security Suite"
    strings:
        $table1 = "wp_users" nocase
        $table2 = "wp_usermeta" nocase
        $insert = "INSERT INTO" nocase
        $hidden1 = "role=0" nocase
        $hidden2 = "user_registered" nocase
    condition:
        (any of ($table*)) and $insert and (any of ($hidden*))
}

rule WordPress_SqlInjection {
    meta:
        description = "Detects SQL injection in WP queries"
        author = "WordPress Security Suite"
    strings:
        $wpdb = "$wpdb->get_results" nocase
        $sql = "UNION" nocase
        $request1 = "$_REQUEST" nocase
        $request2 = "$_GET" nocase
        $request3 = "$_POST" nocase
    condition:
        $wpdb and $sql and (any of ($request*))
}
