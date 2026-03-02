/*
    Whitelist rules to reduce false positives
    Exempts legitimate code and known safe patterns
*/

rule Whitelist_PHPFrameworks {
    meta:
        description = "Whitelists common PHP frameworks"
        author = "Whitelist Suite"
    strings:
        $laravel = "Laravel" nocase
        $symfony = "Symfony" nocase
        $wordpress = "WordPress" nocase
        $drupal = "Drupal" nocase
        $joomla = "Joomla" nocase
        $codeigniter = "CodeIgniter" nocase
    condition:
        any of them
}

rule Whitelist_KnownLibraries {
    meta:
        description = "Whitelists legitimate PHP libraries"
        author = "Whitelist Suite"
    strings:
        $composer = "vendor/autoload.php" nocase
        $pear = "PEAR" nocase
        $phpunit = "PHPUnit" nocase
        $monolog = "Monolog" nocase
        $doctrine = "Doctrine" nocase
    condition:
        any of them
}

rule Whitelist_SecurityLibraries {
    meta:
        description = "Whitelists legitimate security and encoding libraries"
        author = "Whitelist Suite"
    strings:
        $phpseclib = "phpseclib" nocase
        $hash = "hash_hmac" nocase
        $crypt = "password_hash" nocase
        $openssl = "openssl_" nocase
    condition:
        any of them
}

rule Whitelist_CommonNonMalicious {
    meta:
        description = "Whitelists common legitimate patterns"
        author = "Whitelist Suite"
    strings:
        $jquery = "jquery" nocase
        $bootstrap = "bootstrap" nocase
        $angular = "angular" nocase
        $react = "react" nocase
        $vuejs = "vue" nocase
    condition:
        any of them
}

rule Whitelist_ContentManagement {
    meta:
        description = "Whitelists CMS-related legitimate functions"
        author = "Whitelist Suite"
    strings:
        $wp_version = "wp_version" nocase
        $get_theme = "get_theme" nocase
        $get_option = "get_option" nocase
        $do_action = "do_action" nocase
        $apply_filters = "apply_filters" nocase
    condition:
        any of them
}

rule Whitelist_TestingCode {
    meta:
        description = "Whitelists legitimate testing code"
        author = "Whitelist Suite"
    strings:
        $phpunit = "class.*Test" nocase
        $assert = "assert" nocase
        $test_dir = "/tests/" nocase
    condition:
        any of them
}

rule Whitelist_Debugging {
    meta:
        description = "Whitelists legitimate debugging code"
        author = "Whitelist Suite"
    strings:
        $var_dump = "var_dump" nocase
        $print_r = "print_r" nocase
        $debug = "debug" nocase
        $error_log = "error_log" nocase
    condition:
        any of them
}
