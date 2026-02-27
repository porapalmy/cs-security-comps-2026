/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__default_php_functionality/phish__default_php_functionality_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__default_php_functionality
   Reference: phish__default_php_functionality phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__default_php_functionality_home_ubuntu_malware_lab_samples_extracted_phishing__Default_PHP_Functionality_index {
   meta:
      description = "phish__default_php_functionality - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__default_php_functionality phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__default_php_functionality_home_ubuntu_malware_lab_samples_extracted_phishing__Default_PHP_Functionality_login {
   meta:
      description = "phish__default_php_functionality - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__default_php_functionality phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d03b5d565482b5c331bcc4f0aa9c2bbe9a8488b5103656da97425bb4b54a3a03"
   strings:
      $s1 = "file_put_contents(\"informations.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_AP" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://google.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__default_php_functionality_home_ubuntu_malware_lab_samples_extracted_phishing__Default_PHP_Functionality_ip {
   meta:
      description = "phish__default_php_functionality - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__default_php_functionality phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "6410f67f05a6e99a6999076e39de44b578e8e83f66ffc2c74f7fbd34830e8159"
   strings:
      $s1 = "$useragent = \" User-Agent: \";" fullword ascii /* score: '17.00'*/
      $s2 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s3 = "fwrite($fp, $useragent);" fullword ascii /* score: '12.00'*/
      $s4 = "elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))" fullword ascii /* score: '12.00'*/
      $s5 = "$file = 'informations.txt';" fullword ascii /* score: '11.00'*/
      $s6 = "      $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'].\"\\r\\n\";" fullword ascii /* score: '10.00'*/
      $s7 = "$victim = \"IP: \";" fullword ascii /* score: '9.00'*/
      $s8 = "fwrite($fp, $victim);" fullword ascii /* score: '9.00'*/
      $s9 = "fwrite($fp, $ipaddress);" fullword ascii /* score: '7.00'*/
      $s10 = "if (!empty($_SERVER['HTTP_CLIENT_IP']))" fullword ascii /* score: '7.00'*/
      $s11 = "      $ipaddress = $_SERVER['HTTP_CLIENT_IP'].\"\\r\\n\";" fullword ascii /* score: '5.00'*/
      $s12 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s13 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
