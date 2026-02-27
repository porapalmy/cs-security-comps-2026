/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__twitter/phish__twitter_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__twitter
   Reference: phish__twitter phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__twitter_home_ubuntu_malware_lab_samples_extracted_phishing_Twitter_malware_fake_link_master_malware_fake_link_master_index {
   meta:
      description = "phish__twitter - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__twitter phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "100f45abc517399d8d644b14e09bc34dd56fa170cbf67cac975dc46732d09c6d"
   strings:
      $s1 = "    header(\"Content-Length:\".filesize($file));" fullword ascii /* score: '15.00'*/
      $s2 = "    header(\"Content-Type: application/octet-stream\"); // application/octet-stream - application/zip" fullword ascii /* score: '13.00'*/
      $s3 = "    header(\"Content-Transfer-Encoding: Binary\");" fullword ascii /* score: '12.00'*/
      $s4 = "$file = \"some.txt\";" fullword ascii /* score: '11.00'*/
      $s5 = "    header(\"Content-Disposition: attachment; filename=\" . basename($file));" fullword ascii /* score: '9.00'*/
      $s6 = " internet explorer" fullword ascii /* score: '6.00'*/
      $s7 = "    header($_SERVER[\"SERVER_PROTOCOL\"] . \" 200 OK\");" fullword ascii /* score: '4.00'*/
      $s8 = "    header(\"Cache-Control: public\"); // " fullword ascii /* score: '3.00'*/
      $s9 = "    readfile($file);" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule Информация {
   meta:
      description = "phish__twitter - file Информация.txt"
      author = "Comps Team Malware Lab"
      reference = "phish__twitter phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "23b2b88e531c84667a585c934aefac9c6fd1b451e05c1c34866056a2b85f7abe"
   strings:
      $s1 = "https://youtu.be/6rZDZ15lak4" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0xa2d0 and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__twitter_home_ubuntu_malware_lab_samples_extracted_phishing_Twitter_index {
   meta:
      description = "phish__twitter - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__twitter phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__twitter_home_ubuntu_malware_lab_samples_extracted_phishing_Twitter_login {
   meta:
      description = "phish__twitter - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__twitter phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "39660ba1a950d9a279f9e7968ae4c2ac5b4f57a78a65267c6153b5f9ce11463b"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['usernameOrEmail'] . \" Pass: \" . $_POST['pass'] . \"\\n\", FILE_AP" ascii /* score: '24.00'*/
      $s2 = "header('Location: https://twitter.com/');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__twitter_home_ubuntu_malware_lab_samples_extracted_phishing_Twitter_login_2 {
   meta:
      description = "phish__twitter - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__twitter phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "f4c0ece762ccc9cc12861b7d39265f9f61d0abf95a2854158309e94371098f64"
   strings:
      $x1 = "      <input type=\"hidden\" id=\"init-data\" class=\"json-data\" value=\"{&quot;keyboardShortcuts&quot;:[{&quot;name&quot;:&quo" ascii /* score: '45.00'*/
      $x2 = "    !function(){function e(e){if(e||(e=window.event),!e)return!1;if(e.timestamp=(new Date).getTime(),!e.target&&e.srcElement&&(e" ascii /* score: '34.00'*/
      $x3 = "ter.com/login?lang=gl\"><link rel=\"alternate\" hreflang=\"ro\" href=\"https://twitter.com/login?lang=ro\"><link rel=\"alternate" ascii /* score: '31.00'*/
      $x4 = "    <noscript><meta http-equiv=\"refresh\" content=\"0; URL=https://mobile.twitter.com/i/nojs_router?path=%2Flogin\"></noscript>" ascii /* score: '31.00'*/
      $s5 = " hreflang=\"sr\" href=\"https://twitter.com/login?lang=sr\"><link rel=\"alternate\" hreflang=\"sk\" href=\"https://twitter.com/l" ascii /* score: '28.00'*/
      $s6 = "ng=\"hr\" href=\"https://twitter.com/login?lang=hr\"><link rel=\"alternate\" hreflang=\"en-gb\" href=\"https://twitter.com/login" ascii /* score: '28.00'*/
      $s7 = "=sk\"><link rel=\"alternate\" hreflang=\"gu\" href=\"https://twitter.com/login?lang=gu\"><link rel=\"alternate\" hreflang=\"mr\"" ascii /* score: '28.00'*/
      $s8 = " href=\"https://twitter.com/login?lang=zh-cn\"><link rel=\"alternate\" hreflang=\"hi\" href=\"https://twitter.com/login?lang=hi" ascii /* score: '28.00'*/
      $s9 = "s://twitter.com/login?lang=mr\"><link rel=\"alternate\" hreflang=\"ta\" href=\"https://twitter.com/login?lang=ta\"><link rel=\"a" ascii /* score: '28.00'*/
      $s10 = "hreflang=\"pt\" href=\"https://twitter.com/login?lang=pt\"><link rel=\"alternate\" hreflang=\"ko\" href=\"https://twitter.com/lo" ascii /* score: '28.00'*/
      $s11 = "://twitter.com/login?lang=ru\"><link rel=\"alternate\" hreflang=\"nl\" href=\"https://twitter.com/login?lang=nl\"><link rel=\"al" ascii /* score: '28.00'*/
      $s12 = "//twitter.com/login?lang=it\"><link rel=\"alternate\" hreflang=\"id\" href=\"https://twitter.com/login?lang=id\"><link rel=\"alt" ascii /* score: '28.00'*/
      $s13 = "rel=\"alternate\" hreflang=\"no\" href=\"https://twitter.com/login?lang=no\"><link rel=\"alternate\" hreflang=\"sv\" href=\"http" ascii /* score: '28.00'*/
      $s14 = "reflang=\"ja\" href=\"https://twitter.com/login?lang=ja\"><link rel=\"alternate\" hreflang=\"es\" href=\"https://twitter.com/log" ascii /* score: '28.00'*/
      $s15 = "\"da\" href=\"https://twitter.com/login?lang=da\"><link rel=\"alternate\" hreflang=\"pl\" href=\"https://twitter.com/login?lang=" ascii /* score: '28.00'*/
      $s16 = "ng=ms\"><link rel=\"alternate\" hreflang=\"zh-tw\" href=\"https://twitter.com/login?lang=zh-tw\"><link rel=\"alternate\" hreflan" ascii /* score: '28.00'*/
      $s17 = " hreflang=\"fil\" href=\"https://twitter.com/login?lang=fil\"><link rel=\"alternate\" hreflang=\"ms\" href=\"https://twitter.com" ascii /* score: '28.00'*/
      $s18 = "  <link rel=\"alternate\" hreflang=\"fr\" href=\"https://twitter.com/login?lang=fr\"><link rel=\"alternate\" hreflang=\"en\" hre" ascii /* score: '28.00'*/
      $s19 = "s\"><link rel=\"alternate\" hreflang=\"de\" href=\"https://twitter.com/login?lang=de\"><link rel=\"alternate\" hreflang=\"it\" h" ascii /* score: '28.00'*/
      $s20 = "gb\"><link rel=\"alternate\" hreflang=\"vi\" href=\"https://twitter.com/login?lang=vi\"><link rel=\"alternate\" hreflang=\"bn\" " ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x3c0a and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__twitter_home_ubuntu_malware_lab_samples_extracted_phishing_Twitter_ip {
   meta:
      description = "phish__twitter - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__twitter phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d0f8f3e7985a87e0beb1699ccfadab7268ffc777c05fa1dfcc35a16b6d393947"
   strings:
      $s1 = "$useragent = \" User-Agent: \";" fullword ascii /* score: '17.00'*/
      $s2 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s3 = "elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))" fullword ascii /* score: '12.00'*/
      $s4 = "fwrite($fp, $useragent);" fullword ascii /* score: '12.00'*/
      $s5 = "$file = 'ip.txt';" fullword ascii /* score: '11.00'*/
      $s6 = "      $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'].\"\\r\\n\";" fullword ascii /* score: '10.00'*/
      $s7 = "fwrite($fp, $victim);" fullword ascii /* score: '9.00'*/
      $s8 = "$victim = \"IP: \";" fullword ascii /* score: '9.00'*/
      $s9 = "fwrite($fp, $ipaddress);" fullword ascii /* score: '7.00'*/
      $s10 = "if (!empty($_SERVER['HTTP_CLIENT_IP']))" fullword ascii /* score: '7.00'*/
      $s11 = "      $ipaddress = $_SERVER['HTTP_CLIENT_IP'].\"\\r\\n\";" fullword ascii /* score: '5.00'*/
      $s12 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s13 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
