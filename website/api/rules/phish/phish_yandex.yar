/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__yandex/phish__yandex_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__yandex
   Reference: phish__yandex phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__yandex_home_ubuntu_malware_lab_samples_extracted_phishing_Yandex_index {
   meta:
      description = "phish__yandex - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yandex phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__yandex_home_ubuntu_malware_lab_samples_extracted_phishing_Yandex_login {
   meta:
      description = "phish__yandex - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yandex phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c57f5b2a2b8bcca0220b8b12a8c8d003092ed6f34a34b03f2825acd7ead99dc4"
   strings:
      $x1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['login'] . \" Pass: \" . $_POST['passwd'] . \"\\n\", FILE_APPEND);" fullword ascii /* score: '32.00'*/
      $s2 = "header('Location: https://yandex.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__yandex_home_ubuntu_malware_lab_samples_extracted_phishing_Yandex_login_2 {
   meta:
      description = "phish__yandex - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__yandex phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c5b547d17a78e427c7b2774a9e25fd3a032dce725f4abe01a26e845380f37b2c"
   strings:
      $x1 = "<html data-page-type=\"auth.new\" class=\"is-js_yes passport-Page passport-Page_dark is-inlinesvg_yes\" lang=\"en\"><head><scrip" ascii /* score: '60.00'*/
      $x2 = "Ya.Rum.init({beacon:true,clck:'https://yandex.ru/clck/click',slots:[\"phone_alias_as_login_etalon\",\"new_pwd_change_exp\",\"del" ascii /* score: '52.00'*/
      $x3 = "\" href=\"https://mail.yandex.com?noretpath=1\" data-reactid=\"67\">Return to&nbsp;service</a></div><iframe class=\"passport-Dom" ascii /* score: '42.00'*/
      $x4 = "Body-h\" data-uid=\"null\" data-login=\"null\" data-passporthost=\"&quot;passport.yandex.com&quot;\" data-static-url=\"https://y" ascii /* score: '36.00'*/
      $x5 = "1-8acf-2390758893ad\">var uid = null;var login = null;var passportHost = \"passport.yandex.com\";</script><!--[if IE]><script sr" ascii /* score: '36.00'*/
      $x6 = "\" href=\"https://passport.yandex.com/registration?from=mail&amp;origin=hostroot_homer_auth_v3_com&amp;retpath=https%3A%2F%2Fmai" ascii /* score: '31.00'*/
      $x7 = "\" href=\"https://passport.yandex.com/restoration?from=mail&amp;origin=hostroot_homer_auth_v3_com&amp;retpath=https%3A%2F%2Fmail" ascii /* score: '31.00'*/
      $s8 = " 2018, <!-- /react-text --><a class=\"link link_theme_normal\" href=\"//yandex.com\" tabindex=\"0\" data-reactid=\"77\"><span cl" ascii /* score: '29.00'*/
      $s9 = "\" href=\"https://passport.yandex.com/restoration?from=mail&amp;origin=hostroot_homer_auth_v3_com&amp;retpath=https%3A%2F%2Fmail" ascii /* score: '27.00'*/
      $s10 = "ethod=\"post\" target=\"iframe\" action=\"login.php\" class=\"passport-Domik-Form\" data-reactid=\"18\"><input name=\"real_retpa" ascii /* score: '27.00'*/
      $s11 = "\" href=\"https://passport.yandex.com/registration?from=mail&amp;origin=hostroot_homer_auth_v3_com&amp;retpath=https%3A%2F%2Fmai" ascii /* score: '27.00'*/
      $s12 = "href=\"https://yastatic.net/passport-frontend/0.2.88-20/public/css/auth.new.ie.css\"/><![endif]--><script nonce=\"dbe9dfa1-da49-" ascii /* score: '27.00'*/
      $s13 = "e\" content=\"IE=EmulateIE7,IE=edge\"><link rel=\"shortcut icon\" href=\"//yastatic.net/morda-logo/i/favicon_comtr.ico\"><script" ascii /* score: '26.00'*/
      $s14 = "t/passport-frontend/0.2.88-20/public/css/auth.new.css\"><!-- <![endif]--><!--[if lt IE 9]><link rel=\"stylesheet\" type=\"text/c" ascii /* score: '25.00'*/
      $s15 = "<html data-page-type=\"auth.new\" class=\"is-js_yes passport-Page passport-Page_dark is-inlinesvg_yes\" lang=\"en\"><head><scrip" ascii /* score: '25.00'*/
      $s16 = " 2018, <!-- /react-text --><a class=\"link link_theme_normal\" href=\"//yandex.com\" tabindex=\"0\" data-reactid=\"77\"><span cl" ascii /* score: '23.00'*/
      $s17 = " href=\"https://yandex.com/support/passport/\" tabindex=\"0\" data-reactid=\"72\"><span class=\"link__inner\" data-reactid=\"73" ascii /* score: '23.00'*/
      $s18 = "43'});</script><script src=\"https://yastatic.net/nearest.js\" async=\"\" crossorigin=\"\"></script></head><body class=\"passpor" ascii /* score: '23.00'*/
      $s19 = "0.2.88-20/public/js/vendor.js\"></script><script crossorigin=\"anonymous\" src=\"https://yastatic.net/passport-frontend/0.2.88-2" ascii /* score: '22.00'*/
      $s20 = "efer=\"defer\"></script><script crossorigin=\"anonymous\" src=\"https://yastatic.net/passport-frontend/0.2.88-20/public/js/auth." ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__yandex_home_ubuntu_malware_lab_samples_extracted_phishing_Yandex_ip {
   meta:
      description = "phish__yandex - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yandex phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d0f8f3e7985a87e0beb1699ccfadab7268ffc777c05fa1dfcc35a16b6d393947"
   strings:
      $s1 = "$useragent = \" User-Agent: \";" fullword ascii /* score: '17.00'*/
      $s2 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s3 = "fwrite($fp, $useragent);" fullword ascii /* score: '12.00'*/
      $s4 = "elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))" fullword ascii /* score: '12.00'*/
      $s5 = "$file = 'ip.txt';" fullword ascii /* score: '11.00'*/
      $s6 = "      $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'].\"\\r\\n\";" fullword ascii /* score: '10.00'*/
      $s7 = "fwrite($fp, $victim);" fullword ascii /* score: '9.00'*/
      $s8 = "$victim = \"IP: \";" fullword ascii /* score: '9.00'*/
      $s9 = "if (!empty($_SERVER['HTTP_CLIENT_IP']))" fullword ascii /* score: '7.00'*/
      $s10 = "fwrite($fp, $ipaddress);" fullword ascii /* score: '7.00'*/
      $s11 = "      $ipaddress = $_SERVER['HTTP_CLIENT_IP'].\"\\r\\n\";" fullword ascii /* score: '5.00'*/
      $s12 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s13 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
