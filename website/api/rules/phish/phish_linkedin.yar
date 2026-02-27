/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__linkedin/phish__linkedin_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__linkedin
   Reference: phish__linkedin phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__linkedin_home_ubuntu_malware_lab_samples_extracted_phishing_LinkedIn_index {
   meta:
      description = "phish__linkedin - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__linkedin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__linkedin_home_ubuntu_malware_lab_samples_extracted_phishing_LinkedIn_login {
   meta:
      description = "phish__linkedin - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__linkedin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3ce37eec6052179a90f6def84f58ca14300e4f3e864ec75a4406f00c9c599786"
   strings:
      $x1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['session_key'] . \" Pass: \" . $_POST['session_password'] . \"\\n\"," ascii /* score: '32.00'*/
      $x2 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['session_key'] . \" Pass: \" . $_POST['session_password'] . \"\\n\"," ascii /* score: '32.00'*/
      $s3 = "header('Location: https://linkedin.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__linkedin_home_ubuntu_malware_lab_samples_extracted_phishing_LinkedIn_login_2 {
   meta:
      description = "phish__linkedin - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__linkedin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "ea9ff92d82654c353aa8f241dadfd68e698907f37d7415bc6bd0cebde4f201ad"
   strings:
      $x1 = "</button></li></ul><input type=\"hidden\" name=\"i18nLang\" value=\"\"><input type=\"hidden\" name=\"currenturl\" value=\"\"></f" ascii /* score: '45.00'*/
      $x2 = "s you, enter your Email and password here to sign in.</div></div><a title=\"Close\" href=\"#\" class=\"hopscotch-bubble-close ho" ascii /* score: '42.00'*/
      $x3 = "        <div class=\"global-wrapper artdeco-a\"><code id=\"i18n_sign_in\" style=\"display: none;\"><!--\"Sign in\"--></code><cod" ascii /* score: '37.00'*/
      $x4 = "inkedin.com/\",\"potentialAction\": {\"@type\": \"SearchAction\",\"target\": \"https://www.linkedin.com/vsearch/f?type=all&keywo" ascii /* score: '33.00'*/
      $s5 = "<a target=\\\"_blank\\\" href=\\\"https:\\/\\/www.linkedin.com\\/help\\/linkedin\\/answer\\/4135?lang=en\\\">Learn more about br" ascii /* score: '29.00'*/
      $s6 = " RUM.base_urls['permanent_content'] = \"https:\\/\\/static.licdn.com\\/scds\\/common\\/u\\/\";" fullword ascii /* score: '28.00'*/
      $s7 = "<!--[if IE 8]><script src=\"https://static.licdn.com/scds/common/u/lib/polyfill/1.0.2/ie8-polyfill.min.js\"></script><![endif]--" ascii /* score: '28.00'*/
      $s8 = "Url\":\"https://media.licdn.com/media-proxy\"}--></code><script src=\"https://static.licdn.com/sc/h/19dd5wwuyhbk7uttxpuelttdg\">" ascii /* score: '28.00'*/
      $s9 = "<!--[if IE 9]><script src=\"https://static.licdn.com/scds/common/u/lib/polyfill/1.0.2/ie9-polyfill.min.js\"></script><![endif]--" ascii /* score: '28.00'*/
      $s10 = "                            r['global_browser_unsupported_notice'] = 'Looks like you\\'re using a browser that\\'s not supported" ascii /* score: '27.00'*/
      $s11 = "        <link rel=\"stylesheet\" href=\"https://static.licdn.com/sc/h/8nfuf4ujwbho8clwe5964984y\"/><meta name=\"description\" co" ascii /* score: '26.00'*/
      $s12 = "-password\" tabindex=\"1\" href=\"https://www.linkedin.com/uas/request-password-reset?trk=uno-reg-guest-home-forgot-password\">F" ascii /* score: '25.00'*/
      $s13 = "nd-static-content%2B0.1.326/f\",\"csrfToken\":\"ajax:0054295001501331025\",\"intlPolyfillUrl\":\"https://static.licdn.com/sc/h/1" ascii /* score: '25.00'*/
      $s14 = "        <script src=\"https://static.licdn.com/sc/h/3jue9p5yu1z9ypds9u1xcrb7u,27ftp26z6dvrdcg640xdatntb,edz16jejjqcx42fe0m2ca4nx" ascii /* score: '25.00'*/
      $s15 = "data-delayed-url=\"https://static.licdn.com/sc/h/95o6rrc5ws6mlw6wqzy0xgj7y\" alt=\"LinkedIn\"/></h1><form class=\"login-form\" a" ascii /* score: '24.00'*/
      $s16 = " RUM.base_urls['versioned_content'] = \"https:\\/\\/static.licdn.com\\/scds\\/concat\\/common\\/\";" fullword ascii /* score: '24.00'*/
      $s17 = "575y2ma1e5ky\"></script><code id=\"__pageContext__\" style=\"display: none;\"><!--{\"baseScdsUrl\":\"https://static.licdn.com/sc" ascii /* score: '23.00'*/
      $s18 = " RUM.base_urls['media_proxy'] = \"https:\\/\\/media.licdn.com\\/media-proxy\\/\";" fullword ascii /* score: '23.00'*/
      $s19 = "<meta name=\"msapplication-TileImage\" content=\"https://static.licdn.com/scds/common/u/images/logos/linkedin/logo-in-win8-tile-" ascii /* score: '23.00'*/
      $s20 = "static.licdn.com/scds/common/u/lib/fizzy/fz-1.3.3-min.js\",\"mpName\":\"seo-directory-frontend\",\"scHashesUrl\":\"https://stati" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__linkedin_home_ubuntu_malware_lab_samples_extracted_phishing_LinkedIn_ip {
   meta:
      description = "phish__linkedin - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__linkedin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d0f8f3e7985a87e0beb1699ccfadab7268ffc777c05fa1dfcc35a16b6d393947"
   strings:
      $s1 = "$useragent = \" User-Agent: \";" fullword ascii /* score: '17.00'*/
      $s2 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s3 = "elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))" fullword ascii /* score: '12.00'*/
      $s4 = "fwrite($fp, $useragent);" fullword ascii /* score: '12.00'*/
      $s5 = "$file = 'ip.txt';" fullword ascii /* score: '11.00'*/
      $s6 = "      $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'].\"\\r\\n\";" fullword ascii /* score: '10.00'*/
      $s7 = "$victim = \"IP: \";" fullword ascii /* score: '9.00'*/
      $s8 = "fwrite($fp, $victim);" fullword ascii /* score: '9.00'*/
      $s9 = "if (!empty($_SERVER['HTTP_CLIENT_IP']))" fullword ascii /* score: '7.00'*/
      $s10 = "fwrite($fp, $ipaddress);" fullword ascii /* score: '7.00'*/
      $s11 = "      $ipaddress = $_SERVER['HTTP_CLIENT_IP'].\"\\r\\n\";" fullword ascii /* score: '5.00'*/
      $s12 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s13 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
