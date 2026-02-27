/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__steam/phish__steam_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__steam
   Reference: phish__steam phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__steam_home_ubuntu_malware_lab_samples_extracted_phishing_Steam_index {
   meta:
      description = "phish__steam - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__steam phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__steam_home_ubuntu_malware_lab_samples_extracted_phishing_Steam_login {
   meta:
      description = "phish__steam - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__steam phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "220cd6762b3e80efc813c8b9e8f17c9aa3eb6ce6e474a2ae385ec0f5b666e76a"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://steamcommunity.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__steam_home_ubuntu_malware_lab_samples_extracted_phishing_Steam_login_2 {
   meta:
      description = "phish__steam - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__steam phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e11cc54471740c978c69388dd77e517dd0139fa74920169d02e501cdd1f01c71"
   strings:
      $x1 = "#logo_holder { display: inline-block; width: 176px; height: 44px; filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src=" ascii /* score: '35.00'*/
      $s2 = "&copy; Valve Corporation. All rights reserved. All trademarks are property of their respective owners in the US and other countr" ascii /* score: '29.00'*/
      $s3 = "<img src=\"https://steamcommunity-a.akamaihd.net/public/shared/images/header/globalheader_logo.png?t=962016\" width=\"176\" heig" ascii /* score: '29.00'*/
      $s4 = "<meta property=\"og:image:secure\" content=\"https://steamcommunity-a.akamaihd.net/public/shared/images/responsive/share_steam_l" ascii /* score: '29.00'*/
      $s5 = "<img src=\"https://steamcommunity-a.akamaihd.net/public/shared/images/header/globalheader_logo.png?t=962016\" width=\"176\" heig" ascii /* score: '29.00'*/
      $s6 = "<img src=\"https://steamcommunity-a.akamaihd.net/public/shared/images/responsive/header_logo.png\" height=\"36\" border=\"0\" al" ascii /* score: '29.00'*/
      $s7 = "<meta property=\"og:image:secure\" content=\"https://steamcommunity-a.akamaihd.net/public/shared/images/responsive/share_steam_l" ascii /* score: '29.00'*/
      $s8 = "<img src=\"https://steamcommunity-a.akamaihd.net/public/shared/images/responsive/header_logo.png\" height=\"36\" border=\"0\" al" ascii /* score: '29.00'*/
      $s9 = "<meta property=\"og:image\" content=\"https://steamcommunity-a.akamaihd.net/public/shared/images/responsive/share_steam_logo.png" ascii /* score: '29.00'*/
      $s10 = "if ( typeof JSON != 'object' || !JSON.stringify || !JSON.parse ) { document.write( \"<scr\" + \"ipt type=\\\"text\\/javascript" ascii /* score: '29.00'*/
      $s11 = "<a href=\"https://help.steampowered.com/en/wizard/HelpWithLogin?redir=community%2Flogin%2Fhome%2F%3Fgoto%3D\">" fullword ascii /* score: '28.00'*/
      $s12 = "LoginManager = new CLoginPromptManager( 'https://steamcommunity.com', {" fullword ascii /* score: '28.00'*/
      $s13 = "&nbsp; | &nbsp;<a href=\"http://www.valvesoftware.com/legal.htm\" target=\"_blank\">Legal</a>" fullword ascii /* score: '27.00'*/
      $s14 = "&nbsp;| &nbsp;<a href=\"https://store.steampowered.com/subscriber_agreement/\" target=\"_blank\">Steam Subscriber Agreement</a>" fullword ascii /* score: '27.00'*/
      $s15 = "&nbsp;| &nbsp;<a href=\"http://www.valvesoftware.com/legal.htm\" target=\"_blank\">Legal</a>" fullword ascii /* score: '27.00'*/
      $s16 = "<a href=\"https://store.steampowered.com/privacy_agreement/\" target=\"_blank\">Privacy Policy</a>" fullword ascii /* score: '27.00'*/
      $s17 = "<link href=\"https://steamcommunity-a.akamaihd.net/public/shared/css/login.css?v=urY8LqkoziPf\" rel=\"stylesheet\" type=\"text/c" ascii /* score: '27.00'*/
      $s18 = "&nbsp;| &nbsp;<a href=\"http://store.steampowered.com/subscriber_agreement/\" target=\"_blank\">Steam Subscriber Agreement</a>" fullword ascii /* score: '27.00'*/
      $s19 = "<a href=\"http://store.steampowered.com/privacy_agreement/\" target=\"_blank\">Privacy Policy</a>" fullword ascii /* score: '27.00'*/
      $s20 = "&nbsp;| &nbsp;<a href=\"https://store.steampowered.com/steam_refunds/\" target=\"_blank\">Refunds</a>" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__steam_home_ubuntu_malware_lab_samples_extracted_phishing_Steam_ip {
   meta:
      description = "phish__steam - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__steam phishing_kit auto gen"
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
      $s12 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s13 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
