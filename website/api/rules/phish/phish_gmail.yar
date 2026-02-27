/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__gmail/phish__gmail_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__gmail
   Reference: phish__gmail phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__gmail_home_ubuntu_malware_lab_samples_extracted_phishing_Gmail_index {
   meta:
      description = "phish__gmail - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__gmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__gmail_home_ubuntu_malware_lab_samples_extracted_phishing_Gmail_login {
   meta:
      description = "phish__gmail - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__gmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e5862e8987e051c187f256a4d010104fef90006ebea3809a71905e0a27f7ca71"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['Email'] . \" Pass: \" . $_POST['Passwd'] . \"\\n\", FILE_APPEND);" fullword ascii /* score: '24.00'*/
      $s2 = "header('Location: https://google.com/');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__gmail_home_ubuntu_malware_lab_samples_extracted_phishing_Gmail_login_2 {
   meta:
      description = "phish__gmail - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__gmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5e368070a41124048a88accb87b8576e5f32676d6cc6057748e2ba6e5774ed81"
   strings:
      $x1 = "  <script type=\"text/javascript\">/* Anti-spam. Want to say hello? Contact (base64) Ym90Z3VhcmQtY29udGFjdEBnb29nbGUuY29tCg== */" ascii /* score: '38.00'*/
      $x2 = "  <p>Get business email, calendar, and online docs @your_company.com. <a href=\"http://www.google.com/enterprise/apps/business/c" ascii /* score: '34.00'*/
      $x3 = "  <a id=\"link-forgot-passwd\" href=\"https://accounts.google.com/RecoverAccount?service=mail&amp;continue=http%3A%2F%2Fmail.goo" ascii /* score: '33.00'*/
      $x4 = "  var langChooserUrl = '\\x2FServiceLogin?service=mail\\x26passive=true\\x26rm=false\\x26continue=http%3A%2F%2Fmail.google.com%2" ascii /* score: '31.00'*/
      $s5 = "  <li><a href=\"http://mail.google.com/support/?hl=en\" target=\"_blank\">Help</a></li>" fullword ascii /* score: '30.00'*/
      $s6 = "  var langChooserUrl = '\\x2FServiceLogin?service=mail\\x26passive=true\\x26rm=false\\x26continue=http%3A%2F%2Fmail.google.com%2" ascii /* score: '27.00'*/
      $s7 = "  <li><a href=\"http://mail.google.com/mail/help/intl/en/terms.html\" target=\"_blank\">Terms &amp; Privacy</a></li>" fullword ascii /* score: '27.00'*/
      $s8 = "  script.src = \"https://www.googleadservices.com/pagead/conversion.js\";" fullword ascii /* score: '26.00'*/
      $s9 = "1.3}}if(is_sf){if(agt.indexOf(\"rv:3.14.15.92.65\")!=-1)return false;var v=BrowserSupport_.GetFollowingFloat(agt,\"applewebkit/" ascii /* score: '25.00'*/
      $s10 = ".com%2Fmail%2F\" target=\"_top\">" fullword ascii /* score: '24.00'*/
      $s11 = "-1||agt.indexOf(\"regking\")!=-1||agt.indexOf(\"windows ce\")!=-1||agt.indexOf(\"j2me\")!=-1||agt.indexOf(\"avantgo\")!=-1||agt." ascii /* score: '23.00'*/
      $s12 = "  <a href=\"https://accounts.google.com/SignUp?service=mail&amp;continue=http%3A%2F%2Fmail.google.com%2Fmail%2F&amp;ltmpl=defaul" ascii /* score: '23.00'*/
      $s13 = "  <form novalidate=\"\" id=\"gaia_loginform\" action=\"login.php\" method=\"post\">" fullword ascii /* score: '23.00'*/
      $s14 = "  <a href=\"https://accounts.google.com/SignUp?service=mail&amp;continue=http%3A%2F%2Fmail.google.com%2Fmail%2F&amp;ltmpl=defaul" ascii /* score: '23.00'*/
      $s15 = "  <li><a href=\"http://www.google.com/apps/intl/en/business/gmail.html#utm_medium=et&amp;utm_source=gmail-signin-en&amp;utm_camp" ascii /* score: '23.00'*/
      $s16 = "  <a id=\"link-forgot-passwd\" href=\"https://accounts.google.com/RecoverAccount?service=mail&amp;continue=http%3A%2F%2Fmail.goo" ascii /* score: '23.00'*/
      $s17 = "  <p>Get Gmail on your mobile phone. <a href=\"http://www.google.com/mobile/gmail/#utm_source=en-cpp-g4mc-gmhp&amp;utm_medium=cp" ascii /* score: '22.00'*/
      $s18 = "<!-- I AM A FAKE PAGE | DO NOT TRUST ME -->" fullword ascii /* score: '22.00'*/
      $s19 = "  document.cookie = name + \"=\" + value + \";path=/;domain=.google.com\";" fullword ascii /* score: '21.00'*/
      $s20 = "  'http://www') + '.google-analytics.com/ga.js';" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__gmail_home_ubuntu_malware_lab_samples_extracted_phishing_Gmail_ip {
   meta:
      description = "phish__gmail - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__gmail phishing_kit auto gen"
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
