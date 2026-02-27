/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__paypal/phish__paypal_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__paypal
   Reference: phish__paypal phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__paypal_home_ubuntu_malware_lab_samples_extracted_phishing_PayPal_index {
   meta:
      description = "phish__paypal - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__paypal phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__paypal_home_ubuntu_malware_lab_samples_extracted_phishing_PayPal_login {
   meta:
      description = "phish__paypal - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__paypal phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "6bdd929e258914d407095b516a51e9cd94817dfed88bad7fd9524d7464d321a8"
   strings:
      $x1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['login_email'] . \" Pass: \" . $_POST['login_password'] . \"\\n\", F" ascii /* score: '32.00'*/
      $x2 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['login_email'] . \" Pass: \" . $_POST['login_password'] . \"\\n\", F" ascii /* score: '32.00'*/
      $s3 = "header('Location: https://www.paypal.com/login');" fullword ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__paypal_home_ubuntu_malware_lab_samples_extracted_phishing_PayPal_login_2 {
   meta:
      description = "phish__paypal - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__paypal phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "750de8d980931515d7127f23563306335569c8626df09a59335a8eaec2c867eb"
   strings:
      $x1 = "</script><script nonce=\"OdHJON702gbbVy4cAFWxaboMpVOk5muI1jhED3XwaB6eOIPN\">window.PAYPAL=window.PAYPAL||{},function(){\"use str" ascii /* score: '76.00'*/
      $x2 = "<!DOCTYPE html><!--[if lt IE 9]><html lang=\"en\" class=\"no-js lower-than-ie9 ie desktop\"><![endif]--><!--[if lt IE 10]><html " ascii /* score: '61.00'*/
      $x3 = "aria-describedby=\"passwordErrorMessage\"/><button type=\"button\" class=\"showPassword hide show-hide-password scTrack:unifiedl" ascii /* score: '54.00'*/
      $x4 = "</script><style id=\"antiClickjack\">body {display: none !important;}</style><script nonce=\"OdHJON702gbbVy4cAFWxaboMpVOk5muI1jh" ascii /* score: '52.00'*/
      $x5 = "</script><script src=\"https://www.paypalobjects.com/pa/js/min/pa.js\"></script><script nonce=\"OdHJON702gbbVy4cAFWxaboMpVOk5muI" ascii /* score: '49.00'*/
      $x6 = "</p><p class=\"secureMessage hide\">Securely logging you in...</p><p class=\"oneTouchMessage hide\"></p><p class=\"retrieveInfo " ascii /* score: '48.00'*/
      $x7 = "ger.logServerPreparedMetrics(),r||(login.logger.log({evt:\"state_name\",data:login.utils.getKmliCb()?\"LOGIN_UL_RM\":\"LOGIN_UL" ascii /* score: '41.00'*/
      $x8 = "e_name\",data:login.logger.getStateName(),instrument:!0}),login.logger.log({evt:\"transition_name\",data:\"process_password_reco" ascii /* score: '41.00'*/
      $x9 = "ogger.log({evt:\"state_name\",data:\"sso_login\",instrument:!0}),login.logger.log({evt:\"transition_name\",data:\"process_sso_lo" ascii /* score: '39.00'*/
      $x10 = "rn function(l){l.preventDefault(),login.logger.log({evt:\"state_name\",data:t||login.logger.getStateName(),instrument:!0}),login" ascii /* score: '38.00'*/
      $x11 = ",instrument:!0}),login.utils.getIntent()===\"checkout\"&&(login.logger.log({evt:\"landing_page\",data:\"login\",instrument:!0})," ascii /* score: '38.00'*/
      $x12 = "&a&&a.field&&(r=et(a)),r&&(w===\"inputEmail\"||w===\"inputPhone\")&&(login.logger.log({evt:\"state_name\",data:login.logger.getS" ascii /* score: '38.00'*/
      $x13 = "me(),instrument:!0}),login.logger.log({evt:\"transition_name\",data:\"process_next\",instrument:!0}),login.logger.pushLogs());if" ascii /* score: '36.00'*/
      $x14 = "logger.log({evt:\"design\",data:login.utils.isInContextIntegration()?\"in-context\":\"full-context\",instrument:!0})),i&&login.l" ascii /* score: '36.00'*/
      $x15 = "\"),n.aPayAuth=null,e.error_code&&login.logger.log({evt:\"ext_error_code\",data:e.error_code,instrument:!0});if(t){instrumentSpl" ascii /* score: '36.00'*/
      $x16 = "{data:{splitLoginOptOut:!0}})),login.logger.pushLogs(f),r()}}function a(e,t){eventPreventDefault(e),$.ajax({type:\"POST\",url:\"" ascii /* score: '35.00'*/
      $x17 = "ogger.log({evt:\"transition_name\",data:n,instrument:!0}),u=document.querySelector('input[name=\"locale.x\"]'),u&&login.logger.l" ascii /* score: '35.00'*/
      $x18 = "re_sso_login\",instrument:!0}),login.logger.pushLogs(),$.ajax({url:\"/signin/sso\",method:\"POST\",data:r,success:function(t){lo" ascii /* score: '35.00'*/
      $x19 = "opt\",login.logger.log({evt:\"exp_shown\",data:\"tpd\",instrument:!0})),login.logger.log({evt:\"state_name\",data:\"begin_pwd\"," ascii /* score: '33.00'*/
      $x20 = "ign\",data:login.utils.isInContextIntegration()?\"in-context\":\"full-context\",instrument:!0}),n&&login.logger.log({evt:\"page_" ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 300KB and
      1 of ($x*)
}

rule _opt_mal_phish__paypal_home_ubuntu_malware_lab_samples_extracted_phishing_PayPal_ip {
   meta:
      description = "phish__paypal - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__paypal phishing_kit auto gen"
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
