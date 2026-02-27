/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__adobe/phish__adobe_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__adobe
   Reference: phish__adobe phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__adobe_home_ubuntu_malware_lab_samples_extracted_phishing_Adobe_index {
   meta:
      description = "phish__adobe - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__adobe phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__adobe_home_ubuntu_malware_lab_samples_extracted_phishing_Adobe_login {
   meta:
      description = "phish__adobe - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__adobe phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "11f2823bfa194f72610c207f26795edeb95ab92ad785a5c7901c7856a98f17af"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://adobe.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__adobe_home_ubuntu_malware_lab_samples_extracted_phishing_Adobe_login_2 {
   meta:
      description = "phish__adobe - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__adobe phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "2b70de126eeb8ba4706d828a13ac83ee42342a0f5b8c71c0e0cf0e1fc05a6f56"
   strings:
      $x1 = "        <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/script/" ascii /* score: '34.00'*/
      $x2 = "                    <a id=\"enterprise_signin_link\" data-component=\"spinner viewswitcher\" data-component-viewswitcher-targett" ascii /* score: '32.00'*/
      $x3 = "        <a id=\"enterprise_back_to_adobeid\" data-component=\"spinner viewswitcher\" data-component-viewswitcher-targettitle=\"S" ascii /* score: '32.00'*/
      $x4 = "obelogin.com%2Fims%2Fdenied%2FSunbreakWebUI1%3Fredirect_uri%3Dhttps%253A%252F%252Faccounts.adobe.com%252F%2523from_ims%253Dtrue%" ascii /* score: '31.00'*/
      $s5 = "        <link rel=\"stylesheet\" type=\"text/css\" href=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d72" ascii /* score: '30.00'*/
      $s6 = "            <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/scr" ascii /* score: '28.00'*/
      $s7 = "        <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/script/" ascii /* score: '28.00'*/
      $s8 = "3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fadobeid%2FSunbreakWebUI1%2FAdobeID%2Ftoken%3Fredirect_uri%3Dhttps%253A%252F%252Faccounts." ascii /* score: '28.00'*/
      $s9 = "lback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fdenied%2FSunbreakWebUI1%3Fredirect_uri%3Dhttps%253A%252F%252Faccounts.adobe.c" ascii /* score: '28.00'*/
      $s10 = "            <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/scr" ascii /* score: '28.00'*/
      $s11 = "ack=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fadobeid%2FSunbreakWebUI1%2FAdobeID%2Ftoken%3Fredirect_uri%3Dhttps%253A%252F%252" ascii /* score: '28.00'*/
      $s12 = "    <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/script/spec" ascii /* score: '28.00'*/
      $s13 = "            <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/scr" ascii /* score: '28.00'*/
      $s14 = "    <script src=\"https://static.adobelogin.com/renga-idprovider/resources/60550808d7d722ea186a935459f7234f/spectrum/script/spec" ascii /* score: '28.00'*/
      $s15 = "                    <a class=\"nowrap\" data-component=\"spinner\" href=\"create_account?client_id=SunbreakWebUI1&amp;callback=h" ascii /* score: '27.00'*/
      $s16 = "clean-n7-active wf-adobeclean-n3-active wf-active wf-inactive\" data-pagename=\"login\" lang=\"en\"><!--<![endif]--><head>" fullword ascii /* score: '25.00'*/
      $s17 = "nga-idprovider/pages/start_forgot_password?client_id=SunbreakWebUI1&amp;callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fad" ascii /* score: '24.00'*/
      $s18 = ".link%252Cunlink_social_account%252Cadmin_slo%252Creauthenticated&amp;denied_callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims" ascii /* score: '24.00'*/
      $s19 = "terprise_view\" href=\"login?idp_flow_type=login_t2&amp;client_id=SunbreakWebUI1&amp;callback=https%3A%2F%2Fims-na1.adobelogin.c" ascii /* score: '24.00'*/
      $s20 = "=\"login?idp_flow_type=login&amp;client_id=SunbreakWebUI1&amp;callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fadobeid%2FSu" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__adobe_home_ubuntu_malware_lab_samples_extracted_phishing_Adobe_ip {
   meta:
      description = "phish__adobe - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__adobe phishing_kit auto gen"
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
      $s12 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s13 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
