/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__ebay/phish__ebay_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__ebay
   Reference: phish__ebay phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__ebay_home_ubuntu_malware_lab_samples_extracted_phishing_Ebay_index {
   meta:
      description = "phish__ebay - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__ebay phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__ebay_home_ubuntu_malware_lab_samples_extracted_phishing_Ebay_login {
   meta:
      description = "phish__ebay - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__ebay phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "79ef1b4ca1812aef701005a9d2fd8ce6dfe5d36c1c73c0b08ec4772c28f82981"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['userid'] . \" Pass: \" . $_POST['pass'] . \"\\n\", FILE_APPEND);" fullword ascii /* score: '24.00'*/
      $s2 = "header('Location: https://ebay.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__ebay_home_ubuntu_malware_lab_samples_extracted_phishing_Ebay_login_2 {
   meta:
      description = "phish__ebay - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__ebay phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "443306fad679d4944360ff2989b5b7a32dbcccb96f3f937f45f1781e05868132"
   strings:
      $x1 = "vjo.ctype('vjo.com.ebay.darwin.app.signin.KgClientInfo').needs(['vjo.dsf.Element','vjo.com.ebay.darwin.app.signin.KgHelper']).pr" ascii /* score: '54.00'*/
      $x2 = "<div class=\"CentralArea\" id=\"CentralArea\"><div><div id=\"srd\"><div><noscript class=\"noJsErr\"><div style=\"display:inline-" ascii /* score: '51.00'*/
      $x3 = "<div class=\"GlobalNavigation\" id=\"GlobalNavigation\"><style>html,body,div,span,object,iframe,h1,h2,h3,h4,h5,h6,p,blockquote,p" ascii /* score: '51.00'*/
      $x4 = "<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><script src=\"https://www.ebay.com/rdr/js/s/rrbundl" ascii /* score: '50.00'*/
      $x5 = "<body id=\"v4-3\" class=\"sz980 sso ssous\"><div id=\"kgdiv\"> </div><div></div><script src=\"https://secureinclude.ebaystatic.c" ascii /* score: '48.00'*/
      $x6 = "xhReq.open('POST',url,true);xhReq.setRequestHeader(\"X-Requested-With\",\"XMLHttpRequest\");xhReq.setRequestHeader(\"Content-typ" ascii /* score: '45.00'*/
      $x7 = "</div><!--vo{54*2212:53,RcmdId SignIn2,RlogId p4plaijkehq%60%3C%3Dsm%7E71%287040%3F76-16435f2d58d-0x184--><script type=\"text/ja" ascii /* score: '43.00'*/
      $x8 = "xhReq.open('POST',url,true);xhReq.setRequestHeader(\"X-Requested-With\",\"XMLHttpRequest\");xhReq.setRequestHeader(\"Content-typ" ascii /* score: '40.00'*/
      $x9 = "xhReq.open('POST',url,true);xhReq.setRequestHeader(\"X-Requested-With\",\"XMLHttpRequest\");xhReq.setRequestHeader(\"Content-typ" ascii /* score: '40.00'*/
      $x10 = " 1995-2018 eBay Inc. All Rights Reserved. <a href=\"https://www.ebayinc.com/accessibility/\">Accessibility</a>, <a href=\"https:" ascii /* score: '39.00'*/
      $x11 = "var i;for(i=0;i<collection.length;i++){collection[i].onkeydown=keyDownHandler;collection[i].onkeyup=keyUpHandler;collection[i].o" ascii /* score: '37.00'*/
      $x12 = "document.getElementById(\"sgn-otp-conf\").disabled=false;document.getElementById(\"sgnBtn\").disabled=false;}else if(method==='p" ascii /* score: '37.00'*/
      $x13 = "function $0(p1){return function(event){return this.trackOTPOpenAndSignIn(\"https://www.ebay.com:443/ws/eBayISAPI.dll?V4SignInAja" ascii /* score: '37.00'*/
      $x14 = "vjo.ctype('vjo.com.ebay.darwin.app.signin.SigninSelfInit').needs('vjo.dsf.Element').props({flashInit:function(){},verisign:funct" ascii /* score: '36.00'*/
      $x15 = "if(method==='init'){if(resArr[0]==='success'){document.getElementById(\"refId\").value=json[1][1];vjo.com.ebay.darwin.app.signin" ascii /* score: '36.00'*/
      $x16 = "var filenameFinish=fileName.length;fileName=fileName.substring(filenameStart+pLastDir.length,filenameFinish);return fileName;},o" ascii /* score: '35.00'*/
      $x17 = "ript type=\"text/javascript\">var _GlobalNavHeaderUtf8Encoding=true,includeHost='https://secureinclude.ebaystatic.com/';</script" ascii /* score: '33.00'*/
      $x18 = "<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><script src=\"https://www.ebay.com/rdr/js/s/rrbundl" ascii /* score: '33.00'*/
      $x19 = "mmon.otpConfirmContent(json[3][1]);vjo.com.ebay.darwin.app.signin.SignInRedesignCommon.processOTPAjaxSuccessResponse(json[0][1]," ascii /* score: '33.00'*/
      $x20 = "vjo.ctype('vjo.com.ebay.darwin.app.signin.EbayToolbar').needs(['vjo.dsf.Element','vjo.dsf.document.Form','vjo.dsf.client.Browser" ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 500KB and
      1 of ($x*)
}

rule _opt_mal_phish__ebay_home_ubuntu_malware_lab_samples_extracted_phishing_Ebay_ip {
   meta:
      description = "phish__ebay - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__ebay phishing_kit auto gen"
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
