/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__instagram/phish__instagram_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__instagram
   Reference: phish__instagram phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule lY4eZXm_YWu {
   meta:
      description = "phish__instagram - file lY4eZXm_YWu.html"
      author = "Comps Team Malware Lab"
      reference = "phish__instagram phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "ea9f43e2033b48a34baceab019007a5119b4149ce9f661349eaceec903f11bfd"
   strings:
      $x1 = "__d(\"XDM\",[\"DOMEventListener\",\"DOMWrapper\",\"emptyFunction\",\"Flash\",\"GlobalCallback\",\"guid\",\"Log\",\"UserAgent_DEP" ascii /* score: '56.50'*/
      $x2 = "__d(\"initXdArbiter\",[\"QueryString\",\"resolveWindow\",\"Log\",\"XDM\",\"XDMConfig\"],(function a(b,c,d,e,f,g){__p&&__p();(fun" ascii /* score: '48.50'*/
      $x3 = "__d(\"UserAgent_DEPRECATED\",[],(function a(b,c,d,e,f,g){__p&&__p();var h=false,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w;function x(){__p&&" ascii /* score: '39.00'*/
      $x4 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><title>Facebook Cross-Domain Messaging helper" ascii /* score: '33.00'*/
      $s5 = "<!-- saved from url=(0139)https://staticxx.facebook.com/connect/xd_arbiter/r/lY4eZXm_YWu.js?version=42#channel=f39a7d8ae18673c&o" ascii /* score: '30.00'*/
      $s6 = "se j.error(\"Failed proxying to %s, expected %s\",G,y)};var C=null,D={xd_action:\"proxy_ready\",logged_in:/\\bc_user=/.test(docu" ascii /* score: '29.50'*/
      $s7 = "__d(\"Flash\",[\"DOMEventListener\",\"DOMWrapper\",\"QueryString\",\"UserAgent_DEPRECATED\",\"guid\",\"htmlSpecialChars\"],(func" ascii /* score: '29.00'*/
      $s8 = "rigin=https%3A%2F%2Fwww.instagram.com -->" fullword ascii /* score: '26.00'*/
      $s9 = "(function(a,b){var c=a.window||a;function d(){return\"f\"+(Math.random()*(1<<30)).toString(16).replace(\".\",\"\")}function e(j)" ascii /* score: '26.00'*/
      $s10 = "tle></head><body><script>document.domain = 'facebook.com';__transform_includes = {};self.__DEV__=self.__DEV__||0;" fullword ascii /* score: '25.00'*/
      $s11 = "ra(?:.+Version.|.)(\\d+\\.\\d+))|(?:AppleWebKit.(\\d+(?:\\.\\d+)?))|(?:Trident\\/\\d+\\.\\d+.*rv:(\\d+\\.\\d+))/.exec(z),B=/(Mac" ascii /* score: '24.00'*/
      $s12 = "Native.postMessage(t,A)};window.addEventListener(\"fbNativeReady\",B)}}var t=/#(.*)|$/.exec(location.href)[1];if(window==top)loc" ascii /* score: '23.00'*/
      $s13 = "p();if(h)return;h=true;var z=navigator.userAgent,A=/(?:MSIE.(\\d+\\.\\d+))|(?:(?:Firefox|GranParadiso|Iceweasel).(\\d+\\.\\d+))|" ascii /* score: '22.00'*/
      $s14 = " proxy\");s()}else{j.info(\"Legacy proxy to %s\",u.relation);r()}return}if(v!=/https?/.exec(window.name)[0]){j.info(\"Redirectio" ascii /* score: '22.00'*/
      $s15 = "https:\\/\\/connect.facebook.net\\/rsrc.php\\/v2\\/yW\\/r\\/yOZN1vHw3Z_.swf\"}}); require('initXdArbiter'); </script><b id=\"war" ascii /* score: '22.00'*/
      $s16 = "loat(A[3]):NaN;l=A[4]?parseFloat(A[4]):NaN;if(l){A=/(?:Chrome\\/(\\d+\\.\\d+))/.exec(z);m=A&&A[1]?parseFloat(A[1]):NaN}else m=Na" ascii /* score: '21.00'*/
      $s17 = "ion.hash=\"\";if(!t){j.error(\"xd_arbiter.php loaded without a valid hash, referrer: %s\",document.referrer);return}var u=h.deco" ascii /* score: '21.00'*/
      $s18 = "ble(e),configurable:true,get:d.__lookupGetter__(e),set:d.__lookupSetter__(e)}}}}(Object.getOwnPropertyDescriptor)}})();" fullword ascii /* score: '21.00'*/
      $s19 = "<!-- saved from url=(0139)https://staticxx.facebook.com/connect/xd_arbiter/r/lY4eZXm_YWu.js?version=42#channel=f39a7d8ae18673c&o" ascii /* score: '21.00'*/
      $s20 = "__d(\"Log\",[\"sprintf\"],(function a(b,c,d,e,f,g,h){var i={DEBUG:3,INFO:2,WARNING:1,ERROR:0};function j(l,m){var n=Array.protot" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__instagram_home_ubuntu_malware_lab_samples_extracted_phishing_Instagram_login {
   meta:
      description = "phish__instagram - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__instagram phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "569a26536c55d7fde9171f875ba8fe76e9d80c331fd33b9c934df230004c66e3"
   strings:
      $x1 = "<style type=\"text/css\" data-isostyle-id=\"is6d0655d8\">._2g7d5{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-sp" ascii /* score: '61.00'*/
      $x2 = "    <span id=\"react-root\"><section class=\"_sq4bv _29u45\"><main class=\"_8fi2q _2v79o\" role=\"main\"><article class=\"_qmq8y" ascii /* score: '40.00'*/
      $x3 = "<div class=\"_c2vev\"><div class=\"_162ov\"></div></div><div id=\"fb-root\" class=\" fb_reset\"><div style=\"position: absolute;" ascii /* score: '40.00'*/
      $x4 = ".fb_dialog{background:rgba(82, 82, 82, .7);position:absolute;top:-10000px;z-index:10001}.fb_reset .fb_dialog_legacy{overflow:vis" ascii /* score: '40.00'*/
      $x5 = "<script type=\"text/javascript\">!function(e){function n(o){if(a[o])return a[o].exports;var r=a[o]={i:o,l:!1,exports:{}};return " ascii /* score: '31.00'*/
      $s6 = "<!-- saved from url=(0026)https://www.instagram.com/ -->" fullword ascii /* score: '30.00'*/
      $s7 = "<meta content=\"Create an account or log in to Instagram - A simple, fun &amp; creative way to capture, edit &amp; share photos," ascii /* score: '27.00'*/
      $s8 = "            <script type=\"text/javascript\">window._sharedData = {\"activity_counts\": null, \"config\": {\"csrf_token\": \"Kn0" ascii /* score: '27.00'*/
      $s9 = ".fb_iframe_widget{display:inline-block;position:relative}.fb_iframe_widget span{display:inline-block;position:relative;text-alig" ascii /* score: '27.00'*/
      $s10 = "{min-height:32px;z-index:2;zoom:1}.fb_iframe_widget_loader .FB_Loader{background:url(https://static.xx.fbcdn.net/rsrc.php/v3/y9/" ascii /* score: '27.00'*/
      $s11 = "aver.js\"></script><script type=\"text/javascript\" src=\"chrome-extension://jnkdcmgmnegofdddphijckfagibepdlb/inject_download_al" ascii /* score: '26.00'*/
      $s12 = "<html lang=\"en\" class=\"js not-logged-in client-root\"><!--<![endif]--><head><meta http-equiv=\"Content-Type\" content=\"text/" ascii /* score: '26.00'*/
      $s13 = "<html lang=\"en\" class=\"js not-logged-in client-root\"><!--<![endif]--><head><meta http-equiv=\"Content-Type\" content=\"text/" ascii /* score: '26.00'*/
      $s14 = "Ys.png) no-repeat scroll 0 -30px transparent}.fb_dialog_loader{background-color:#f6f7f9;border:1px solid #606060;font-size:24px;" ascii /* score: '25.00'*/
      $s15 = "<meta content=\"Create an account or log in to Instagram - A simple, fun &amp; creative way to capture, edit &amp; share photos," ascii /* score: '24.00'*/
      $s16 = " 3px 6px;text-shadow:rgba(0, 30, 84, .296875) 0 -1px 0}.fb_dialog_content .dialog_header .header_center{color:#fff;font-size:16p" ascii /* score: '23.00'*/
      $s17 = "<meta property=\"og:url\" content=\"https://instagram.com/\">" fullword ascii /* score: '22.00'*/
      $s18 = "_overlay.hidden{display:none}.fb_dialog.fb_dialog_mobile.loading iframe{visibility:hidden}.fb_dialog_content .dialog_header{-web" ascii /* score: '22.00'*/
      $s19 = "YeTNIlTZjm.png) no-repeat 0 -20px;bottom:-10px;left:-10px}.fb_dialog_bottom_right{background:url(https://static.xx.fbcdn.net/rsr" ascii /* score: '22.00'*/
      $s20 = "ialog_loader_close{float:left}.fb_dialog.fb_dialog_mobile .fb_dialog_close_button{text-shadow:rgba(0, 30, 84, .296875) 0 -1px 0}" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__instagram_home_ubuntu_malware_lab_samples_extracted_phishing_Instagram_index {
   meta:
      description = "phish__instagram - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__instagram phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__instagram_home_ubuntu_malware_lab_samples_extracted_phishing_Instagram_login_2 {
   meta:
      description = "phish__instagram - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__instagram phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "926ab74674d52bef2c8e7cbcc5d0877690e50b960fe079fed33334e5873da9e6"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://instagram.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__instagram_home_ubuntu_malware_lab_samples_extracted_phishing_Instagram_ip {
   meta:
      description = "phish__instagram - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__instagram phishing_kit auto gen"
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
