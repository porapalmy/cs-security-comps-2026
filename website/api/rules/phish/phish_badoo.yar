/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__badoo/phish__badoo_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__badoo
   Reference: phish__badoo phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__badoo_home_ubuntu_malware_lab_samples_extracted_phishing_Badoo_index {
   meta:
      description = "phish__badoo - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__badoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__badoo_home_ubuntu_malware_lab_samples_extracted_phishing_Badoo_login {
   meta:
      description = "phish__badoo - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__badoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "2264bbd8a153860e1b1e03aba842f54ccd0286da2dd94ab8b4579d542dc9e1aa"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['email'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEND);" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://badoo.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__badoo_home_ubuntu_malware_lab_samples_extracted_phishing_Badoo_login_2 {
   meta:
      description = "phish__badoo - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__badoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "df4d5eec529e8d3738403fcf6654431241a2614724a7de37f7a24a22495893ae"
   strings:
      $x1 = "&nbsp;</span>Badoo </div> </div> <div class=\"footer__seo-language\"></div> </div>  <script type=\"text/javascript\"> $vars={\"r" ascii /* score: '61.00'*/
      $x2 = "<html dir=\"ltr\" class=\"js linux firefox\" lang=\"en\"><head>  <meta http-equiv=\"Content-type\" content=\"text/html;charset=u" ascii /* score: '56.00'*/
      $x3 = "<a href=\"https://badoo.com/en/signup/?f=top\" class=\"btn btn--xsm btn--white-no-border js-inside-link\"> <div class=\"btn__con" ascii /* score: '52.00'*/
      $x4 = "</script> <script id=\"base-lite\" onerror=\"handleLoadError(this)\" src=\"https://badoocdn.com/v2/-/-/js/hon_v3/base-lite.05534" ascii /* score: '42.00'*/
      $x5 = ".fb_dialog{background:rgba(82, 82, 82, .7);position:absolute;top:-10000px;z-index:10001}.fb_reset .fb_dialog_legacy{overflow:vis" ascii /* score: '40.00'*/
      $x6 = "error_log_url\":\"https:\\/\\/badoo.com\\/jss\\/js_error.phtml\"}; $s.fake_start=+new Date; </script>     <title>Sign in to Bado" ascii /* score: '34.00'*/
      $x7 = "</script> <script id=\"base-lite\" onerror=\"handleLoadError(this)\" src=\"https://badoocdn.com/v2/-/-/js/hon_v3/base-lite.05534" ascii /* score: '32.00'*/
      $s8 = "ript onerror=\"handleLoadError(this)\" src=\"https://badoocdn.com/v2/-/-/js/hon_v3/unauth/page.signin.48df850c35f8630de1a3.js\" " ascii /* score: '29.00'*/
      $s9 = "ipt type=\"text/javascript\" src=\"https://badoocdn.com/facebook_sdk/cbad4cd6/en_US/sdk.js\" crossorigin=\"use-credentials\"></s" ascii /* score: '28.00'*/
      $s10 = "--sign-in js-core-events-container\">  <form method=\"post\" action=\"login.php\" class=\"no_autoloader form js-signin\" novalid" ascii /* score: '28.00'*/
      $s11 = "{min-height:32px;z-index:2;zoom:1}.fb_iframe_widget_loader .FB_Loader{background:url(https://static.xx.fbcdn.net/rsrc.php/v3/y9/" ascii /* score: '27.00'*/
      $s12 = "</svg></div> <div class=\"page__stream-loader js-page-loader\"></div> <div class=\"page page--simple    js-vrt-marker\" data-ab-" ascii /* score: '27.00'*/
      $s13 = ".fb_iframe_widget{display:inline-block;position:relative}.fb_iframe_widget span{display:inline-block;position:relative;text-alig" ascii /* score: '27.00'*/
      $s14 = " window.onCssLoad = function() { window.loadedCSS++; } </script> <script>/* inline source: https://badoocdn.com/v2/-/-/js/hon_v3" ascii /* score: '27.00'*/
      $s15 = "nel.html\",\"sdk_url\":\"\\/\\/badoocdn.com\\/facebook_sdk\\/cbad4cd6\\/en_US\\/sdk.js\"},\"SignIn\":{\"homePageURL\":\"https:" ascii /* score: '26.00'*/
      $s16 = "up_url\":\"https:\\/\\/badoo.com\\/facebook\\/authorize.phtml?rt=9dbbde&js_use_scheme=https\",\"lookalikes_signup_url\":\"https:" ascii /* score: '26.00'*/
      $s17 = "_mobile.loading iframe{visibility:hidden}.fb_dialog_content .dialog_header{-webkit-box-shadow:white 0 1px 1px -1px inset;backgro" ascii /* score: '26.00'*/
      $s18 = "ding.centered .fb_dialog_content{background:none}.loading.centered #fb_dialog_loader_close{color:#fff;display:block;padding-top:" ascii /* score: '26.00'*/
      $s19 = "oocdn.com/v2/-/-/js/hon_v3/unauth/base-app.c103cdf470828f5ba677.js\" defer=\"defer\" crossorigin=\"use-credentials\"></script>  " ascii /* score: '26.00'*/
      $s20 = ": https://badoocdn.com/v2/-/-/css/hotornot_v2/generic.critical-ltr.29f303c759f3746e209b.css */ @-webkit-keyframes loader{0%,to{-" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__badoo_home_ubuntu_malware_lab_samples_extracted_phishing_Badoo_ip {
   meta:
      description = "phish__badoo - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__badoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d0f8f3e7985a87e0beb1699ccfadab7268ffc777c05fa1dfcc35a16b6d393947"
   strings:
      $s1 = "$useragent = \" User-Agent: \";" fullword ascii /* score: '17.00'*/
      $s2 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s3 = "fwrite($fp, $useragent);" fullword ascii /* score: '12.00'*/
      $s4 = "elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))" fullword ascii /* score: '12.00'*/
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
