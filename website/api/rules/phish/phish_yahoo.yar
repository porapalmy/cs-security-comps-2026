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
