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
