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
