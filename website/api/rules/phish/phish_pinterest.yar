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
