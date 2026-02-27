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
