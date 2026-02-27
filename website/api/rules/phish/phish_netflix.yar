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
