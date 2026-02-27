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
