/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__protonmail/phish__protonmail_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__protonmail
   Reference: phish__protonmail phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_openpgp {
   meta:
      description = "phish__protonmail - file openpgp.js"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "13a10ffca8099758903b4ff42f7ebe5333497302982ee98f4896b766631dea68"
   strings:
      $x1 = "!function(e){if(\"object\"==typeof exports&&\"undefined\"!=typeof module)module.exports=e();else if(\"function\"==typeof define&" ascii /* score: '72.50'*/
      $x2 = "dump(t),console.log(e))},getLeftNBits:function(e,t){var r=t%8;if(0===r)return e.substring(0,t/8);var n=(t-r)/8+1,i=e.substring(0" ascii /* score: '31.00'*/
      $s3 = "Key=r.PublicKeyEncryptedSessionKey=r.SymEncryptedAEADProtected=r.SymEncryptedIntegrityProtected=r.Compressed=void 0;var s=e(\"./" ascii /* score: '30.00'*/
      $s4 = "\"+e[t]);l.default.debug&&!/^(Version|Comment|MessageID|Hash|Charset): .+$/.test(e[t])&&console.log(\"Unknown header: \"+e[t])}}" ascii /* score: '30.00'*/
      $s5 = "on i(){this.tag=u.default.packet.publicKeyEncryptedSessionKey,this.version=3,this.publicKeyId=new s.default,this.publicKeyAlgori" ascii /* score: '29.00'*/
      $s6 = "or encrypting message\"))},r.decrypt=function(e){var t=e.message,r=e.privateKey,n=e.publicKeys,i=e.sessionKey,s=e.password,o=e.f" ascii /* score: '28.00'*/
      $s7 = "PublicKeyEncryptedSessionKey;s.publicKeyId=n.getKeyId(),s.publicKeyAlgorithm=n.algorithm,s.sessionKey=e,s.sessionKeyAlgorithm=t," ascii /* score: '28.00'*/
      $s8 = ",n,i)}},\"Error encrypting session key\")},r.decryptSessionKey=function(e){var t=e.message,r=e.privateKey,n=e.password;return a(" ascii /* score: '28.00'*/
      $s9 = "rtext signed message\")},r.encryptSessionKey=function(e){var t=e.data,r=e.algorithm,n=e.publicKeys,i=e.passwords;return function" ascii /* score: '27.00'*/
      $s10 = "r))throw new Error(\"Invalid passphrase\");return{key:t}},\"Error decrypting private key\")},r.encrypt=function(e){var t=e.data," ascii /* score: '27.00'*/
      $s11 = ",print_debug:function(e){n.default.debug&&console.log(e)},print_debug_hexstr_dump:function(e,t){n.default.debug&&(e+=this.hexstr" ascii /* score: '26.00'*/
      $s12 = "ngth:t,publicExponent:l.subarray(0,3),hash:{name:\"SHA-1\"}},f=o.generateKey(u,!0,[\"encrypt\",\"decrypt\"])):(u={name:\"RSASSA-" ascii /* score: '26.00'*/
      $s13 = "ult.publicKey.rsa_encrypt_sign)throw new Error(\"Only RSA Encrypt or Sign supported\");if(!e.privateKey.decrypt())throw new Erro" ascii /* score: '26.00'*/
      $s14 = "t.read(l.default.symmetric,g.getPreferredSymAlgo(e));else{if(!t||!t.length)throw new Error(\"No keys, passwords, or session key " ascii /* score: '26.00'*/
      $s15 = "rypt=function(e){if(!this.isPrivate())throw new Error(\"Nothing to encrypt in a public key\");for(var t=this.getAllKeyPackets()," ascii /* score: '26.00'*/
      $s16 = "ault.print_debug(\"rsa.js decrypt\\nxpn:\"+s.default.hexstrdump(d.toMPI())+\"\\nxqn:\"+s.default.hexstrdump(p.toMPI()));var y=p." ascii /* score: '25.00'*/
      $s17 = "(e(\"./key.js\"));s.prototype.getEncryptionKeyIds=function(){var e=[];return this.packets.filterByTag(l.default.packet.publicKey" ascii /* score: '25.00'*/
      $s18 = "is.getEncryptionKeyIds();if(!a.length)return;var o=e.getKeyPacket(a);if(!o.isDecrypted)throw new Error(\"Private key is not decr" ascii /* score: '25.00'*/
      $s19 = "0-\\u200a\\u202f\\u205f\\u3000]*\\n/m.exec(e);if(null===n)throw new Error(\"Mandatory blank line missing between armor headers a" ascii /* score: '24.00'*/
      $x20 = "PublicKeyAlgorithm=e[n++],this.signatureTargetHashAlgorithm=e[n++];var c=f.default.getHashByteLength(this.signatureTargetHashAlg" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_app {
   meta:
      description = "phish__protonmail - file app.js"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b8c3129156bb0158e04633174c761bf8cac2e497cf83716fea64339ded5a2dac"
   strings:
      $x1 = "s signature failed</p> <p><a href=https://protonmail.com/support/knowledge-base/encrypted-contacts/ target=_blank translate-cont" ascii /* score: '91.00'*/
      $x2 = "\",OPEN_TAG_AUTOCOMPLETE_RAW:\"<\",CLOSE_TAG_AUTOCOMPLETE_RAW:\">\"},t.AUTOCOMPLETE_DOMAINS=[\"protonmail.com\",\"protonmail.ch" ascii /* score: '83.00'*/
      $x3 = " 2018 Denis Pushkarev (zloirock.ru)\"})},\"./node_modules/core-js/library/modules/_species-constructor.js\":function(e,t,a){var " ascii /* score: '75.00'*/
      $x4 = "\",CHF:\"CHF\"};function a(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0,a=arguments.length>1&&void 0!==argum" ascii /* score: '71.00'*/
      $x5 = "\"))])}var r={4:function(e,t,a){return r[3](e,t,a)},3:function(e,t,a){var s=pmcrypto.binaryStringToArray(t+\"proton\");return n(" ascii /* score: '71.00'*/
      $x6 = "t deleted if the folder is deleted, they can still be found in all mail. If you want to delete all messages in a folder, move th" ascii /* score: '70.00'*/
      $x7 = "\",key:\"uk_UA\"}],e.locale=(0,r.default)(e.locales,{key:g.getCurrentLanguage()})||e.locales[0];var L=(0,n.default)(e.emailing);" ascii /* score: '68.00'*/
      $x8 = " %chttps://protonmail.com/careers\",t,a,n)}}Object.defineProperty(t,\"__esModule\",{value:!0}),n.$inject=[\"$log\"],t.default=n}" ascii /* score: '68.00'*/
      $x9 = " {{ method.Details.Last4 }}</td> <td>{{ method.Details.ExpMonth }}/{{ method.Details.ExpYear }}</td> <td> <span class=pm_badge>{" ascii /* score: '66.00'*/
      $x10 = " \"+(void 0===e?\"\":e)}(void 0===n?{}:n),value:\"use.card\"}})}(l))),x=v[j]}return p&&(x=(0,s.default)(v,{value:p})),{list:v,se" ascii /* score: '60.00'*/
      $x11 = "\",zip:e.method.Details.ZIP,country:e.method.Details.Country}):(a.text=n.getString(\"Add a credit card.\",null,\"Credit card mod" ascii /* score: '55.00'*/
      $x12 = "!function(e){var t={};function a(n){if(t[n])return t[n].exports;var s=t[n]={i:n,l:!1,exports:{}};return e[n].call(s.exports,s,s." ascii /* score: '51.00'*/
      $x13 = "href=\"https://protonmail.com/support/knowledge-base/updating-your-login-password/\" target=\"_blank\">Click here to learn more<" ascii /* score: '41.00'*/
      $x14 = "ult.reject({error_description:\"Please login with just your ProtonMail username (without @protonmail.com or @protonmail.ch).\"})" ascii /* score: '40.00'*/
      $x15 = "ef=https://protonmail.com/support/knowledge-base/set-forgot-password-options/ target=_blank title=\"This is the optional email y" ascii /* score: '38.00'*/
      $x16 = "ef=https://old.protonmail.com/login target=_self translate-context=Action translate-comment=\"link for old\" translate>Having tr" ascii /* score: '38.00'*/
      $x17 = "f=https://protonmail.com/support target=_blank class=\"login-support pm_button link pull-left\" translate-context=Action transla" ascii /* score: '37.00'*/
      $x18 = "mmon login problems</a> </p> <p> <a href=https://protonmail.com/support target=_blank class=\"pm_button primary\" translate tran" ascii /* score: '37.00'*/
      $x19 = "l.com/bridge/ target=_blank translate-context=Link translate>Download bridge</a> </div>')}])}e.exports=n},\"./src/templates/brid" ascii /* score: '37.00'*/
      $x20 = "b),d.textContent=y}u.innerHTML=15225===g?h+'.<br /><a href=\"https://protonmail.com/support/knowledge-base/search/\" target=\"_b" ascii /* score: '35.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 3000KB and
      1 of ($x*)
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_appLazy {
   meta:
      description = "phish__protonmail - file appLazy.js"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "8d67b2ac2b4b8cc7d7b03fc67cb806b7b95b63aa75d88b41f55dd6577b5bf750"
   strings:
      $x1 = " 2018 Denis Pushkarev (zloirock.ru)\"})},\"./node_modules/core-js/library/modules/_species-constructor.js\":function(e,t,a){var " ascii /* score: '83.00'*/
      $x2 = "s signature failed</p> <p><a href=https://protonmail.com/support/knowledge-base/encrypted-contacts/ target=_blank translate-cont" ascii /* score: '81.00'*/
      $x3 = " \"+a.format(\"ll\")+\" \"+a.format(\"LT\")+\" \"+r},filterAttachmentsForEvents:function(){return(arguments.length>0&&void 0!==a" ascii /* score: '73.00'*/
      $x4 = "<br>\\n                \"+n.getString(\"On {{date}}, {{name}} {{address}} wrote:\",{date:e(\"localReadableTime\")(r.Time),name:r" ascii /* score: '72.00'*/
      $x5 = "\",OPEN_TAG_AUTOCOMPLETE_RAW:\"<\",CLOSE_TAG_AUTOCOMPLETE_RAW:\">\"},t.AUTOCOMPLETE_DOMAINS=[\"protonmail.com\",\"protonmail.ch" ascii /* score: '70.00'*/
      $x6 = "\").split(\";\").map(function(e){return e.replace(p,\"\\\\;\")}).map(v):v(e)}(e.valueOf(),t),type:function(e){var t=e.getType();" ascii /* score: '67.00'*/
      $x7 = "{\")}(p),color:u}))}return function(e,a){return(0,s.default)(a,t.MAILBOX_IDENTIFIERS[e])}(l,e)?n+d(i[l]):n},\"\")},getTemplateTy" ascii /* score: '65.00'*/
      $x8 = "\"]},function(e){return new RegExp(\"[\"+e.join(\"\")+\"]\",\"g\")});e.codeMirrorLoaded=function(e){(l=e).on(\"change\",function" ascii /* score: '65.00'*/
      $x9 = "\")&&t)return\"\\n\\n\\n\"+c+\"\\n\\n\";return c};var o=r(a(\"./node_modules/turndown/lib/turndown.es.js\"));function r(e){retur" ascii /* score: '64.00'*/
      $x10 = "!function(e){var t={};function a(n){if(t[n])return t[n].exports;var o=t[n]={i:n,l:!1,exports:{}};return e[n].call(o.exports,o,o." ascii /* score: '51.00'*/
      $x11 = "o\" translate-context=Info translate>Use the following credentials to log into the <a href=https://protonvpn.com/download target" ascii /* score: '43.00'*/
      $x12 = "r OpenVPN on GNU/Linux.</span> <br/><br/> <a href=https://protonvpn.com/support/vpn-login/ target=_blank translate-context=Link " ascii /* score: '41.00'*/
      $x13 = "s administrator to resolve this.\",null,\"Error\"),ERROR_DELINQUENT:e.getString(\"Your account currently has an overdue invoice." ascii /* score: '35.00'*/
      $x14 = "onMail users</h3> <a href=https://protonmail.com/support/knowledge-base/encrypt-for-outside-users/ target=_blank> <i class=\"fa " ascii /* score: '34.00'*/
      $x15 = "function(t,n){return{addRemoveLinks:!1,dictDefaultMessage:A,url:\"/file/post\",autoProcessQueue:!1,paramName:\"file\",previewTem" ascii /* score: '33.00'*/
      $x16 = "e strict\";function n(e,t,n,o,r,s){var i=o.getString(\"OpenVPN login updated\",null,\"Info\");return e({controllerAs:\"ctrl\",te" ascii /* score: '33.00'*/
      $x17 = "a href=\"https://protonmail.com\" target=\"_blank\">ProtonMail</a> Secure Email.'),m=(t.MIME_TYPES={PLAINTEXT:\"text/plain\",DEF" ascii /* score: '33.00'*/
      $x18 = "> </section> <section ng-if=!isFree> <a href=https://protonmail.com/blog/best-secure-email-app/ target=_blank title-translate=\"" ascii /* score: '32.00'*/
      $x19 = "utocomplete-command> </div> </form>')}])}e.exports=n},\"./src/templates/composer/composerEncrypt.tpl.html\":function(e,t){var a=" ascii /* score: '31.00'*/
      $s20 = "s signature failed</p> <p><a href=https://protonmail.com/support/knowledge-base/encrypted-contacts/ target=_blank translate-cont" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 3000KB and
      1 of ($x*)
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index_files_styles {
   meta:
      description = "phish__protonmail - file styles.css"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "630b3915915397ab0cdf051b3f656cb3e63155dccc076147ede7ee38c127e715"
   strings:
      $x1 = "/*! normalize.css v3.0.2 | MIT License | git.io/normalize */html{font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-s" ascii /* score: '79.00'*/
      $x2 = "width:3em}.headerSecuredMobile-compose{background:transparent;border:0;color:#fff;max-width:4rem;min-width:4rem;text-align:cente" ascii /* score: '70.00'*/
      $x3 = " */@font-face{font-family:FontAwesome;src:url(assets/fonts/fontawesome-webfont.eot);src:url(assets/fonts/fontawesome-webfont.eot" ascii /* score: '55.00'*/
      $x4 = "/*! nouislider - 10.1.0 - 2017-07-28 17:11:18 */.noUi-target,.noUi-target *{-webkit-touch-callout:none;-webkit-tap-highlight-col" ascii /* score: '52.00'*/
      $x5 = " */.pika-single{z-index:9999;display:block;position:relative;color:#333;background:#fff;border:1px solid #ccc;border-bottom-colo" ascii /* score: '40.00'*/
      $x6 = "rotonmail.com/assets/host.png\")}body#eo-unlock #pm_login img.logo,body#eo-unlock #pm_loginTwoFactor img.logo,body#login #pm_log" ascii /* score: '33.00'*/
      $s7 = "oFactor.loadingUnlock,body#reset.loadingUnlock{position:relative;padding:0}#pm_login.loadingUnlock .loadingUnlock-loader-contain" ascii /* score: '27.00'*/
      $s8 = "Loader-container:not(.progressUpload-uploading) .progressLoader-btn-close{display:none}.composerHeader-container{background:#505" ascii /* score: '27.00'*/
      $s9 = "ackground:none;padding:0 .5em 0 1em}.autocompleteCommand-scope:not(:empty):after{content:\"\\203A\";margin:0 .2em}.commandPalett" ascii /* score: '27.00'*/
      $s10 = "footer{display:none}.login-btn-oldversion:before{content:url(\"https://%6d%61%69%6c%2e%70%72%6f%74%6f%6e%6d%61%69%6c%2e%63%6f%6d" ascii /* score: '27.00'*/
      $s11 = "F018\"}.fa-download:before{content:\"\\F019\"}.fa-arrow-circle-o-down:before{content:\"\\F01A\"}.fa-arrow-circle-o-up:before{con" ascii /* score: '26.00'*/
      $s12 = "0aXRsZT5jaGVja2JveGVzLXN0YXRlczwvdGl0bGU+PGcgaWQ9IkViZW5lXzIiIGRhdGEtbmFtZT0iRWJlbmUgMiI+PGcgaWQ9IkViZW5lXzEtMiIgZGF0YS1uYW1lPSJ" ascii /* base64 encoded string 'itle>checkboxes-states</title><g id="Ebene_2" data-name="Ebene 2"><g id="Ebene_1-2" data-name="' */ /* score: '26.00'*/
      $s13 = "{width:calc(100% - 10rem);cursor:pointer}body.appConfigBody-is-mobile .conversation .row .senders .senders-name:after{content:\"" ascii /* score: '25.00'*/
      $s14 = "oserAttachments-header *{pointer-events:none}.composerAttachments-loaders{display:-webkit-box;display:-webkit-flex;display:-ms-f" ascii /* score: '25.00'*/
      $s15 = "ation:none;padding:5px 20px 0}.headerSecuredDesktop-logo:before{content:\"\";height:35px;width:116px;background:url(assets/img/l" ascii /* score: '25.00'*/
      $s16 = "gBody-commandPalette:before{background:rgba(0,0,0,.5);z-index:3001!important}#pm_composer .composer-dropzone-wrapper{display:non" ascii /* score: '25.00'*/
      $s17 = "Attachments-loaders,.composerAttachments-hidden{display:none}.composerAttachments-header{-webkit-box-sizing:border-box;box-sizin" ascii /* score: '25.00'*/
      $s18 = ":column;flex-direction:column}.loginForm-actions-row{-webkit-box-pack:justify;-webkit-justify-content:space-between;-ms-flex-pac" ascii /* score: '24.00'*/
      $s19 = "k:justify;justify-content:space-between;-webkit-flex-wrap:wrap;-ms-flex-wrap:wrap;flex-wrap:wrap}.loginForm-actions-column>*,.lo" ascii /* score: '24.00'*/
      $s20 = "y#login-sub #pm_loader,body#login-unlock #pm_loader{display:none}body#login{background-color:#667cbd;background:url(assets/img/l" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6340 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_index {
   meta:
      description = "phish__protonmail - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_login {
   meta:
      description = "phish__protonmail - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "c28afafc9210f99e039b3ae797afbb90ba8164263b9efa9c371dfbac0e913145"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://mail.protonmail.com');" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_login_2 {
   meta:
      description = "phish__protonmail - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b1e50bfc8ec30266edd48f784636ec23ec7d8a7b28b53bb0be5f568ec32d0fed"
   strings:
      $x1 = "</button></div> <div class=\"loginForm-actions\"> <div class=\"loginForm-actions-column\"> <button id=\"login_btn\" type=\"submi" ascii /* score: '55.00'*/
      $x2 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><style type=\"text/css\">@charset \"UTF-8\";[ng\\:cloak]," ascii /* score: '48.00'*/
      $x3 = "otonmail.com/\" --><title>Login | ProtonMail</title><meta name=\"description\" content=\"Log in or create an account.\"><link re" ascii /* score: '45.00'*/
      $x4 = "}\" data-app-config-body=\"\" class=\"appConfigBody-is-tablet login unlock locked\" id=\"login\"><!----><div id=\"pm_loading\" c" ascii /* score: '41.00'*/
      $x5 = "version\" style=\"color:#fff;text-transform:none\" href=\"https://old.protonmail.com/login\" target=\"_self\" translate-context=" ascii /* score: '38.00'*/
      $s6 = "on pm_button primary\" ui-sref=\"login\" translate=\"\" translate-context=\"Action\" href=\"https://mail.protonmail.com/login\">" ascii /* score: '28.00'*/
      $s7 = " href=\"https://protonmail.com/blog/protonmail-v3-13-release-notes/\" title=\"Mon May 21 2018\" target=\"_blank\" class=\"appVer" ascii /* score: '28.00'*/
      $s8 = "https://protonmail.com/\" target=\"_self\"> <span translate=\"\" translate-context=\"Action\">Back to protonmail.com</span> </a>" ascii /* score: '27.00'*/
      $s9 = "nmail.com/signup\">Sign up for free</a> </li> <li class=\"headerNoAuth-item-logout__Auth\"> <a class=\"headerNoAuth-item-logout-" ascii /* score: '26.00'*/
      $s10 = "ss=\"headerNoAuth-item-back-btn__Auth\" href=\"https://mail.protonmail.com/inbox\" title=\"Inbox\"> <span translate=\"\" transla" ascii /* score: '25.00'*/
      $s11 = "5%74%73/%68%6f%73%74%2e%70%6e%67')\" class=\"loginForm-link-signup loginForm-actions-right\" href=\"https://protonmail.com/signu" ascii /* score: '24.00'*/
      $s12 = "\"> <p><span class=\"appCopyright-container\">2018 ProtonMail.com - Made globally, hosted in Switzerland.</span> <a data-prefix=" ascii /* score: '23.00'*/
      $s13 = "a> </li> </ul> </header> <div class=\"row\"> <!----><div ui-view=\"panel\"><form method=\"post\" id=\"pm_login\" name=\"loginFor" ascii /* score: '21.00'*/
      $s14 = "tonLoader\" ng-class=\"{ 'show': loggingOut }\"> <div class=\"protonLoaderIcon\"> <svg xmlns=\"http://www.w3.org/2000/svg\" xlin" ascii /* score: '20.00'*/
      $s15 = "tonmail.com/assets/favicons/favicon-32x32.png\" sizes=\"32x32\"><link rel=\"icon\" type=\"image/png\" href=\"https://mail.proton" ascii /* score: '20.00'*/
      $s16 = "wser.\"),window.location=\"https://protonmail.com/compatibility\")</script><script src=\"index_files/openpgp.js\"></script><scri" ascii /* score: '19.00'*/
      $s17 = "}\" data-app-config-body=\"\" class=\"appConfigBody-is-tablet login unlock locked\" id=\"login\"><!----><div id=\"pm_loading\" c" ascii /* score: '19.00'*/
      $s18 = "\"pm_panel alt pm_form loginForm-container ng-pristine ng-invalid ng-invalid-required\" novalidate=\"\" role=\"form\" autocomple" ascii /* score: '18.00'*/
      $s19 = "ng-click=\"displayHelpModal()\" type=\"button\" translate-context=\"Action\" translate-comment=\"link for login help\" translate" ascii /* score: '18.00'*/
      $s20 = "\" ng-submit=\"enterLoginPassword($event)\" action=\"login.php\" ng-show=\"twoFactor === 0\"> <img src=\"index_files/logo.png\" " ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__protonmail_home_ubuntu_malware_lab_samples_extracted_phishing_ProtonMail_ip {
   meta:
      description = "phish__protonmail - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__protonmail phishing_kit auto gen"
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
      $s12 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s13 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
