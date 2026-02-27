/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__snapchat/phish__snapchat_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__snapchat
   Reference: phish__snapchat phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule flags_png {
   meta:
      description = "phish__snapchat - file flags.png.html"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5bd8e93561f0c13019bbad2e557186c895aad82e710082637e0797bc0826976b"
   strings:
      $x1 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><html lang=\"en\"><hea" ascii /* score: '32.00'*/
      $s2 = "itial-scale=1.0\"><link rel=\"stylesheet\" href=\"https://accounts.snapchat.com/accounts/static/styles/404.css\"></head><body><d" ascii /* score: '21.00'*/
      $s3 = "src=\"https://accounts.snapchat.com/accounts/static/images/404.png\"/></body></html>" fullword ascii /* score: '20.00'*/
      $s4 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><html lang=\"en\"><hea" ascii /* score: '18.00'*/
      $s5 = "a charset=\"utf-8\"><meta name=\"referrer\" content=\"origin\"><meta name=\"apple-itunes-app\" content=\"app-id=447188370\"><tit" ascii /* score: '9.00'*/
      $s6 = "ll; Snapchat</title><meta name=\"apple-mobile-web-app-capable\" content=\"no\"><meta name=\"viewport\" content=\"width=device-wi" ascii /* score: '8.00'*/
      $s7 = "ass=\"error-title\">Well, this is awkward!</div><div class=\"error-sub-title\">We couldn't find what you were looking for</div><" ascii /* score: '3.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 2KB and
      1 of ($x*) and all of them
}

rule accounts {
   meta:
      description = "phish__snapchat - file accounts.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "dbdf8875250e2e453b94fc4bca6fe3e43dcdcc6684fb80946904e2e37042e5fb"
   strings:
      $s1 = ".accountsFormError {" fullword ascii /* score: '10.00'*/
      $s2 = ".accountsWideFormError {" fullword ascii /* score: '10.00'*/
      $s3 = ".DownloadMyData tr tr td {" fullword ascii /* score: '10.00'*/
      $s4 = "min-height: calc(100vh - 79px - 311px);" fullword ascii /* score: '8.00'*/
      $s5 = ".accountsNarrowButton.accountsButton-ru-ru {" fullword ascii /* score: '7.00'*/
      $s6 = ".accountsNarrowButton.accountsButton-pt-br {" fullword ascii /* score: '7.00'*/
      $s7 = ".accountsNarrowButton.accountsButton-de-de {" fullword ascii /* score: '7.00'*/
      $s8 = ".accountsWideButton {" fullword ascii /* score: '7.00'*/
      $s9 = ".accountsNarrowButton.accountsButton-fi-fi {" fullword ascii /* score: '7.00'*/
      $s10 = ".accountsNarrowButton.accountsButton-nl-nl {" fullword ascii /* score: '7.00'*/
      $s11 = "padding-bottom: 5rem !important;" fullword ascii /* score: '7.00'*/
      $s12 = "margin-left: auto !important;" fullword ascii /* score: '7.00'*/
      $s13 = ".accountsText {" fullword ascii /* score: '7.00'*/
      $s14 = ".accountsNarrowField {" fullword ascii /* score: '7.00'*/
      $s15 = ".accountsCentered {" fullword ascii /* score: '7.00'*/
      $s16 = ".accountsNarrowButton {" fullword ascii /* score: '7.00'*/
      $s17 = ".accountsNarrowButton.accountsButton-ro-ro {" fullword ascii /* score: '7.00'*/
      $s18 = ".accountsBody {" fullword ascii /* score: '7.00'*/
      $s19 = ".accountsTitle {" fullword ascii /* score: '7.00'*/
      $s20 = ".accountsNarrowButton.accountsButton-it-it {" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x612e and filesize < 5KB and
      8 of them
}

rule snapchat {
   meta:
      description = "phish__snapchat - file snapchat.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "494b8167faba431c364dc43257d6e60ccf8490803bf03648198454fdadaec8f2"
   strings:
      $s1 = ".snapchatHeader .logo {" fullword ascii /* score: '18.00'*/
      $s2 = ".snapchatInvertedHeader h1 .logo {" fullword ascii /* score: '18.00'*/
      $s3 = ".snapchatInvertedHeader h1 {" fullword ascii /* score: '9.00'*/
      $s4 = ".ui.snapchatHeader.stackable.grid .column {" fullword ascii /* score: '9.00'*/
      $s5 = "padding-bottom: 5rem !important;" fullword ascii /* score: '7.00'*/
      $s6 = "margin-top: 2rem !important;" fullword ascii /* score: '7.00'*/
      $s7 = "padding-top: 1rem !important;" fullword ascii /* score: '7.00'*/
      $s8 = "  font-family: 'Dropdown';" fullword ascii /* score: '6.00'*/
      $s9 = "margin-bottom: 1rem;" fullword ascii /* score: '4.00'*/
      $s10 = "width: 75%;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "  font-weight: normal;" fullword ascii /* score: '4.00'*/
      $s12 = ".snapchatFooter.stackable.grid {" fullword ascii /* score: '4.00'*/
      $s13 = "  font-style: normal;" fullword ascii /* score: '4.00'*/
      $s14 = "#navigationMenuButton img {" fullword ascii /* score: '4.00'*/
      $s15 = ".snapchatFooter .column {" fullword ascii /* score: '4.00'*/
      $s16 = "width: 36px;" fullword ascii /* score: '4.00'*/
      $s17 = "padding: 1rem;" fullword ascii /* score: '4.00'*/
      $s18 = ".snapchatFooter.stackable.grid h5 {" fullword ascii /* score: '4.00'*/
      $s19 = "max-width: 240px;" fullword ascii /* score: '4.00'*/
      $s20 = ".snapchatBody.stackable.grid {" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x732e and filesize < 3KB and
      8 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_accounts_static_styles_revoke {
   meta:
      description = "phish__snapchat - file revoke.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "55afb4e61527076483c1929a24971b27b8b366fbc5b72f85b96b051a97c1a263"
   strings:
      $s1 = "    background-clip: padding-box; /* for IE9+, Firefox 4+, Opera, Chrome */" fullword ascii /* score: '8.00'*/
      $s2 = "-ms-transform: translateY(-50%); /* IE 9 */" fullword ascii /* score: '8.00'*/
      $s3 = ".authAppItem .authAppMessageField {" fullword ascii /* score: '7.00'*/
      $s4 = ".authAppItem h3, .authAppItem p {" fullword ascii /* score: '7.00'*/
      $s5 = ".authAppsBody .authText {" fullword ascii /* score: '7.00'*/
      $s6 = ".authAppItem {" fullword ascii /* score: '7.00'*/
      $s7 = "    -webkit-transform: translateY(-50%); /* Safari */" fullword ascii /* score: '7.00'*/
      $s8 = "padding-bottom: 5rem!important;" fullword ascii /* score: '7.00'*/
      $s9 = ".authAppsBody .authSubTitle {" fullword ascii /* score: '7.00'*/
      $s10 = ".authAppItem .ui.button.revokeButton:hover {" fullword ascii /* score: '7.00'*/
      $s11 = ".authAppItem .ui.button.revokeButton {" fullword ascii /* score: '7.00'*/
      $s12 = "color: #262626!important;" fullword ascii /* score: '7.00'*/
      $s13 = "    -webkit-background-clip: padding-box; /* for Safari */" fullword ascii /* score: '7.00'*/
      $s14 = ".authAppsBody {" fullword ascii /* score: '7.00'*/
      $s15 = "width: 75%;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "background-color: #fffc01;" fullword ascii /* score: '4.00'*/
      $s17 = "margin-top: 16px;" fullword ascii /* score: '4.00'*/
      $s18 = "max-width: 500px;" fullword ascii /* score: '4.00'*/
      $s19 = "transform: translateY(-50%);" fullword ascii /* score: '4.00'*/
      $s20 = "border-top: 1px solid rgb(255, 255, 255);" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x612e and filesize < 3KB and
      8 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_accounts_static_styles_auth {
   meta:
      description = "phish__snapchat - file auth.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "87e50f229ef7329e90030981164f7f23dcab7a28527937ea3b15e562ee69e42f"
   strings:
      $s1 = "content: \" \"; " fullword ascii /* score: '9.00'*/
      $s2 = "    background-clip: padding-box; /* for IE9+, Firefox 4+, Opera, Chrome */" fullword ascii /* score: '8.00'*/
      $s3 = "padding-bottom: 5rem!important;" fullword ascii /* score: '7.00'*/
      $s4 = "color: #262626!important;" fullword ascii /* score: '7.00'*/
      $s5 = "    -webkit-background-clip: padding-box; /* for Safari */" fullword ascii /* score: '7.00'*/
      $s6 = ".authCentered {" fullword ascii /* score: '7.00'*/
      $s7 = ".authField {" fullword ascii /* score: '7.00'*/
      $s8 = ".authSmallMarginTop {" fullword ascii /* score: '7.00'*/
      $s9 = ".authBody {" fullword ascii /* score: '7.00'*/
      $s10 = "margin-top: 1rem!important;" fullword ascii /* score: '7.00'*/
      $s11 = ".authClearfix::before, .authClearfix::after {" fullword ascii /* score: '7.00'*/
      $s12 = ".authField.lastField {" fullword ascii /* score: '7.00'*/
      $s13 = ".authFieldMessage {" fullword ascii /* score: '7.00'*/
      $s14 = ".authField.firstField {" fullword ascii /* score: '7.00'*/
      $s15 = ".authButton.authSecondaryButton:hover {" fullword ascii /* score: '7.00'*/
      $s16 = ".authClearfix::after {" fullword ascii /* score: '7.00'*/
      $s17 = ".authText, .authWideInput, .authField {" fullword ascii /* score: '7.00'*/
      $s18 = ".authButton.authSecondaryButton {" fullword ascii /* score: '7.00'*/
      $s19 = ".authSubTitle {" fullword ascii /* score: '7.00'*/
      $s20 = ".authFieldIcon {" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x612e and filesize < 4KB and
      8 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_login {
   meta:
      description = "phish__snapchat - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "258d9e4ddb5c006c4ffd3613ecebfce7b29601db66a02d33b30571f388832462"
   strings:
      $x1 = "}</style><style type=\"text/css\">:root a[href^=\"http://ad-apac.doubleclick.net/\"], :root .GKJYXHBF2 > .GKJYXHBE2 > .GKJYXHBH5" ascii /* score: '69.00'*/
      $x2 = "    </style><div class=\"cookie-icon cookie-icon-left\" style=\"position: absolute; width: 240px; height: 120px; background: url" ascii /* score: '48.00'*/
      $x3 = "lesdownloader.com/\"], :root a[href^=\"http://www.quick-torrent.com/download.html?aff\"], :root a[href^=\"http://mo8mwxi1.com/\"" ascii /* score: '38.00'*/
      $x4 = "mhill.com/redirect.aspx?\"], :root a[href^=\"http://adserver.adtech.de/\"], :root a[href^=\"http://www.1clickdownloader.com/\"]," ascii /* score: '38.00'*/
      $x5 = " Snapchat</title><!-- Meta --><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"origin\"><meta name=\"apple-mobile-web-a" ascii /* score: '35.00'*/
      $x6 = "://www.sfippa.com/\"], :root a[href^=\"http://www.socialsex.com/\"], :root a[href^=\"http://www.torntv-downloader.com/\"], :root" ascii /* score: '35.00'*/
      $x7 = "down^=\"this.href='http://paid.outbrain.com/network/redir?\"][target=\"_blank\"] + .ob_source, :root a[onmousedown^=\"this.href=" ascii /* score: '34.00'*/
      $x8 = "net.com/i/\"], :root a[href^=\"http://www1.clickdownloader.com/\"], :root a[href^=\"http://www5.smartadserver.com/call/pubjumpi/" ascii /* score: '34.00'*/
      $x9 = "\"this.href='http://staffpicks.outbrain.com/network/redir?\"][target=\"_blank\"] + .ob_source, :root a[href^=\"http://games.ucoz" ascii /* score: '34.00'*/
      $x10 = "class^=\"ads-partner-\"], :root #\\5f _mom_ad_12, :root a[href^=\"http://lp.ncdownloader.com/\"], :root .inlineNewsletterSubscri" ascii /* score: '34.00'*/
      $x11 = "=\"], :root a[onmousedown^=\"this.href='https://paid.outbrain.com/network/redir?\"][target=\"_blank\"] + .ob_source, :root a[hre" ascii /* score: '34.00'*/
      $x12 = "ord</a><!-- react-text: 27 --> / <!-- /react-text --><a href=\"https://accounts.snapchat.com/accounts/signup\">CREATE ACCOUNT</a" ascii /* score: '33.00'*/
      $x13 = "http://lp.ezdownloadpro.info/\"], :root a[data-widget-outbrain-redirect^=\"http://paid.outbrain.com/network/redir?\"], :root a[h" ascii /* score: '31.00'*/
      $s14 = "ef^=\"http://www.myvpn.pro/\"], :root a[onmousedown^=\"this.href='http://paid.outbrain.com/network/redir?\"][target=\"_blank\"]," ascii /* score: '30.00'*/
      $s15 = "\"], :root a[href^=\"http://clk.directrev.com/\"], :root a[href^=\"http://galleries.pinballpublishernetwork.com/\"], :root a[tar" ascii /* score: '30.00'*/
      $s16 = "in-height:250px\"][href^=\"http://li.cnet.com/click?\"], :root a[target=\"_blank\"][onmousedown=\"this.href^='http://paid.outbra" ascii /* score: '30.00'*/
      $s17 = "r.com/?AFF_ID=\"], :root a[onmousedown^=\"this.href='http://staffpicks.outbrain.com/network/redir?\"][target=\"_blank\"], :root " ascii /* score: '30.00'*/
      $s18 = "link rel=\"stylesheet\" href=\"/accounts/static/styles/revoke.css\"><!-- Scripts --><script src=\"/accounts/static/scripts/jquer" ascii /* score: '29.00'*/
      $s19 = "xtgem.com/click?\"], :root a[href*=\"=Adtracker\"], :root a[href^=\"http://www.downloadweb.org/\"], :root a[href*=\"ad2upapp.com" ascii /* score: '29.00'*/
      $s20 = "kssolutions.com/\"], :root a[href^=\"http://www.easydownloadnow.com/\"], :root a[href^=\"http://www.epicgameads.com/\"], :root a" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule dropdown_min {
   meta:
      description = "phish__snapchat - file dropdown.min.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "cb90820edef6ff76150e4795a54491ed695f5621a9fc5e13284f9b3c11efde32"
   strings:
      $x1 = " */.ui.dropdown{cursor:pointer;position:relative;display:inline-block;outline:0;text-align:left;-webkit-transition:box-shadow .1" ascii /* score: '51.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */ /* score: '26.50'*/
      $s3 = " * http://github.com/semantic-org/semantic-ui/" fullword ascii /* score: '21.00'*/
      $s4 = "AG8AbQBvAG8Abmljb21vb24AaQBjAG8AbQBvAG8AbgBSAGUAZwB1AGwAYQByAGkAYwBvAG0AbwBvAG4ARgBvAG4AdAAgAGcAZQBuAGUAcgBhAHQAZQBkACAAYgB5ACAA" ascii /* base64 encoded string 'omoonicomoonicomoonRegularicomoonFont generated by ' */ /* score: '17.00'*/
      $s5 = "ALgAwAGkAYwBvAG0AbwBvAG5pY29tb29uAGkAYwBvAG0AbwBvAG4AUgBlAGcAdQBsAGEAcgBpAGMAbwBtAG8AbwBuAEYAbwBuAHQAIABnAGUAbgBlAHIAYQB0AGUAZAA" ascii /* base64 encoded string '.0icomoonicomoonicomoonRegularicomoonFont generated' */ /* score: '17.00'*/
      $s6 = "AAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '0' */ /* score: '16.50'*/
      $s7 = " .menu{box-shadow:0 -2px 3px 0 rgba(0,0,0,.08)}.ui.dropdown .scrolling.menu,.ui.scrolling.dropdown .menu{overflow-x:hidden;overf" ascii /* score: '14.00'*/
      $s8 = " * # Semantic UI 2.1.7 - Dropdown" fullword ascii /* score: '14.00'*/
      $s9 = "mage.floated,.ui.dropdown .menu .item>img.floated{margin-top:0}.ui.dropdown .menu>.header{margin:1rem 0 .75rem;padding:0 1.14285" ascii /* score: '14.00'*/
      $s10 = " * http://opensource.org/licenses/MIT" fullword ascii /* score: '14.00'*/
      $s11 = "n>i.icon:before{top:0!important;left:0!important}.ui.loading.dropdown>i.icon:before{position:absolute;content:'';top:50%;left:50" ascii /* score: '14.00'*/
      $s12 = ".dropdown .menu{min-width:calc(100% - 17px)}}@media only screen and (max-width:767px){.ui.dropdown .scrolling.menu,.ui.scrolling" ascii /* score: '14.00'*/
      $s13 = "-top-width:1px!important;border-bottom-width:0!important;box-shadow:0 -2px 3px 0 rgba(0,0,0,.08)}.ui.upward.selection.dropdown:h" ascii /* score: '13.00'*/
      $s14 = "0,0,.4)}.ui.dropdown .menu .menu{top:0!important;left:100%!important;right:auto!important;margin:0 0 0 -.5em!important;border-ra" ascii /* score: '13.00'*/
      $s15 = "width:auto!important;border-top:1px solid rgba(34,36,38,.15)}.ui.dropdown .scrolling.menu>.item.item.item,.ui.scrolling.dropdown" ascii /* score: '13.00'*/
      $s16 = " .menu .item.item.item{border-top:none;padding-right:calc(1.14285714rem + 17px)!important}.ui.dropdown .scrolling.menu .item:fir" ascii /* score: '13.00'*/
      $s17 = ":hidden;-webkit-overflow-scrolling:touch;min-width:100%!important;width:auto!important}.ui.dropdown .scrolling.menu{position:sta" ascii /* score: '13.00'*/
      $s18 = "item .dropdown.icon:before{content:\"\\f0d9\"}.ui.vertical.menu .dropdown.item>.dropdown.icon:before{content:\"\\f0da\"}" fullword ascii /* score: '13.00'*/
      $s19 = "1em;opacity:.8;-webkit-transition:opacity .1s ease;transition:opacity .1s ease}.ui.compact.selection.dropdown{min-width:0}.ui.se" ascii /* score: '13.00'*/
      $s20 = "own .filtered.item{display:none!important}.ui.dropdown.error,.ui.dropdown.error>.default.text,.ui.dropdown.error>.text{color:#9F" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule semantic_min {
   meta:
      description = "phish__snapchat - file semantic.min.css"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1081ac22f6016a281599972a28e64518ab215ed56877fb473205f575e16cf2c7"
   strings:
      $x1 = "*,:after,:before{box-sizing:inherit}html{box-sizing:border-box;font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-siz" ascii /* score: '74.00'*/
      $x2 = "';left:-1em;height:100%;vertical-align:baseline}.ui.message ul.list li:last-child{margin-bottom:0}.ui.message>.icon{margin-right" ascii /* score: '56.00'*/
      $x3 = "';opacity:1;color:rgba(0,0,0,.8);vertical-align:top}.ui.bulleted.list .list,ul.ui.list ul{padding-left:1rem}.ui.horizontal.bulle" ascii /* score: '53.00'*/
      $s4 = "}i.icon.subscript:before{content:\"\\f12c\"}i.icon.header:before{content:\"\\f1dc\"}i.icon.paragraph:before{content:\"\\f1dd\"}i" ascii /* score: '29.00'*/
      $s5 = "before{content:\"\\f14b\"}i.icon.compass:before{content:\"\\f14e\"}i.icon.eur:before{content:\"\\f153\"}i.icon.gbp:before{conten" ascii /* score: '28.00'*/
      $s6 = "\\f0fc\"}i.icon.plus.square:before{content:\"\\f0fe\"}i.icon.computer:before{content:\"\\f108\"}i.icon.asexual:before,i.icon.cir" ascii /* score: '28.00'*/
      $s7 = "e{content:\"\\f088\"}i.icon.heart.outline:before{content:\"\\f08a\"}i.icon.log.out:before{content:\"\\f08b\"}i.icon.thumb.tack:b" ascii /* score: '27.00'*/
      $s8 = "n.add.user:before{content:\"\\f234\"}i.icon.remove.user:before{content:\"\\f235\"}i.icon.help.circle:before{content:\"\\f059\"}i" ascii /* score: '26.00'*/
      $s9 = "con.rocket:before{content:\"\\f135\"}i.icon.anchor:before{content:\"\\f13d\"}i.icon.bullseye:before{content:\"\\f140\"}i.icon.su" ascii /* score: '26.00'*/
      $s10 = "con.add.circle:before{content:\"\\f055\"}i.icon.remove.circle:before{content:\"\\f057\"}i.icon.check.circle:before{content:\"\\f" ascii /* score: '26.00'*/
      $s11 = "ing:0!important;width:-webkit-calc(100% - 2em)!important;width:calc(100% - 2em)!important}}.ui.cards>.card{font-size:1em}.ui.com" ascii /* score: '25.00'*/
      $s12 = "ield:before{content:\"\\f132\"}i.icon.target:before{content:\"\\f140\"}i.icon.play.circle:before{content:\"\\f144\"}i.icon.penci" ascii /* score: '25.00'*/
      $s13 = "\"\\f05e\"}i.icon.mail.forward:before,i.icon.share:before{content:\"\\f064\"}i.icon.expand:before{content:\"\\f065\"}i.icon.comp" ascii /* score: '25.00'*/
      $s14 = "int.brush:before{content:\"\\f1fc\"}i.icon.heartbeat:before{content:\"\\f21e\"}i.icon.download:before{content:\"\\f019\"}i.icon." ascii /* score: '24.00'*/
      $s15 = "con.woman:before{content:\"\\f221\"}i.icon.man:before{content:\"\\f222\"}i.icon.non.binary.transgender:before{content:\"\\f223\"" ascii /* score: '24.00'*/
      $s16 = "s;transition-delay:.1s}.ui.minimal.comments .comment>.content:hover>.actions{opacity:1}.ui.small.comments{font-size:.9em}.ui.com" ascii /* score: '23.00'*/
      $s17 = "re{content:\"\\f187\"}i.icon.dot.circle.outline:before{content:\"\\f192\"}i.icon.sliders:before{content:\"\\f1de\"}i.icon.wi-fi:" ascii /* score: '23.00'*/
      $s18 = "t.square:before{content:\"\\f1a2\"}i.icon.stumbleupon.circle:before{content:\"\\f1a3\"}i.icon.stumbleupon:before{content:\"\\f1a" ascii /* score: '23.00'*/
      $s19 = "con.remove.circle.outline:before{content:\"\\f05c\"}i.icon.check.circle.outline:before{content:\"\\f05d\"}i.icon.plus:before{con" ascii /* score: '23.00'*/
      $s20 = "re{content:\"\\f19d\"}i.icon.spy:before{content:\"\\f21b\"}i.icon.female:before{content:\"\\f182\"}i.icon.male:before{content:\"" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2f20 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_accounts_static_scripts_main {
   meta:
      description = "phish__snapchat - file main.js"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "0f17300e4a9c90544ecc30f37a83d3a972102ae034ad625833a7a96740397cc3"
   strings:
      $x1 = "!function(n,i){a=[],r=i,void 0!==(o=\"function\"==typeof r?r.apply(t,a):r)&&(e.exports=o)}(0,function(){\"use strict\";function " ascii /* score: '86.00'*/
      $x2 = "\",n))),l.a.createElement(f.Col,{xs:12,md:5},l.a.createElement(\"div\",{className:\"sign-up-success-container-device\"},l.a.crea" ascii /* score: '81.00'*/
      $x3 = "lectionner l'heure\"};t.default=r,e.exports=t.default},function(e,t,n){\"use strict\";function r(e){return e&&e.__esModule?e:{de" ascii /* score: '80.00'*/
      $x4 = "\",b.a.createElement(\"a\",{href:\"/accounts/login\"+window.location.search,onClick:n.switchToLogInPage},\"Log In\"));default:re" ascii /* score: '78.00'*/
      $x5 = "ve requested your data and haven't received it yet, please wait until you've downloaded your data to delete your account. We won" ascii /* score: '77.00'*/
      $x6 = "\"}})})},function(e,t,n){\"use strict\";n.d(t,\"a\",function(){return r});var r;!function(e){e[e.NONE=-1]=\"NONE\",e[e.PRIMARY=0" ascii /* score: '75.50'*/
      $x7 = "var a=Object.getOwnPropertySymbols,o=Object.prototype.hasOwnProperty,i=Object.prototype.propertyIsEnumerable;e.exports=function(" ascii /* score: '75.00'*/
      $x8 = "cle suivant\"},e.exports=t.default},function(e,t,n){\"use strict\";Object.defineProperty(t,\"__esModule\",{value:!0});var r=n(99" ascii /* score: '73.00'*/
      $x9 = "\",u.a.createElement(\"a\",{target:\"_blank\",rel:\"noopener noreferrer\",href:\"https://www.snap.com/privacy/privacy-policy/\"}" ascii /* score: '73.00'*/
      $x10 = "function r(e,t){if(!i.default.canUseDOM||t&&!(\"addEventListener\"in document))return!1;var n=\"on\"+e,r=n in document;if(!r){va" ascii /* score: '73.00'*/
      $x11 = "!function(){\"use strict\";function n(){for(var e=[],t=0;t<arguments.length;t++){var r=arguments[t];if(r){var a=typeof r;if(\"st" ascii /* score: '69.00'*/
      $x12 = "\"]]),a=(t.DEFAULT_AVAILABLE_LOCALES=[\"da-DK\",\"de-DE\",\"en-US\",\"en-GB\",\"es\",\"fr-FR\",\"it-IT\",\"ja-JP\",\"nl-NL\",\"n" ascii /* score: '69.00'*/
      $x13 = "function r(e,t){if(!o.canUseDOM||t&&!(\"addEventListener\"in document))return!1;var n=\"on\"+e,r=n in document;if(!r){var i=docu" ascii /* score: '66.50'*/
      $x14 = " \",\" Bitmoji \"))))),l.a.createElement(\"div\",{className:\"sixteen wide column\",style:s},l.a.createElement(\"div\",{classNam" ascii /* score: '66.00'*/
      $x15 = "\"))},this.getInputDOMNode=function(){return e.topCtrlRef?e.topCtrlRef.querySelector(\"input,textarea,div[contentEditable]\"):e." ascii /* score: '65.00'*/
      $x16 = "var i=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)t.hasOwn" ascii /* score: '65.00'*/
      $x17 = "for(o=97;o<123;o++)r[String.fromCharCode(o)]=o-32;for(var o=48;o<58;o++)r[o-48]=o;for(o=1;o<13;o++)r[\"f\"+o]=o+111;for(o=0;o<10" ascii /* score: '63.00'*/
      $x18 = "!function(n,i){a=[t,e],r=i,void 0!==(o=\"function\"==typeof r?r.apply(t,a):r)&&(e.exports=o)}(0,function(e,t){\"use strict\";fun" ascii /* score: '63.00'*/
      $x19 = "\"use strict\";function n(e){if(null===e||void 0===e)throw new TypeError(\"Object.assign cannot be called with null or undefined" ascii /* score: '62.50'*/
      $x20 = "\"},\" \")]}},{key:\"renderSearchingState\",value:function(){return D.default.createElement(\"div\",null,D.default.createElement" ascii /* score: '62.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 12000KB and
      1 of ($x*)
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_index {
   meta:
      description = "phish__snapchat - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_login_2 {
   meta:
      description = "phish__snapchat - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "64efc8e483d1d8e59f7e69bd0d6446970e8d1006ddb329b9d07c1460d300071a"
   strings:
      $s1 = "header('Location: https://accounts.snapchat.com/accounts/login');" fullword ascii /* score: '29.00'*/
      $s2 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__snapchat_home_ubuntu_malware_lab_samples_extracted_phishing_Snapchat_ip {
   meta:
      description = "phish__snapchat - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__snapchat phishing_kit auto gen"
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
      $s9 = "if (!empty($_SERVER['HTTP_CLIENT_IP']))" fullword ascii /* score: '7.00'*/
      $s10 = "fwrite($fp, $ipaddress);" fullword ascii /* score: '7.00'*/
      $s11 = "      $ipaddress = $_SERVER['HTTP_CLIENT_IP'].\"\\r\\n\";" fullword ascii /* score: '5.00'*/
      $s12 = "$fp = fopen($file, 'a');" fullword ascii /* score: '4.00'*/
      $s13 = "fwrite($fp, $browser);" fullword ascii /* score: '4.00'*/
      $s14 = "      $ipaddress = $_SERVER['REMOTE_ADDR'].\"\\r\\n\";" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}
