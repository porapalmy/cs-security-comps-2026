/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__spotify/phish__spotify_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__spotify
   Reference: phish__spotify phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule styles__ltr {
   meta:
      description = "phish__spotify - file styles__ltr.css"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1fa89ff0d6cd6e360c58f7fdb1ecec1d4aee2e1f6f3699072c5f9e2852c615ea"
   strings:
      $x1 = ".goog-inline-block{position:relative;display:-moz-inline-box;display:inline-block}* html .goog-inline-block{display:inline}*:fir" ascii /* score: '66.00'*/
      $s2 = "sform.Microsoft.AlphaImageLoader(src='https://www.gstatic.com/recaptcha/api2/logo_48.png',sizingMethod='scale')}.rc-anchor-logo-" ascii /* score: '30.00'*/
      $s3 = "tps://www.gstatic.com/recaptcha/api2/logo_48.png');background-repeat:no-repeat}.rc-anchor-logo-img-ie8{filter:progid:DXImageTran" ascii /* score: '20.00'*/
      $s4 = "argin:5px 20px 5px 20px;text-align:center}.rc-audiochallenge-tdownload-link{background-image:url('https://www.gstatic.com/recapt" ascii /* score: '19.00'*/
      $s5 = ".com/recaptcha/api2/canonical_bridge.png');background-repeat:no-repeat}.rc-coref-payload{padding:10px;font-family:Roboto,helveti" ascii /* score: '19.00'*/
      $s6 = "utton-radio{background:url(//ssl.gstatic.com/ui/v1/radiobutton/unchecked_focused.png) -3px -3px;background:rgba(255,255,255,0)}." ascii /* score: '18.00'*/
      $s7 = "ton-checked .jfk-radiobutton-radio{background:url(//ssl.gstatic.com/ui/v1/radiobutton/checked-disabled.png) -3px -3px;background" ascii /* score: '18.00'*/
      $s8 = "z-box-sizing:border-box;box-sizing:border-box;background:url(//ssl.gstatic.com/ui/v1/radiobutton/unchecked.png) -3px -3px;backgr" ascii /* score: '18.00'*/
      $s9 = "c.com/ui/v1/radiobutton/checked.png) -3px -3px;background:rgba(255,255,255,0)}.jfk-radiobutton.jfk-radiobutton:focus .jfk-radiob" ascii /* score: '18.00'*/
      $s10 = "der-box;text-align:center;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none}.rc-imageselect-target>div:hover{}" ascii /* score: '17.00'*/
      $s11 = "ding:1px}.rc-image-tile-target tr,td{margin:0}.rc-imageselect-keyboard{outline:solid orange!important;position:relative;z-index:" ascii /* score: '17.00'*/
      $s12 = "a9op/Blh8jE+opghoHpAyTmPMRZKobXSKGcTHWMQY7wqDGMEkxQ3Uj2Z6hjfrunVghe44QzG+I9I8jFqbqw0xBiXpDVgPKl8GOP2jMd3ie+9VOTJGM8CSWyX01z5S4eC" ascii /* score: '17.00'*/
      $s13 = "POFjQtQPHvAORpi+f5qx2cVkrXstQci4K2s9wgxY01zEbgW2O1PbeoIRCnqdfI5JEYwXoqg8aScOqRKMtR4NRKREY619hnekzCoOPRmqc8JAdfZUrPWbwFx3KGs+ooYu" ascii /* score: '16.00'*/
      $s14 = "65je0wLoGHlIvl7uk1GFEBeB+Rj7VsDQ8IxWxSE9iDEeIJIxQg4dVL46EoGFrwLC23cl+rNRQAIAHuC8z61lRrNbSdBtE3DrvBJvIUbG7NCjzIrx+H/cHDorcnQOHVlR" ascii /* score: '16.00'*/
      $s15 = "qKmxFRXRA4dsArc6HLZBFVNhXX40OKHwboIvyYZNuChX2vPOaVWME3Rp8wrcBOiUftpF7a9VRgS+6qFm9/Xazqq1tVnV1uQk+4As+DUzE6J0vDzqU8EelonrQAb5L8u1" ascii /* score: '16.00'*/
      $s16 = "PBipy1SR/42YffU/9hXPTmKjyTV0A1AZOTmGbwh8nQhia2ASQDALnVlrKG4IIsUk6uJhf9aaWq68eYvHf5kOsvDCGofgMjB0SFUNTtwllwu4Dy9+FAKe6MwiPEzYHdBU" ascii /* score: '16.00'*/
      $s17 = "4vyCEYeYsk9ZbQ5r3UmsxW4eciZ3jBMT9mbyrNvV/3Y5xJRerHVsiqAQax2DVOkLxVq3MYeW00tRWOt2z+HtK7P2cPZAwYCGQezl7DdVrRlY63QTokfpUL+SPjWM3Sl3" ascii /* score: '16.00'*/
      $s18 = "kINVJ1dblpOgXJKd/a8sbs98pg6U3i9DJh7xDgTRhlxr/ezMglNHzZx9MRuo1afHyySLY4uy4SbDXeYCStwc8/Cdie5AXl1a1rPDUU5khEADdKX4/M38EMNOwYOgZl9D" ascii /* score: '16.00'*/
      $s19 = "gDtR6Wasyi5BmoAOQPbT+n1ZlFiFNj1xhnqf1DoBd/dyGyt+W76z84LOGys/3xUg4xjlcY6hIe14OMM/TegfAFi1aVFldXV1ZV1dX+cUXX5BwjHO4xlCR9rwcYA7W+h8" ascii /* score: '16.00'*/
      $s20 = "BKTT3Ci6/GCTU26HjhlOGMaIe4qjDJVuOccG6BifErZ4koINVARwA03ud49w/WJiDc1clsJLxFC8No1DmrOLotu74D9vo/CsK42/eCD+UqUKY/yUVpG8jPDIA/GpOHra" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x672e and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule hVpKLs9k787xwHAhrfSZCIqM1XtnPD1dxAE7zC2jvTU {
   meta:
      description = "phish__spotify - file hVpKLs9k787xwHAhrfSZCIqM1XtnPD1dxAE7zC2jvTU.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "855a4a2ecf64efcef1c07021adf499088a8cd57b673c3d5dc4013bcc2da3bd35"
   strings:
      $x1 = "/* Anti-spam. Want to say hello? Contact (base64) Ym90Z3VhcmQtY29udGFjdEBnb29nbGUuY29t */ Function('var R=this,b=function(A,m,q," ascii /* score: '38.50'*/
      $s2 = "/* Anti-spam. Want to say hello? Contact (base64) Ym90Z3VhcmQtY29udGFjdEBnb29nbGUuY29t */ Function('var R=this,b=function(A,m,q," ascii /* score: '15.00'*/
      $s3 = "ch(A){}try{R.addEventListener(\"test\",null,Object.defineProperty({},\"passive\",{get:function(){e={passive:true}}}))}catch(A){}" ascii /* score: '11.00'*/
      $s4 = "T=function(A,m){for(m=[];A--;)m.push(255*Math.random()|0);return m},K=function(A,m){A.U=(\"E:\"+m.message+\":\"+m.stack).slice(0" ascii /* score: '10.00'*/
      $s5 = "f(A,242,function(A,m,q){S(A,1,5)||(m=A.J(),q=A.J(),f(A,q,function(A){return eval(A)}(A.c(m))))}),A.K=[],m)&&\"!\"==m.charAt(0)?(" ascii /* score: '9.00'*/
      $s6 = "0;E<H;E+=D)q(m.slice(E,E+D),A)}}),f)(A,96,function(){}),f(A,220,function(A){b(A,1)}),f)(A,89,function(A,m,q,D){if(m=A.j.pop()){f" ascii /* score: '7.00'*/
      $s7 = "(C(A,g),O(A,true,false,false)):P=h(A,g);return P}},S=(B.prototype.F=(window.performance||{}).now?function(){return this.Je+(wind" ascii /* score: '7.00'*/
      $s8 = "removeEventListener(A[1],A[2],false)}),f)(A,214,0),f(A,45,function(A,m,q,D){(q=(m=A.J(),A).J(),D=A.J(),f)(A,D,A.c(m)||A.c(q))})," ascii /* score: '7.00'*/
      $s9 = ")),A).c(A.J()),A).c(q),A.c(D)),0)!==m&&(D=r(A,D,E,1,m,q),m.addEventListener(q,D,e),f(A,152,[m,q,D]))}),f)(A,153,function(A){A.M&" ascii /* score: '7.00'*/
      $s10 = "(q&&m&&L(A)){E=A,A.cg(function(){O(E,false,m,false)});break}D=(q=true,A).K.pop(),D=h(A,D)}return D}),r=function(A,m,q,D,E,W){ret" ascii /* score: '7.00'*/
      $s11 = "ow.performance.now()|0)}:function(){return+new Date},function(A,m,q){if(0>=A.D||1<A.B||!A.g&&0<m||0!=document.hidden||A.F()-A.o<" ascii /* score: '7.00'*/
      $s12 = "ion(A,m){if(m=this.f[A],void 0===m)throw J(this,30,0,A),this.v;return m()},X=R.botguard||(R.botguard={}),X.EKc=function(A,m,q){(" ascii /* score: '7.00'*/
      $s13 = ";return D=(A=(D+=D<<3,D^=D>>11,D+(D<<15)>>>0),new Number(A&(1<<m)-1)),D[0]=(A>>>m)%q,D},function(A,m,q,D,E){for(;A.K.length;){if" ascii /* score: '6.50'*/
      $s14 = ",E=\"\",A.f)[127])for(l=A.c(127),H=0,y=l.length;q--;)H=(H+N(A))%y,E+=D[l[H]];else for(;q--;)E+=D[A.J()];f(A,m,E)}),f(A,17,functi" ascii /* score: '6.50'*/
      $s15 = "(q=X[A.substring(0,3)])?new q(A.substring(3),m):new X.EKc(A,m)};try{X.u||(R.addEventListener(\"unload\",function(){},e),X.u=1)}c" ascii /* score: '6.00'*/
      $s16 = "nction(A,m,q,D,E){if(4==(m=A[0],m)){A=A[1];try{for(D=(A=(q=atob(A),[]),m=0);D<q.length;D++)E=q.charCodeAt(D),255<E&&(A[m++]=E&25" ascii /* score: '4.00'*/
      $s17 = "eturn\"object\";if(\"[object Array]\"==q||\"number\"==typeof A.length&&\"undefined\"!=typeof A.splice&&\"undefined\"!=typeof A.p" ascii /* score: '4.00'*/
      $s18 = "ut(A,0)},function(A,m,q){return q=A.c(196),A.m&&q<A.m.length?(f(A,196,A.m.length),a(A,m)):f(A,196,m),Z(A,q)}),Z=function(A,m,q,D" ascii /* score: '4.00'*/
      $s19 = "on(A,m){if(this.C)return A=A?this.C().shift():this.w().shift(),this.C().length||this.w().length||(this.w=this.C=void 0,this.B--)" ascii /* score: '4.00'*/
      $s20 = ").push(A[8]<<24|A[9]<<16|A[10]<<8|A[11])},f)(A,83,function(A,m,q){m=(m=A.J(),q=A.J(),A).c(m),f(A,q,Y(m))}),f)(A,73,function(A){z" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_api {
   meta:
      description = "phish__spotify - file api.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "f7a1c7cd63a592edeb73310c39f4e7cf4d3f58b9a68bba72365f2a797e8461ff"
   strings:
      $s1 = "/* PLEASE DO NOT COPY AND PASTE THIS CODE. */(function() {var CFG='___grecaptcha_cfg';if(!window[CFG]){window[CFG]={};}var GR='g" ascii /* score: '28.00'*/
      $s2 = "o=document.createElement('script');po.type='text/javascript';po.async=true;po.src='https://www.gstatic.com/recaptcha/api2/v15288" ascii /* score: '19.00'*/
      $s3 = "'));if(n){po.setAttribute('nonce',n);}var s=document.getElementsByTagName('script')[0];s.parentNode.insertBefore(po, s);})();" fullword ascii /* score: '15.00'*/
      $s4 = "55115741/recaptcha__en.js';var elem=document.querySelector('script[nonce]');var n=elem&&(elem['nonce']||elem.getAttribute('nonce" ascii /* score: '11.00'*/
      $s5 = "/* PLEASE DO NOT COPY AND PASTE THIS CODE. */(function() {var CFG='___grecaptcha_cfg';if(!window[CFG]){window[CFG]={};}var GR='g" ascii /* score: '4.00'*/
      $s6 = "recaptcha';if(!window[GR]){window[GR]={};}window[GR].ready=window[GR].ready||function(f){(window[CFG]['fns']=window[CFG]['fns']|" ascii /* score: '3.00'*/
      $s7 = "1528855115741" ascii /* score: '1.00'*/
      $s8 = "|[]).push(f);};(window[CFG]['render']=window[CFG]['render']||[]).push('explicit');window['__google_recaptcha_client']=true;var p" ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 2KB and
      all of them
}

rule recaptcha__en {
   meta:
      description = "phish__spotify - file recaptcha__en.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "802f005cedac2ee562b3e02cfc9cb8188be89802d3abb3074fccffc0db7cb15b"
   strings:
      $x1 = "break;case 8:b+=\"ERROR for site owner: Invalid key type\";break;case 9:b+=\"ERROR for site owner: Invalid package name\";break;" ascii /* score: '40.00'*/
      $x2 = "V(Kq({id:a.pb,name:a.qb,display:!0}))+\"</div>\")};var Pq=function(a){var b=a.pb,c=a.qb;return U('<div class=\"grecaptcha-badge" ascii /* score: '37.00'*/
      $x3 = "n.xa=function(a,b){if(b)return vp(this.l,a),aq.I.xa.call(this,a,b);Z(this,a,M(\"rc-defaultchallenge-incorrect-response\",void 0)" ascii /* score: '37.00'*/
      $x4 = "Vp.prototype.Ea=function(){this.l.push([]);this.Qa();if(3<this.l.length)return!1;lp(this,!1);Q(function(){lp(this,!0)},500,this)" ascii /* score: '34.00'*/
      $x5 = "d);pj(g);qj(g,!1,a)};f=b.attributes||{};Yb(f,{type:\"text/javascript\",charset:\"UTF-8\"});Nd(e,f);Cd(e,a);Aj(c).appendChild(e);" ascii /* score: '33.00'*/
      $x6 = "var re=function(a,b,c){v(c)&&(c=c.join(\" \"));var d=\"aria-\"+b;\"\"===c||void 0==c?(Zc||(Zc={atomic:!1,autocomplete:\"none\",d" ascii /* score: '33.00'*/
      $x7 = "\"Alternatively, download audio as MP3\".replace(Ql,Rl);return U(a+'\"></a>')},ip=function(a){a=a||{};var b=\"\";a.Be||(b+=\"Pre" ascii /* score: '32.00'*/
      $s8 = "'\"><div id=\"rc-text-target\" class=\"'+W(\"rc-text-target\")+'\" dir=\"ltr\">';a=a.fe;var d=10>a.length?1:2,e=a.length/d;var f" ascii /* score: '30.00'*/
      $s9 = "function Yr(a,b){try{return a[Zr(b)]}catch(c){return null}}function $r(a){try{return a[Zr(\"175206285a0d021a170b714d210f1758\")]" ascii /* score: '30.00'*/
      $s10 = "'<div class=\"'+W(\"rc-prepositional-attribution\")+'\">';b+=\"Sources: \";a=a.dd;for(var c=a.length,d=0;d<c;d++)b+='<a target=" ascii /* score: '30.00'*/
      $s11 = "(e=null)}}else\"mouseover\"==c?e=a.fromElement:\"mouseout\"==c&&(e=a.toElement);this.relatedTarget=e;null===d?(this.clientX=void" ascii /* score: '30.00'*/
      $s12 = "Of()};Jm.prototype.execute=function(a,b){this.o.then(function(b){b.invoke(function(b){a(b)})},function(){b()})};var Km=function(" ascii /* score: '30.00'*/
      $s13 = "p.window&&p.window.__google_recaptcha_client&&(p.window.___grecaptcha_cfg||Ta(\"___grecaptcha_cfg\",{}),p.window.___grecaptcha_c" ascii /* score: '28.00'*/
      $s14 = "var b=a.contentWindow;a=b.document;a.open();a.write(\"\");a.close();var c=\"callImmediate\"+Math.random(),d=\"file:\"==b.locatio" ascii /* score: '28.00'*/
      $s15 = "he=function(a,b){var c=[];ge(a,b,c,!1);return c},ge=function(a,b,c,d){if(null!=a)for(a=a.firstChild;a;){if(b(a)&&(c.push(a),d)||" ascii /* score: '27.00'*/
      $s16 = "users, we can\\'t process your request right now. For more details visit <a href=\"https://developers.google.com/recaptcha/docs/" ascii /* score: '27.00'*/
      $s17 = "t clear, or to get a new challenge, reload the challenge.<a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Lear" ascii /* score: '26.00'*/
      $s18 = "ion and reload.<br><br><a href=\"https://support.google.com/recaptcha#6262736\" target=\"_blank\">Why is this happening to me?</" ascii /* score: '26.00'*/
      $s19 = "yp.prototype.Ma=function(a){Fk(a,ip,{Be:this.P})};var Bp=function(a){return U('<div id=\"rc-canvas\"><canvas class=\"rc-canvas-c" ascii /* score: '26.00'*/
      $s20 = "ew challenge, click the reload icon. <a href=\"https://support.google.com/recaptcha\" target=\"_blank\">Learn more.</a>')};var a" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_login {
   meta:
      description = "phish__spotify - file login.html"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5553c5b0a5505bd8b19fc823887f9539b9e30f624f405aa9294be68205e2a918"
   strings:
      $x1 = "&quot;\" sp-disallow-chars-model=\"usernameDisallowedChars\" autocapitalize=\"off\" autocomplete=\"off\" autocorrect=\"off\" aut" ascii /* score: '60.00'*/
      $x2 = "  <!-- ngView:  --><body ng-view=\"\" class=\"ng-scope\"><div sp-header=\"\" class=\"ng-scope\"><div class=\"head \"> <a class=" ascii /* score: '58.00'*/
      $x3 = "potify's <a href=\"https://www.spotify.com/br/legal/end-user-agreement/plain/\" target=\"_blank\">Terms &amp; Conditions</a> and" ascii /* score: '32.00'*/
      $x4 = "\"onLoginClick($event)\">Log In</button> </div> </div> </form> <!-- ngIf: !iOS && !disableSignup --><div ng-if=\"!iOS &amp;&amp;" ascii /* score: '31.00'*/
      $s5 = "    <!-- base href=\"https://accounts.spotify.com/\" -->" fullword ascii /* score: '28.00'*/
      $s6 = "href=\"https://www.spotify.com/br/legal/privacy-policy/plain/\" target=\"_blank\">Privacy Policy</a>.</p> </div> </div> </div> <" ascii /* score: '27.00'*/
      $s7 = "facebook.com/v2.3/dialog/oauth?client_id=174829003346&amp;state=AQB-Kb-5JrLE65CJt-HB-Z5ZinnCqV1XJtFttc5U68oOHGxVKlV6LFCefH2dHqjt" ascii /* score: '25.00'*/
      $s8 = "utofocus\" ng-trim=\"false\" type=\"text\"> <!-- ngIf: accounts.username.$dirty && accounts.username.$invalid --> </div> </div> " ascii /* score: '23.00'*/
      $s9 = "ptcha --> <div class=\"col-xs-12 col-sm-6\"> <button class=\"btn btn-sm btn-block btn-green ng-binding\" id=\"login-button\" ng-" ascii /* score: '23.00'*/
      $s10 = "- ngIf: !disableSignup --><p ng-if=\"!disableSignup\" class=\"ng-binding ng-scope\"> Don't have an account? <a ng-href=\"https:/" ascii /* score: '22.00'*/
      $s11 = "spotify.com/br/signup/?forward_url=true\" class=\"ng-binding\" href=\"https://www.spotify.com/br/signup/?forward_url=true\">Sign" ascii /* score: '21.00'*/
      $s12 = "word-reset/\" class=\"ng-binding\" href=\"https://www.spotify.com/br/password-reset/\">Forgot your username or password?</a> </p" ascii /* score: '21.00'*/
      $s13 = "6CutdCpOdob68gmqQTD0onsRL0Nqh_U6LOefp8UAyxuKDhScRK4ct9oUkaJxekvJQZRoy1s&amp;redirect_uri=https%3A%2F%2Faccounts.spotify.com%2Fap" ascii /* score: '20.00'*/
      $s14 = "68gmqQTD0onsRL0Nqh_U6LOefp8UAyxuKDhScRK4ct9oUkaJxekvJQZRoy1s&amp;redirect_uri=https%3A%2F%2Faccounts.spotify.com%2Fapi%2Ffaceboo" ascii /* score: '20.00'*/
      $s15 = " && accounts.password.$invalid --> </div> </div> <div class=\"row row-submit\"> <div class=\"col-xs-12 col-sm-6\"> <div class=\"" ascii /* score: '20.00'*/
      $s16 = "    <title ng-bind=\"(title &amp;&amp; (title | localize) + ' - ') + 'Spotify'\" class=\"ng-binding\">Login - Spotify</title>" fullword ascii /* score: '20.00'*/
      $s17 = "k%2Foauth%2Faccess_token\" class=\"btn btn-sm btn-block btn-facebook ng-binding\" target=\"_parent\" role=\"button\" href=\"http" ascii /* score: '19.00'*/
      $s18 = "word\" placeholder=\"Password\" required=\"\" autocomplete=\"off\" ng-trim=\"false\" type=\"password\"> <!-- ngIf: accounts.pass" ascii /* score: '19.00'*/
      $s19 = "ainer-fluid login ng-scope\"> <div class=\"content\"> <div class=\"row\"> <div class=\"col-xs-12\"> <a ng-href=\"https://www.fac" ascii /* score: '19.00'*/
      $s20 = "tus && status !== 200 --> <div class=\"row\" ng-class=\"{'has-error': (accounts.username.$dirty &amp;&amp; accounts.username.$in" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_index {
   meta:
      description = "phish__spotify - file index.css"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "7ad0874abe3e28a8ecdb0183b9772aff858bdbd8cf30354dfd2f0d62f82da178"
   strings:
      $x1 = " *//*! normalize.css v3.0.3 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;-ms-text-size-adjust:" ascii /* score: '67.00'*/
      $s2 = "}.authorize .disclaimer,.login .disclaimer{font-size:.7em}.error .content{text-align:center}.eula .iframe-wrapper{height:350px;o" ascii /* score: '30.00'*/
      $s3 = " * Bootstrap v3.3.7 (http://getbootstrap.com)" fullword ascii /* score: '26.00'*/
      $s4 = "play:inline-block;max-width:100%;width:200px}.head .spotify-logo:before{content:\"\";display:block;padding-top:33.33333333%}.hea" ascii /* score: '25.00'*/
      $s5 = "-superscript:before{content:\"\\E255\"}.glyphicon-subscript:before{content:\"\\E256\"}.glyphicon-menu-left:before{content:\"\\E2" ascii /* score: '24.00'*/
      $s6 = "{content:\"\\E179\"}.glyphicon-header:before{content:\"\\E180\"}.glyphicon-compressed:before{content:\"\\E181\"}.glyphicon-earph" ascii /* score: '23.00'*/
      $s7 = "right-mark:before{content:\"\\E194\"}.glyphicon-registration-mark:before{content:\"\\E195\"}.glyphicon-cloud-download:before{con" ascii /* score: '21.00'*/
      $s8 = " * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)" fullword ascii /* score: '21.00'*/
      $s9 = "\\E158\"}.glyphicon-collapse-down:before{content:\"\\E159\"}.glyphicon-collapse-up:before{content:\"\\E160\"}.glyphicon-log-in:b" ascii /* score: '21.00'*/
      $s10 = "re{content:\"\\E025\"}.glyphicon-download:before{content:\"\\E026\"}.glyphicon-upload:before{content:\"\\E027\"}.glyphicon-inbox" ascii /* score: '21.00'*/
      $s11 = "efore{content:\"\\E022\"}.glyphicon-time:before{content:\"\\E023\"}.glyphicon-road:before{content:\"\\E024\"}.glyphicon-download" ascii /* score: '21.00'*/
      $s12 = "tr(href) \")\"}abbr[title]:after{content:\" (\" attr(title) \")\"}a[href^=\"#\"]:after,a[href^=\"javascript:\"]:after{content:\"" ascii /* score: '21.00'*/
      $s13 = "n-info-sign:before{content:\"\\E086\"}.glyphicon-screenshot:before{content:\"\\E087\"}.glyphicon-remove-circle:before{content:\"" ascii /* score: '20.00'*/
      $s14 = "efore{content:\"\\E103\"}.glyphicon-fire:before{content:\"\\E104\"}.glyphicon-eye-open:before{content:\"\\E105\"}.glyphicon-eye-" ascii /* score: '20.00'*/
      $s15 = "ontent:\"\\E028\"}.glyphicon-play-circle:before{content:\"\\E029\"}.glyphicon-repeat:before{content:\"\\E030\"}.glyphicon-refres" ascii /* score: '20.00'*/
      $s16 = "-arrow-left:before{content:\"\\E132\"}.glyphicon-circle-arrow-up:before{content:\"\\E133\"}.glyphicon-circle-arrow-down:before{c" ascii /* score: '20.00'*/
      $s17 = "ntent:\"\\E129\"}.glyphicon-hand-down:before{content:\"\\E130\"}.glyphicon-circle-arrow-right:before{content:\"\\E131\"}.glyphic" ascii /* score: '20.00'*/
      $s18 = "ntent:\"\\E161\"}.glyphicon-flash:before{content:\"\\E162\"}.glyphicon-log-out:before{content:\"\\E163\"}.glyphicon-new-window:b" ascii /* score: '20.00'*/
      $s19 = ":\"\\E034\"}.glyphicon-headphones:before{content:\"\\E035\"}.glyphicon-volume-off:before{content:\"\\E036\"}.glyphicon-volume-do" ascii /* score: '20.00'*/
      $s20 = ".glyphicon-ok-circle:before{content:\"\\E089\"}.glyphicon-ban-circle:before{content:\"\\E090\"}.glyphicon-arrow-left:before{cont" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x6e2e and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_bframe {
   meta:
      description = "phish__spotify - file bframe.html"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d8caebaf9ce075161c742851b8656885908bd8b0531a68041e7dc18e2363068a"
   strings:
      $s1 = "<html dir=\"ltr\" lang=\"en\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" fullword ascii /* score: '17.00'*/
      $s2 = "ce=\"C/YlxIB2+Y0GHKWfEsri/aar4Hg\"></script></head>" fullword ascii /* score: '15.00'*/
      $s3 = "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">" fullword ascii /* score: '15.00'*/
      $s4 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfABc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s5 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfBBc4.woff2) format" ascii /* score: '13.00'*/
      $s6 = "  src: local('Roboto Regular'), local('Roboto-Regular'), url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2) for" ascii /* score: '13.00'*/
      $s7 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2) form" ascii /* score: '13.00'*/
      $s8 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCxc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s9 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s10 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCBc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s11 = "  src: local('Roboto Regular'), local('Roboto-Regular'), url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7GxKOzY.woff2) for" ascii /* score: '13.00'*/
      $s12 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s13 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCRc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s14 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCxc4EsA.woff2) for" ascii /* score: '13.00'*/
      $s15 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fABc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s16 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2) f" ascii /* score: '13.00'*/
      $s17 = "  src: local('Roboto Black'), local('Roboto-Black'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfBBc4.woff2) format" ascii /* score: '13.00'*/
      $s18 = "  src: local('Roboto Regular'), local('Roboto-Regular'), url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2) for" ascii /* score: '13.00'*/
      $s19 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2) form" ascii /* score: '13.00'*/
      $s20 = "  src: local('Roboto Medium'), local('Roboto-Medium'), url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2) f" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      8 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_anchor {
   meta:
      description = "phish__spotify - file anchor.html"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "1f816ce8967fdcc394fb58e685790d907f4b675fbc8aad054fa92fb5c119fbcc"
   strings:
      $x1 = "    </script><div class=\"rc-anchor rc-anchor-invisible rc-anchor-light  rc-anchor-invisible-hover\"><div id=\"recaptcha-accessi" ascii /* score: '37.00'*/
      $x2 = "dden=\"true\" role=\"presentation\"> - </span><a href=\"https://www.google.com/intl/en/policies/terms/\" target=\"_blank\">Terms" ascii /* score: '35.00'*/
      $x3 = "- </span><a href=\"https://www.google.com/intl/en/policies/terms/\" target=\"_blank\">Terms</a></div></div></div></body></html>" fullword ascii /* score: '31.00'*/
      $s4 = "      recaptcha.anchor.Main.init(\"[\\x22ainput\\x22,[\\x22bgdata\\x22,\\x22Ly93d3cuZ29vZ2xlLmNvbS9qcy9iZy9oVnBLTHM5azc4N3h3SEFo" ascii /* score: '27.00'*/
      $s5 = "ref=\"https://www.google.com/intl/en/policies/privacy/\" target=\"_blank\">Privacy</a><span aria-hidden=\"true\" role=\"presenta" ascii /* score: '27.00'*/
      $s6 = "Z0dCWVVIWlg0Wk04NWRpbFAremZLN080VjlodGRnR0did2VMOEZLYmp5Mm9yb1Q2WDU3V2YrT2RlOGhTQ29uQVFBY0U5SzdLUzgrbzhUNDNDVGMrOHR0akpaTFkzdkw0" ascii /* base64 encoded string 'gGBYUHZX4ZM85dilP+zfK7O4V9htdgGGbweL8FKbjy2oroT6X57Wf+Ode8hSConAQAcE9K7KS8+o8T43CTc+8ttjJZLY3vL4' */ /* score: '26.00'*/
      $s7 = "WVkyN2NCQzUvdm1wZVp0c0V3MkNJbThxNmFieUJhVTFmcmUweUZCVG1mSUg5TDREUTd0Wm5oY283SXFrL20vakhoUlc0MkpSMnNVUnpWMitWMzFOV3JFeG5Td0YyMTgy" ascii /* base64 encoded string 'YY27cBC5/vmpeZtsEw2CIm8q6abyBaU1fre0yFBTmfIH9L4DQ7tZnhco7Iqk/m/jHhRW42JR2sURzV2+V31NWrExnSwF2182' */ /* score: '26.00'*/
      $s8 = "emx0UlIydXE0Z1dBcmpzYUViMW1UNXgwV3NvTWpReS94Rmg1d09meTFrdjZzQzVpeGs3cTRFRGRUNk1ENFVBcnZYeXFNbDNxdEZBZ2VHbjlOYUhZMDcreEFpWWdjUnoy" ascii /* base64 encoded string 'zltRR2uq4gWArjsaEb1mT5x0WsoMjQy/xFh5wOfy1kv6sC5ixk7q4EDdT6MD4UArvXyqMl3qtFAgeGn9NaHY07+xAiYgcRz2' */ /* score: '24.00'*/
      $s9 = "dVNWRzJDejBIUUwvMzZ0N2crOENnQkEySDhzUk9mV2toYWZScDRHaEJlcXc2QTFWbXhtcUd0aFZmM3lXRHhGK1VWZkVuNFppaVRuai8yR1BGNGd0Z09kQWxqcUI5U2l0" ascii /* base64 encoded string 'uSVG2Cz0HQL/36t7g+8CgBA2H8sROfWkhafRp4GhBeqw6A1VmxmqGthVf3yWDxF+UVfEn4ZiiTnj/2GPF4gtgOdAljqB9Sit' */ /* score: '24.00'*/
      $s10 = "cE85OUFnRS8wcmdZZ2poaW9OdldzZlA3Rm5JK3lXQjRVUWlSQkQ0d1A5bHF2cjJnRDBkMWZ3SzBKdFRKd0RtWGt6VHVTN1RodHd3a2ZEYjZlbTRkc2tFdmVIVVBXRStr" ascii /* base64 encoded string 'pO99AgE/0rgYgjhioNvWsfP7FnI+yWB4UQiRBD4wP9lqvr2gD0d1fwK0JtTJwDmXkzTuS7ThtwwkfDb6em4dskEveHUPWE+k' */ /* score: '24.00'*/
      $s11 = "iv><div class=\"rc-anchor-pt\"><a href=\"https://www.google.com/intl/en/policies/privacy/\" target=\"_blank\">Privacy</a><span a" ascii /* score: '23.00'*/
      $s12 = "bTJSb1FiVnM2VVcyMlZQdVlpMDAwdjVYL0xNV2lncE1BanA5dHdDMFhzTmdkeVMvYXkvMXMxUWdJajRRQVhCNkRxRjdPSUxCRXBZR1JzZThEY1lFdUoyZ2F6bGt4NUV4" ascii /* base64 encoded string 'm2RoQbVs6UW22VPuYi000v5X/LMWigpMAjp9twC0XsNgdyS/ay/1s1QgIj4QAXB6DqF7OILBEpYGRse8DcYEuJ2gazlkx5Ex' */ /* score: '21.00'*/
      $s13 = "blFsU1lNZ1V5V05HZ0U1ZmVyN0lPR1dMYmU4ZmIvNkIyUTc3VkNyVktaVkFWR2g4S2ErWVBCRkVZa05hekJoWGVTbDZRSFFkMkczQktlU1c1SmVwenZkbzNjN0NWTXo0" ascii /* base64 encoded string 'nQlSYMgUyWNGgE5fer7IOGWLbe8fb/6B2Q77VCrVKZVAVGh8Ka+YPBFEYkNazBhXeSl6QHQd2G3BKeSW5Jepzvdo3c7CVMz4' */ /* score: '21.00'*/
      $s14 = "dzlMQ1ZTUW5xS29PdTNvWjljQzZWekYvMkxaSWx2bnJYQVhjTEdYdFlvY0psVWQ3bjBERGtQRGhmdzNtUlh4WExvSXk1NDd5dzAxclRVblp6b1RRbDZraWE5NWJBRy9v" ascii /* base64 encoded string 'w9LCVSQnqKoOu3oZ9cC6VzF/2LZIlvnrXAXcLGXtYocJlUd7n0DDkPDhfw3mRXxXLoIy547yw01rTUnZzoTQl6kia95bAG/o' */ /* score: '21.00'*/
      $s15 = "N3VtY0g3Rk9jSjBpTDdqbWFPYURBY1VyckVRT29SeElVMzBBbXNGWU9vaDhZN2RNeTJMZ0VZQTZ2UVE5dXBkM29SRjdEdG9HWTVHN2NrZi9BVDhRYmpSWm1wMG9JeWNj" ascii /* base64 encoded string '7umcH7FOcJ0iL7jmaOaDAcUrrEQOoRxIU30AmsFYOoh8Y7dMy2LgEYA6vQQ9upd3oRF7DtoGY5G7ckf/AT8QbjRZmp0oIycc' */ /* score: '21.00'*/
      $s16 = "cStXcUtDSEJ4cisvb2NyK3N0bkJKbFZnQjcwOEdBejdMWllmaktWbld2Wmx2TlpKVUMvcnJDRkdmL1dRc2hPcGZWUG1mYnV2MFp2Qk5UWjFkWmpSWnY2d2ZHK2tkWk1o" ascii /* base64 encoded string 'q+WqKCHBxr+/ocr+stnBJlVgB708GAz7LZYfjKVnWvZlvNZJUC/rrCFGf/WQshOpfVPmfbuv0ZvBNTZ1dZjRZv6wfG+kdZMh' */ /* score: '21.00'*/
      $s17 = "RkRxbWhwbFhtQW81cUVWbEJrT3FxSXB3QlUyREJDSHBYZUJJblV3bmVtTVVha3pZQ0g4NWZIYXhFSDcrcU92VFNRQWxKc3poQWFOK0xrd2JQRXdYSGN2VWlwQWVXQ1R0" ascii /* base64 encoded string 'FDqmhplXmAo5qEVlBkOqqIpwBU2DBCHpXeBInUwnemMUakzYCH85fHaxEH7+qOvTSQAlJszhAaN+LkwbPEwXHcvUipAeWCTt' */ /* score: '21.00'*/
      $s18 = "OWRKaDYzRmxleGFYUXdsY2VkbnRVbW1yLzk5Z2JvRHVTUEgzLzhsTjVzZ0pmQitKWHFsOTl1OFl2VTVZZ0NmSmN1Z3FIcG1RYmxoaXVXeGp2N0NLcEhOeHMvQkRGZUxh" ascii /* base64 encoded string '9dJh63FlexaXQwlcedntUmmr/99gboDuSPH3/8lN5sgJfB+JXql99u8YvU5YgCfJcugqHpmQblhiuWxjv7CKpHNxs/BDFeLa' */ /* score: '21.00'*/
      $s19 = "bVU2RCtQQUFhTnREZ3VDQWRST3NzaFJoejRsY1dXa25LNEVvSEYvQXNjUGhkUUVkd04zczFkblVJRGJBZWdyREt3Ym9BK3g0RXJLQzdjclE5TjU0eFB6TTE4cGxzTUM4" ascii /* base64 encoded string 'mU6D+PAAaNtDguCAdROsshRhz4lcWWknK4EoHF/AscPhdQEdwN3s1dnUIDbAegrDKwboA+x4ErKC7crQ9N54xPzM18plsMC8' */ /* score: '21.00'*/
      $s20 = "UEtYVkdLallhbjNMdjBzM29ZTUE1eUdEeGF5WHU2N3BBWkVuc1BvMmNPNnovcCsvMllGQlVtSWdSRVlqS2o2MzBhRGNRV3R3UUMwbFZlN2FBWVdCMUcySnBmRmh6cnNK" ascii /* base64 encoded string 'PKXVGKjYan3Lv0s3oYMA5yGDxayXu67pAZEnsPo2cO6z/p+/2YFBUmIgREYjKj630aDcQWtwQC0lVe7aAYWB1G2JpfFhzrsJ' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule analytics {
   meta:
      description = "phish__spotify - file analytics.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3fab1c883847e4b5a02f3749a9f4d9eab15cd4765873d3b2904a1a4c8755fba3"
   strings:
      $x1 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '34.00'*/
      $x2 = "3E4),c=\"\");return Pc(c,b)?(Ub.push(a),!0):!1},Pc=function(a,b,c){if(!window.JSON)return J(58),!1;var d=O.XMLHttpRequest;if(!d)" ascii /* score: '33.00'*/
      $x3 = "(\"https:\"==a||a==c||(\"http:\"!=a?0:\"http:\"==c))&&B(d)&&(wa(d.url,void 0,e),$d.set(b,!0)))}},v=function(a,b){var c=A.get(a)|" ascii /* score: '32.00'*/
      $x4 = "for(d=0;d<a.length;d++)if(b==a[d]){d=!0;break a}d=!1}return d},Cc=function(a){return encodeURIComponent?encodeURIComponent(a).re" ascii /* score: '31.00'*/
      $s5 = "N.N=function(){\"ga\"!=gb&&J(49);var a=O[gb];if(!a||42!=a.answer){N.L=a&&a.l;N.loaded=!0;var b=O[gb]=N;X(\"create\",b,b.create);" ascii /* score: '30.00'*/
      $s6 = "rd(e,b)}})};function sd(a,b){if(b==M.location.hostname)return!1;for(var c=0;c<a.length;c++)if(a[c]instanceof RegExp){if(a[c].tes" ascii /* score: '28.00'*/
      $s7 = "Dc.prototype.S=function(a,b,c){function d(c){try{c=c||O.event;a:{var d=c.target||c.srcElement;for(c=100;d&&0<c;){if(d.href&&d.no" ascii /* score: '27.00'*/
      $s8 = "\"\"==a||\":\"==a)return!0;return!1},ya=function(a,b){var c=M.referrer;if(/^(https?|android-app):\\/\\//i.test(c)){if(a)return c" ascii /* score: '27.00'*/
      $s9 = "String(a.get(Q)),d.ka=Number(a.get(n)),c=c.palindrome?r:q,c=(c=M.cookie.replace(/^|(; +)/g,\";\").match(c))?c.sort().join(\"\")." ascii /* score: '27.00'*/
      $s10 = "turn J(59),!1;var e=new d;if(!(\"withCredentials\"in e))return J(60),!1;e.open(\"POST\",(c||\"https://ampcid.google.com/v1/publi" ascii /* score: '27.00'*/
      $s11 = " c=\"https://www.google-analytics.com/gtm/js?id=\"+K(a.id);\"dataLayer\"!=a.B&&b(\"l\",a.B);b(\"t\",a.target);b(\"cid\",a.client" ascii /* score: '27.00'*/
      $s12 = "(a=[\"t=error\",\"_e=\"+a,\"_v=j68\",\"sr=1\"],b&&a.push(\"_f=\"+b),c&&a.push(\"_m=\"+K(c.substring(0,100))),a.push(\"aip=1\"),a" ascii /* score: '24.00'*/
      $s13 = "c.type=\"text/javascript\",c.async=!0,c.src=a,b&&(c.id=b),a=M.getElementsByTagName(\"script\")[0],a.parentNode.insertBefore(c,a)" ascii /* score: '24.00'*/
      $s14 = "pc.prototype.ma=function(a,b){var c=this;u(a,c,b)||(v(a,function(){u(a,c,b)}),y(String(c.get(V)),a,void 0,b,!0))};var rc=functio" ascii /* score: '23.00'*/
      $s15 = "b){Za.push([new RegExp(\"^\"+a+\"$\"),b])},T=function(a,b,c){return S(a,b,c,void 0,db)},db=function(){};var gb=qa(window.GoogleA" ascii /* score: '23.00'*/
      $s16 = "l?\"https:\":\"http:\")+\"//www.google-analytics.com\"},Da=function(a){this.name=\"len\";this.message=a+\"-8192\"},ba=function(a" ascii /* score: '23.00'*/
      $s17 = "if(!e)return!1;var g=new e;if(!(\"withCredentials\"in g))return!1;a=a.replace(/^http:/,\"https:\");g.open(\"POST\",a,!0);g.withC" ascii /* score: '23.00'*/
      $s18 = "cation.protocol?\"https:\":\"http:\")+\"//www.google-analytics.com/plugins/ua/\"+c),d=ae(c),a=d.protocol,c=M.location.protocol," fullword ascii /* score: '22.00'*/
      $s19 = "encodeURIComponent(a),\"/\",e,\"\",b)){fb=e;return}}}zc(\"AMP_TOKEN\",encodeURIComponent(a),\"/\",fb,\"\",b)},Qc=function(a,b,c)" ascii /* score: '22.00'*/
      $s20 = "(\"https:\"==a||a==c||(\"http:\"!=a?0:\"http:\"==c))&&B(d)&&(wa(d.url,void 0,e),$d.set(b,!0)))}},v=function(a,b){var c=A.get(a)|" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index_files_index_2 {
   meta:
      description = "phish__spotify - file index.js"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d86af73b2f46ac79673ad6e42baf6c3c90445353d3022b4088592102c392ff10"
   strings:
      $x1 = "&quot;\" sp-disallow-chars-model=usernameDisallowedChars autocapitalize=off autocomplete=off autocorrect=off autofocus=autofocus" ascii /* score: '81.00'*/
      $x2 = "\";else{(function(e,t,n,r){var a=e.d,i=a.length-e.i,o=(t=_(t)?Math.min(Math.max(n,i),r):+t)+e.i,s=a[o];if(o>0)a.splice(o);else{e" ascii /* score: '80.00'*/
      $x3 = "\"===e},isIdent:function(e){return\"a\"<=e&&e<=\"z\"||\"A\"<=e&&e<=\"Z\"||\"_\"===e||\"$\"===e},isExpOperator:function(e){return" ascii /* score: '73.00'*/
      $x4 = "profile!\",alreadyOnSpotify:\"Already on Spotify?\",signUpForFree:\"Sign up for free\",goToAppStore:\"Go to App Store\",\"scope-" ascii /* score: '72.00'*/
      $x5 = "</span><span class=sr-only>Close</span></button> <span ng-bind-html=\"\\'notificationCookiePolicy\\' | localize:cookiePolicyURL" ascii /* score: '72.00'*/
      $x6 = "profile!\",alreadyOnSpotify:\"Already on Spotify?\",signUpForFree:\"Sign up for free\",goToAppStore:\"Go to App Store\",\"scope-" ascii /* score: '67.00'*/
      $x7 = "n de tu cuenta de Spotify\"}},function(e){e.exports={smartling:{translate_paths:{path:\"/*\",key:\"/{*}\"},variants_enabled:\"tr" ascii /* score: '64.00'*/
      $x8 = ".',youAreLoggedInAsUsername:\"Je bent ingelogd als {0}.\",errorTitle:\"Fout\",error404Title:\"Fout 404 - Niet gevonden\",error40" ascii /* score: '56.00'*/
      $x9 = "!function(e){var t={};function n(r){if(t[r])return t[r].exports;var a=t[r]={i:r,l:!1,exports:{}};return e[r].call(a.exports,a,a." ascii /* score: '55.00'*/
      $x10 = "t ein, um es mit deinem Spotify Konto zu verbinden.\",helpMessageGeneral:'Wenn Du noch immer Hilfe brauchst, wende Dich an den <" ascii /* score: '52.00'*/
      $x11 = " responsabile dell\\'uso delle tue informazioni secondo quanto riportato nella propria informativa sulla privacy e che queste po" ascii /* score: '51.00'*/
      $x12 = " tardi o consulta <a href=\"https://www.spotify.com/help\" target=\"_blank\">l\\'area di assistenza</a>',errorInvalidCredentials" ascii /* score: '49.00'*/
      $x13 = "essayez ou consultez notre <a href=\"https://www.spotify.com/help\" target=\"_blank\">rubrique d\\'aide</a>.',errorInvalidCreden" ascii /* score: '44.00'*/
      $x14 = " votre compte Spotify.\",helpMessageGeneral:'Si vous avez toujours besoin d\\'aide, contactez <a href=\"https://support.spotify." ascii /* score: '44.00'*/
      $x15 = ".com/\" target=\"_blank\">Spotify Support.</a>',inputUsername:\"E-mailadres of gebruikersnaam\",inputPassword:\"Wachtwoord\",che" ascii /* score: '41.00'*/
      $x16 = "profile!\",alreadyOnSpotify:\"Already on Spotify?\",signUpForFree:\"Sign up for free\",goToAppStore:\"Go to App Store\",\"scope-" ascii /* score: '40.00'*/
      $x17 = " gebruiken cookies om je onze diensten te leveren en je advertenties te tonen die zijn gebaseerd op je interesses. Door onze web" ascii /* score: '40.00'*/
      $x18 = "ih memerlukan bantuan, hubungi <a href=\"https://support.spotify.com/\" target=\"_blank\">Dukungan Spotify</a>',inputUsername:\"" ascii /* score: '39.00'*/
      $x19 = "lp kontaktar du <a href=\"https://support.spotify.com/\" target=\"_blank\">Spotifys support</a>',inputUsername:\"E-postadress el" ascii /* score: '39.00'*/
      $x20 = "n necesitas ayuda, ponte en contacto con el <a href=\"https://support.spotify.com/\" target=\"_blank\">Soporte de Spotify</a>',i" ascii /* score: '39.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 1000KB and
      1 of ($x*)
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_index {
   meta:
      description = "phish__spotify - file index.php"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5d075785e9770ec2637793b66977cc5c4fd0b7545711033e6dde3c484eff15c4"
   strings:
      $s1 = "header('Location: login.html');" fullword ascii /* score: '16.00'*/
      $s2 = "include 'ip.php';" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_login_2 {
   meta:
      description = "phish__spotify - file login.php"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "5a6f20e962d31fadabcc7fb3f35733703fb28951a5acbe9957d99d38716a5801"
   strings:
      $s1 = "file_put_contents(\"usernames.txt\", \"Account: \" . $_POST['username'] . \" Pass: \" . $_POST['password'] . \"\\n\", FILE_APPEN" ascii /* score: '29.00'*/
      $s2 = "header('Location: https://accounts.spotify.com/');" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__spotify_home_ubuntu_malware_lab_samples_extracted_phishing_Spotify_ip {
   meta:
      description = "phish__spotify - file ip.php"
      author = "Comps Team Malware Lab"
      reference = "phish__spotify phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b4cca83eb16c721d752117de2d7c60d83f2c643299e4c3c4f9bad3fdfac3affb"
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
