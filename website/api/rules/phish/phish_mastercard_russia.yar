/* ===================== */
/* Source: /home/ubuntu/yara-lab/rule_library/generated/phish__mastercard_russia/phish__mastercard_russia_auto.yar */
/* ===================== */

/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-02-27
   Identifier: phish__mastercard_russia
   Reference: phish__mastercard_russia phishing_kit auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__css_custom {
   meta:
      description = "phish__mastercard_russia - file custom.css"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "d10f52ecf026e639d446691c1f2ccc32f637c1077a17e8f1ce5131dc4fc8cb3a"
   strings:
      $s1 = ".head_cvv img {" fullword ascii /* score: '9.00'*/
      $s2 = ".modal-header {" fullword ascii /* score: '9.00'*/
      $s3 = ".modal-content {" fullword ascii /* score: '9.00'*/
      $s4 = ".head_cvv {" fullword ascii /* score: '9.00'*/
      $s5 = "-webkit-transition: -webkit-transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s6 = "-webkit-transition: -webkit-transform 250ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s7 = "display: -ms-flexbox;" fullword ascii /* score: '8.00'*/
      $s8 = "transition: -webkit-transform 250ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s9 = "transition: -webkit-transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36);" fullword ascii /* score: '8.00'*/
      $s10 = "src: url('FuturaPT-Medium.eot?#iefix') format('embedded-opentype')," fullword ascii /* score: '7.00'*/
      $s11 = "background: url(/img/link_right_black.png) no-repeat;" fullword ascii /* score: '7.00'*/
      $s12 = "outline: none !important;" fullword ascii /* score: '7.00'*/
      $s13 = "src: url('FuturaPT-Medium.eot');" fullword ascii /* score: '7.00'*/
      $s14 = "url('FuturaPT-Medium.ttf') format('truetype');" fullword ascii /* score: '7.00'*/
      $s15 = ".arrow {" fullword ascii /* score: '4.00'*/
      $s16 = "transition: transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36),-webkit-transform 300ms cubic-bezier(0.195, 1.29, 0.795, 1.36" ascii /* score: '4.00'*/
      $s17 = "border-top: #dbdcde 1px solid;" fullword ascii /* score: '4.00'*/
      $s18 = "border-top: #33c3c5 3px solid;" fullword ascii /* score: '4.00'*/
      $s19 = " Chezz, " fullword ascii /* score: '4.00'*/
      $s20 = "margin: 0 0 0 14px;" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 20KB and
      8 of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__token {
   meta:
      description = "phish__mastercard_russia - file token.php"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "b2d278ed1e7ea79366109ba7001b927fdedca1cb12c91542787dc104a2a2b329"
   strings:
      $s1 = "7658222021502155" ascii /* score: '17.00'*/ /* hex encoded string 'vX" !P!U' */
      $s2 = ": 7658222021502155, " fullword ascii /* score: '9.00'*/ /* hex encoded string 'vX" !P!U' */
      $s3 = ":1111, CVV:111 " fullword ascii /* score: '1.00'*/
      $s4 = "<br> 1213456795452121:2121:323 " fullword ascii /* score: '1.00'*/
      $s5 = "123131231231231" ascii /* score: '1.00'*/
      $s6 = "<br> 323213123131:3123: " fullword ascii /* score: '1.00'*/
      $s7 = ": 1111111111111111, " fullword ascii /* score: '1.00'*/
      $s8 = ":1220, CVV:869 " fullword ascii /* score: '1.00'*/
      $s9 = "<br> 123131231231231:1313 " fullword ascii /* score: '1.00'*/
      $s10 = "323213123131" ascii /* score: '1.00'*/
      $s11 = "1213456795452121" ascii /* score: '1.00'*/
      $s12 = ": 111111111111111, " fullword ascii /* score: '1.00'*/
      $s13 = ": 111111, " fullword ascii /* score: '1.00'*/
      $s14 = ":, CVV: " fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 1KB and
      8 of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__index {
   meta:
      description = "phish__mastercard_russia - file index.html"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "781dcfd1fb7086cb44e0a3872ff4b086472fc16b01796e5c03e1eda4b1734ef1"
   strings:
      $s1 = "<form method=\"post\" name=\"log\" id=\"login\" action=\"entercard.php\">" fullword ascii /* score: '19.00'*/
      $s2 = "<a href=\"#\" class=\"link_arrow\" data-toggle=\"modal\" data-target=\"#operations\">" fullword ascii /* score: '15.00'*/
      $s3 = "<script src=\"js/jquery-3.3.1.slim.min.js\" integrity=\"sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" ascii /* score: '13.00'*/
      $s4 = "<div class=\"modal fade\" id=\"operations\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"exampleModalCenterTitle\" aria-hid" ascii /* score: '13.00'*/
      $s5 = "<script src=\"js/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorig" ascii /* score: '13.00'*/
      $s6 = "<script src=\"js/jquery-3.3.1.slim.min.js\" integrity=\"sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" ascii /* score: '13.00'*/
      $s7 = "<script src=\"js/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorig" ascii /* score: '13.00'*/
      $s8 = "<script src=\"js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crosso" ascii /* score: '13.00'*/
      $s9 = "<script src=\"js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crosso" ascii /* score: '13.00'*/
      $s10 = "<div class=\"modal fade\" id=\"operations\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"exampleModalCenterTitle\" aria-hid" ascii /* score: '13.00'*/
      $s11 = "<a href=\"#\" class=\"button_cvv\" data-toggle=\"modal\" data-target=\"#entercard\">" fullword ascii /* score: '10.00'*/
      $s12 = "n=\"anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s13 = "ossorigin=\"anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s14 = "anonymous\"></script>" fullword ascii /* score: '10.00'*/
      $s15 = "<div class=\"modal fade\" id=\"entercard\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"exampleModalCenterTitle\" aria-hidd" ascii /* score: '8.00'*/
      $s16 = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">" fullword ascii /* score: '8.00'*/
      $s17 = "<img src=\"img/logo.png\" alt=\"mastercard\">" fullword ascii /* score: '8.00'*/
      $s18 = "<link rel=\"stylesheet\" href=\"css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9J" ascii /* score: '7.00'*/
      $s19 = "<link href=\"css/custom.css\" rel=\"stylesheet\">" fullword ascii /* score: '7.00'*/
      $s20 = "<link rel=\"stylesheet\" href=\"css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9J" ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__autor {
   meta:
      description = "phish__mastercard_russia - file autor.txt"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "3e47f4fdadca978cf9f41232cfd56708883d2a61cdcb9f38ec83d929a9d689ac"
   strings:
      $s1 = ": @bsixdfour;" fullword ascii /* score: '4.00'*/
      $s2 = " B6D4, " fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 1KB and
      all of them
}

rule _opt_mal_phish__mastercard_russia_home_ubuntu_malware_lab_samples_extracted_phishing_Mastercard__Russia__ыфыа {
   meta:
      description = "phish__mastercard_russia - file ыфыа.txt"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "97e6a34d7bd2ffe869b443307198681ba5f07b931485028dc4e5ababfe72f351"
   strings:
      $s1 = " token.php;" fullword ascii /* score: '10.00'*/
      $s2 = " index.html (" fullword ascii /* score: '4.00'*/
      $s3 = " input);" fullword ascii /* score: '4.00'*/
      $s4 = " entercard.php " fullword ascii /* score: '3.00'*/
   condition:
      uint16(0) == 0xe0c4 and filesize < 1KB and
      all of them
}

rule entercard {
   meta:
      description = "phish__mastercard_russia - file entercard.php"
      author = "Comps Team Malware Lab"
      reference = "phish__mastercard_russia phishing_kit auto gen"
      date = "2026-02-27"
      hash1 = "e1384a28222ac0a23f528bdd2c16343bf62584c606b0cc83bb8ef5ec7bb811a5"
   strings:
      $s1 = "$log = fopen(\"token.php\",\"a+\");" fullword ascii /* score: '15.00'*/
      $s2 = "echo \"<html><head><META HTTP-EQUIV='Refresh' content ='0; URL=https://www.mastercard.ru'></head></html>\";" fullword ascii /* score: '13.00'*/
      $s3 = "$Year = $_POST['year'];" fullword ascii /* score: '9.00'*/
      $s4 = "$Cvv = $_POST['cvv'];" fullword ascii /* score: '9.00'*/
      $s5 = "fwrite($log,\"<br> " fullword ascii /* score: '9.00'*/
      $s6 = "$Number = $_POST['number'];" fullword ascii /* score: '9.00'*/
      $s7 = ": $Number, " fullword ascii /* score: '4.00'*/
      $s8 = ":$Year, CVV:$Cvv \\n\"); " fullword ascii /* score: '4.00'*/
      $s9 = "fclose($log);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}
