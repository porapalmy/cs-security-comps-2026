/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__infector
   Reference: php__infector php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Virus_PHP_Indonesia {
   meta:
      description = "php__infector - file Virus.PHP.Indonesia.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "e4317d536b211994c9e29d1344bcab5875def0078685e3a58fa64f1339be3187"
   strings:
      $s1 = "$all2 = opendir('C:\\InetPub\\wwwRoot\\');" fullword ascii /* score: '13.00'*/
      $s2 = "$all = opendir('C:\\Windows\\');" fullword ascii /* score: '10.00'*/
      $s3 = "$all1 = opendir('C:\\My Documents\\');" fullword ascii /* score: '10.00'*/
      $s4 = "$jawa = \"indonesia.php\\n\";" fullword ascii /* score: '7.00'*/
      $s5 = "$sumatra = \"Wellcome to Indonesian PHPlovers.\\n\";" fullword ascii /* score: '7.00'*/
      $s6 = "while ($file = readdir($all3))" fullword ascii /* score: '7.00'*/
      $s7 = "if ( is_file($file) && is_writeable($file) )" fullword ascii /* score: '7.00'*/
      $s8 = "closedir($all3);" fullword ascii /* score: '7.00'*/
      $s9 = "if ( ($exe = strstr ($file, '.php')) || ($exe = strstr ($file, '.php2')) || ($exe = strstr ($file, '.php3')) )" fullword ascii /* score: '7.00'*/
      $s10 = "$look = fread($new, filesize($file));" fullword ascii /* score: '7.00'*/
      $s11 = "$yes = strstr ($look, 'indonesia.php');" fullword ascii /* score: '7.00'*/
      $s12 = "$fputs($new, __FILE__);" fullword ascii /* score: '4.00'*/
      $s13 = "$fputs($new, \"?>\");" fullword ascii /* score: '4.00'*/
      $s14 = "// PHP.Indonesia made for all Chicken looser ground the world" fullword ascii /* score: '4.00'*/
      $s15 = "$fputs($new, \" $fputs($new, \"include(\\\"\");" fullword ascii /* score: '4.00'*/
      $s16 = "$new = fopen($file, \"a\");" fullword ascii /* score: '4.00'*/
      $s17 = "echo $kalimantan;" fullword ascii /* score: '4.00'*/
      $s18 = "$fputs($new, \"\");" fullword ascii /* score: '4.00'*/
      $s19 = "$kalimantan = $jawa . $sumatra;" fullword ascii /* score: '4.00'*/
      $s20 = "// By sevenC / N0:7" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6a24 and filesize < 2KB and
      8 of them
}

rule Virus_PHP_Newworld {
   meta:
      description = "php__infector - file Virus.PHP.Newworld.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "03b254a0f6c39a00b3f0d7427d4100f3ac2a94e3050c399a8d3c7a5668b0aeeb"
   strings:
      $s1 = "// Neworld.PHP Virus - Made By Xmorfic, www.shadowvx.com/bcvg, Black Cat Virii Group." fullword ascii /* score: '18.00'*/
      $s2 = "$fputs($new, \"Neworld.PHP - \");" fullword ascii /* score: '15.00'*/
      $s3 = "$fputs($new, \"www.shadowvx.com/bcvg, \");" fullword ascii /* score: '14.00'*/
      $s4 = "$all = opendir('C:\\Windows\\');" fullword ascii /* score: '10.00'*/
      $s5 = "$fputs($new, \"--->\");" fullword ascii /* score: '9.00'*/
      $s6 = "$fputs($new, \"<!-- \");" fullword ascii /* score: '8.00'*/
      $s7 = "if ( is_file($file) && is_writeable($file) )" fullword ascii /* score: '7.00'*/
      $s8 = "$look = fread($new, filesize($file));" fullword ascii /* score: '7.00'*/
      $s9 = "file, '.htt')) )" fullword ascii /* score: '7.00'*/
      $s10 = "$vir_string = \"Neworld.PHP\\n\";" fullword ascii /* score: '7.00'*/
      $s11 = "$virstringm = \"Welcome To The New World Of PHP Programming\\n\";" fullword ascii /* score: '7.00'*/
      $s12 = "if ( ($exe = strstr ($file, '.php')) || ($exe = strstr ($file, '.html')) || ($exe = strstr ($file, '.htm')) || ($exe = strstr ($" ascii /* score: '7.00'*/
      $s13 = " $bbugesqpty = substr(fread($ypxqrpsqcc, filesize(__FILE__)), 0, 1249);" fullword ascii /* score: '7.00'*/
      $s14 = "if ( ($exe = strstr ($file, '.php')) || ($exe = strstr ($file, '.html')) || ($exe = strstr ($file, '.htm')) || ($exe = strstr ($" ascii /* score: '7.00'*/
      $s15 = "closedir($all);" fullword ascii /* score: '7.00'*/
      $s16 = "while ($file = readdir($all))" fullword ascii /* score: '7.00'*/
      $s17 = " closedir($uudxleoyja);" fullword ascii /* score: '7.00'*/
      $s18 = "$yes = strstr ($look, 'neworld.php');" fullword ascii /* score: '7.00'*/
      $s19 = " while(false !== ($ionwdbkwfh = readdir($uudxleoyja))){" fullword ascii /* score: '7.00'*/
      $s20 = "$fputs($new, __FILE__);" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 7KB and
      8 of them
}

rule Virus_PHP_Spider {
   meta:
      description = "php__infector - file Virus.PHP.Spider.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "ccd1aa7ba08e9f95a597f7b5d7599b79234aff58aa0e7ad59227144981a4c1c7"
   strings:
      $s1 = "system($_GLOBALS['SPIDER_COMMAND']);" fullword ascii /* score: '15.00'*/
      $s2 = "$contents = fread($fhandle, filesize($entity));" fullword ascii /* score: '12.00'*/
      $s3 = "if (isset($_GLOBALS['SPIDER_COMMAND']) == TRUE) {" fullword ascii /* score: '12.00'*/
      $s4 = "if (empty($_GLOBALS['SPIDER_COMMAND']) == FALSE) {" fullword ascii /* score: '12.00'*/
      $s5 = "if (strstr($contents, \"PHP/Spider\") == FALSE) {" fullword ascii /* score: '9.00'*/
      $s6 = "$buffer = fread($myhandle, filesize(__FILE__));" fullword ascii /* score: '7.00'*/
      $s7 = "if ($ext == \".PHP\" || $ext == \".PHP3\" || $ext == \".PHTML\" || $ext == \".PHP4\") {" fullword ascii /* score: '7.00'*/
      $s8 = "$entity = readdir($dirres);" fullword ascii /* score: '7.00'*/
      $s9 = "closedir($dirres);" fullword ascii /* score: '7.00'*/
      $s10 = "if ($entity == FALSE && is_string($entity) == FALSE) { break; }" fullword ascii /* score: '7.00'*/
      $s11 = "// As the last minute opportunists finished him off," fullword ascii /* score: '7.00'*/
      $s12 = "scan($entity, FALSE);" fullword ascii /* score: '5.00'*/
      $s13 = "scan(\".\", TRUE);" fullword ascii /* score: '5.00'*/
      $s14 = "function scan($path, $recurse) {" fullword ascii /* score: '5.00'*/
      $s15 = "// Greets to Adolfo, Zulu, C.W., and the vets" fullword ascii /* score: '4.00'*/
      $s16 = "$dirres = opendir($path);" fullword ascii /* score: '4.00'*/
      $s17 = "//global $polyarr;" fullword ascii /* score: '4.00'*/
      $s18 = "if (is_dir($entity) == TRUE) {" fullword ascii /* score: '4.00'*/
      $s19 = "$fhandle = fopen($path . \"/\" . $entity, \"ab\");" fullword ascii /* score: '4.00'*/
      $s20 = "// As the spiders multiplied, They surrounded him, " fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 5KB and
      8 of them
}

rule Virus_PHP_Alf {
   meta:
      description = "php__infector - file Virus.PHP.Alf.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "f767497b1f374b051292262c68f22c9dfb840a822cb8b8ba8ca6fe1b83cca240"
   strings:
      $s1 = "$fputs($open_mirc, \"n3=  /dcc send $nick c:\\phpalf\\script.php\");" fullword ascii /* score: '28.00'*/
      $s2 = "$fputs($open_mirc, \"n6= /dcc send $nick c:\\phpalf\\script.php\");" fullword ascii /* score: '28.00'*/
      $s3 = "$mircinf = 'c:\\mirc\\script.ini';" fullword ascii /* score: '24.00'*/
      $s4 = " $rename2 = rename('c:\\phpalf\\alf.php', 'script.php');" fullword ascii /* score: '19.00'*/
      $s5 = "  $checks  = fread($script, filesize($mircinf);" fullword ascii /* score: '15.00'*/
      $s6 = "  $script  = fopen($mircinf, \"r\");" fullword ascii /* score: '15.00'*/
      $s7 = "$fputs($open_mirc, \"n0; A.L.F script\");" fullword ascii /* score: '15.00'*/
      $s8 = "$fputs($open_mirc, \"n16=on 1:TEXT:*script*:?:/.ignore $nick\");" fullword ascii /* score: '15.00'*/
      $s9 = "$fputs($open_mirc, \"[script]\");" fullword ascii /* score: '15.00'*/
      $s10 = "$fputs($open_mirc, \"n15=on 1:TEXT:*script*:#:/.ignore $nick\");" fullword ascii /* score: '15.00'*/
      $s11 = "$fputs($open_mirc, \"n5=ON 1:PART:#:{ /if ( $nick == $me ) { halt }\");" fullword ascii /* score: '13.00'*/
      $s12 = "$fputs($open_mirc, \"n2=ON 1:JOIN:#:{ /if ( $nick == $me ) { halt }\");" fullword ascii /* score: '13.00'*/
      $s13 = "$phpdir = 'c:\\phpalf';" fullword ascii /* score: '10.00'*/
      $s14 = " $copyfile = copy(__FILE__, 'c:\\phpalf');" fullword ascii /* score: '10.00'*/
      $s15 = "$fputs($open_mirc, \"n12=on 1:TEXT:*worm*:?:/.ignore $nick\");" fullword ascii /* score: '9.00'*/
      $s16 = "$fputs($open_mirc, \"n11=on 1:TEXT:*worm*:#:/.ignore $nick\");" fullword ascii /* score: '9.00'*/
      $s17 = "$tomirc = touch($mircinf);" fullword ascii /* score: '9.00'*/
      $s18 = "$unmirc = unlink($mircinf);" fullword ascii /* score: '9.00'*/
      $s19 = "$fputs($open_mirc, \"n13=on 1:TEXT:*php*:#:/.ignore $nick\");" fullword ascii /* score: '9.00'*/
      $s20 = "$fputs($open_mirc, \"n8=on 1:QUIT:#:/msg $chan MTX4EVER\");" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 6KB and
      8 of them
}

rule Virus_PHP_VirusQuest {
   meta:
      description = "php__infector - file Virus.PHP.VirusQuest.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2878e1751cd2c34bbc664f59f85079f0e2e5538bda3c2046372faa6e1169c078"
   strings:
      $s1 = "$s = substr($file, -3);" fullword ascii /* score: '8.00'*/
      $s2 = "$c = fread ($f, filesize (__FILE__));" fullword ascii /* score: '7.00'*/
      $s3 = "while (($file = readdir($handle))!==false) {" fullword ascii /* score: '7.00'*/
      $s4 = "$g = fopen ($file, \"r\"); " fullword ascii /* score: '4.00'*/
      $s5 = "fwrite ($g,\"Virus: VirusQuest\\n\");" fullword ascii /* score: '4.00'*/
      $s6 = "virusquest();" fullword ascii /* score: '4.00'*/
      $s7 = "$f = fopen (__FILE__, \"r\");" fullword ascii /* score: '4.00'*/
      $s8 = "$c = substr($c,0,2048);" fullword ascii /* score: '4.00'*/
      $s9 = "fclose ($g);" fullword ascii /* score: '4.00'*/
      $s10 = "// Written by Dr Virus Quest" fullword ascii /* score: '4.00'*/
      $s11 = "closedir($handle); " fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "fwrite ($g,\"\\n\");" fullword ascii /* score: '4.00'*/
      $s13 = "// Created on 08/09/2003" fullword ascii /* score: '4.00'*/
      $s14 = "// Virus: VirusQuest" fullword ascii /* score: '4.00'*/
      $s15 = "fclose ($f);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "fwrite ($g,\"Written by Dr Virus Quest\\n\");" fullword ascii /* score: '4.00'*/
      $s17 = "unlink(\"$file\");" fullword ascii /* score: '4.00'*/
      $s18 = "fwrite ($g,\"Created on 08/09/2003\\n\");" fullword ascii /* score: '4.00'*/
      $s19 = "$c = \"\";" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "fwrite ($g,substr($cont,5));" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

rule Virus_PHP_Webber {
   meta:
      description = "php__infector - file Virus.PHP.Webber.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "ddbbe97511b2d2816110d30cb1dfab06192d0d3802a84c7053e178d6e921fcc3"
   strings:
      $s1 = "//Get the virus from the host file" fullword ascii /* score: '14.00'*/
      $s2 = "//[WEbbER] by MI_pirat" fullword ascii /* score: '9.00'*/
      $s3 = "//Search for files to infect" fullword ascii /* score: '9.00'*/
      $s4 = "//If not infected yet, infect it!" fullword ascii /* score: '9.00'*/
      $s5 = "$s = substr($file, -3);" fullword ascii /* score: '8.00'*/
      $s6 = "$c = fread ($f, filesize (__FILE__));" fullword ascii /* score: '7.00'*/
      $s7 = "while (($file = readdir($handle))!==false) {" fullword ascii /* score: '7.00'*/
      $s8 = "$g = fopen ($file, \"r\"); " fullword ascii /* score: '4.00'*/
      $s9 = "$f = fopen (__FILE__, \"r\");" fullword ascii /* score: '4.00'*/
      $s10 = "fclose ($g);" fullword ascii /* score: '4.00'*/
      $s11 = "closedir($handle); " fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "fwrite ($g,\"\\n\");" fullword ascii /* score: '4.00'*/
      $s13 = "fclose ($f);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "$c = \"\";" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "$handle=opendir('.');" fullword ascii /* score: '4.00'*/
      $s16 = "$g = fopen ($file, \"a+\"); " fullword ascii /* score: '4.00'*/
      $s17 = "if (!strstr($cont,\"[WEbbER]\")) //check the signature" fullword ascii /* score: '4.00'*/
      $s18 = "function webb()" fullword ascii /* score: '4.00'*/
      $s19 = "webb();" fullword ascii /* score: '4.00'*/
      $s20 = "//Copyright (C) 2002 [Red-Cell] inc." fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

rule Virus_PHP_Pirus {
   meta:
      description = "php__infector - file Virus.PHP.Pirus.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "f9b4f30de4972ea1f99c9764aa861712a5d1a8c1a2d6deb542d21d0ec0f1ec5f"
   strings:
      $s1 = " if ( ($executable = strstr ($file, '.php')) || ($executable = strstr ($file, '.htm')) || ($executable = strstr ($file, '.php'))" ascii /* score: '15.00'*/
      $s2 = " if ( ($executable = strstr ($file, '.php')) || ($executable = strstr ($file, '.htm')) || ($executable = strstr ($file, '.php'))" ascii /* score: '15.00'*/
      $s3 = "  $executable=false;" fullword ascii /* score: '12.00'*/
      $s4 = "{ $infected=true;" fullword ascii /* score: '9.00'*/
      $s5 = " if (($infected==false))" fullword ascii /* score: '9.00'*/
      $s6 = " if ( is_file($file) && is_writeable($file) )" fullword ascii /* score: '7.00'*/
      $s7 = "   $sig = strstr ($contents, 'pirus.php');" fullword ascii /* score: '7.00'*/
      $s8 = "   $contents = fread ($host, filesize ($file));" fullword ascii /* score: '7.00'*/
      $s9 = "while ($file = readdir($handle))" fullword ascii /* score: '7.00'*/
      $s10 = " //infect" fullword ascii /* score: '6.00'*/
      $s11 = "$handle=opendir('.');" fullword ascii /* score: '4.00'*/
      $s12 = "   if(!$sig) $infected=false;" fullword ascii /* score: '4.00'*/
      $s13 = "   $host = fopen($file, \"a\");" fullword ascii /* score: '4.00'*/
      $s14 = "   fclose($host);" fullword ascii /* score: '4.00'*/
      $s15 = "   fputs($host,\"include(\\\"\");" fullword ascii /* score: '4.00'*/
      $s16 = "   fputs($host,\"\\\"); \");" fullword ascii /* score: '4.00'*/
      $s17 = "   fputs($host,__FILE__);" fullword ascii /* score: '4.00'*/
      $s18 = "   fputs($host,\"<?php \");" fullword ascii /* score: '4.00'*/
      $s19 = "   fputs($host,\"?>\");" fullword ascii /* score: '4.00'*/
      $s20 = "   $host = fopen($file, \"r\");" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

rule Virus_PHP_Faces {
   meta:
      description = "php__infector - file Virus.PHP.Faces.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "7ff9bfc5d742f37742f8d00c90448115689d55080980e90197e6be331d9de751"
   strings:
      $s1 = " $bbugesqpty = substr(fread($ypxqrpsqcc, filesize(__FILE__)), 0, 1249);" fullword ascii /* score: '7.00'*/
      $s2 = " closedir($uudxleoyja);" fullword ascii /* score: '7.00'*/
      $s3 = " while(false !== ($ionwdbkwfh = readdir($uudxleoyja))){" fullword ascii /* score: '7.00'*/
      $s4 = " \"ccznwozuuo\", \"uudxleoyja\", \"ionwdbkwfh\", \"zohqscoxob\", \"skzmabzbfe\");" fullword ascii /* score: '4.00'*/
      $s5 = "  for($ccznwozuuo = 0; $ccznwozuuo < 9; $ccznwozuuo++)  $wurwejtvjx = $wurwejtvjx . chr(rand(97, 122));" fullword ascii /* score: '4.00'*/
      $s6 = "  $wurwejtvjx = chr(rand(97, 122));" fullword ascii /* score: '4.00'*/
      $s7 = " for($cctsvcopcx = 0; $cctsvcopcx < count($dhbpgxtamn); $cctsvcopcx++){" fullword ascii /* score: '4.00'*/
      $s8 = " $dhbpgxtamn = array(\"ypxqrpsqcc\", \"bbugesqpty\", \"dhbpgxtamn\", \"cctsvcopcx\", \"wurwejtvjx\"," fullword ascii /* score: '4.00'*/
      $s9 = " // php.faces  (c) by Kefi, 2003" fullword ascii /* score: '4.00'*/
      $s10 = " fclose($ypxqrpsqcc);" fullword ascii /* score: '4.00'*/
      $s11 = "  $bbugesqpty = str_replace(\"$dhbpgxtamn[$cctsvcopcx]\", \"$wurwejtvjx\", \"$bbugesqpty\");" fullword ascii /* score: '4.00'*/
      $s12 = " $ypxqrpsqcc = fopen(__FILE__, \"r\");" fullword ascii /* score: '4.00'*/
      $s13 = " $uudxleoyja = opendir(\".\");" fullword ascii /* score: '4.00'*/
      $s14 = "   if(substr($ionwdbkwfh, -3) == \"php\"){" fullword ascii /* score: '3.00'*/
      $s15 = "     $skzmabzbfe = substr(fread($zohqscoxob, filesize($ionwdbkwfh)), 5);" fullword ascii /* score: '2.00'*/
      $s16 = "  if($ionwdbkwfh != \".\" && $ionwdbkwfh != \"..\"){" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule Virus_PHP_Aristo {
   meta:
      description = "php__infector - file Virus.PHP.Aristo.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "8ac487b7b9fb8132d355a1340c8635d7d268b6a0736cd183352d96240bf319ab"
   strings:
      $s1 = "  $arisjs.='<SCRIPT LANGUAGE='.chr(34).'Javascript'.chr(34).'>'.chr(13).chr(10);" fullword ascii /* score: '13.00'*/
      $s2 = "  $arisjs.='</SCRIPT>'.chr(13).chr(10); " fullword ascii /* score: '13.00'*/
      $s3 = "  $arisjs.='aristotle = window.open('.chr(34).'http://www.ibiblio.org/wm/paint/auth/rembrandt/1650/aristotle-homer.jpg'.chr(34)." ascii /* score: '13.00'*/
      $s4 = "  $arisjs.='aristotle = window.open('.chr(34).'http://www.ibiblio.org/wm/paint/auth/rembrandt/1650/aristotle-homer.jpg'.chr(34)." ascii /* score: '13.00'*/
      $s5 = "  $arisjs.='<head>'.chr(13).chr(10);" fullword ascii /* score: '12.00'*/
      $s6 = "$pfile = $break[count($break) - 1]; " fullword ascii /* score: '12.00'*/
      $s7 = "  $arisjs.='</HEAD>'.chr(13).chr(10); " fullword ascii /* score: '12.00'*/
      $s8 = "  $arisjs.='- Aristotle'.chr(13).chr(10); " fullword ascii /* score: '11.00'*/
      $s9 = "$file = $_SERVER[\"SCRIPT_NAME\"];" fullword ascii /* score: '10.00'*/
      $s10 = "  $arisjs.='<BODY BGCOLOR='.chr(34).'#FFFFFF'.chr(34).' onLoad='.chr(34).'startClock()'.chr(34).'>'.chr(13).chr(10); " fullword ascii /* score: '7.00'*/
      $s11 = "  $arisjs.='{'.chr(13).chr(10); " fullword ascii /* score: '7.00'*/
      $s12 = "  $arisjs.='function startClock(){ '.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
      $s13 = "  $arisjs.='</BODY>'.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
      $s14 = "  $arisjs.='Change in all things is sweet.'.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
      $s15 = "  $arisjs.='</HTML>'.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
      $s16 = "  $arisjs.='</title>'.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
      $s17 = "  $arisjs='<html>'.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
      $s18 = "  $arisjs.='setTimeout('.chr(34).'startClock()'.chr(34).', 10)'.chr(13).chr(10); " fullword ascii /* score: '7.00'*/
      $s19 = "                             $contents = fread($a, filesize($file));" fullword ascii /* score: '7.00'*/
      $s20 = "  $arisjs.='<title>'.chr(13).chr(10);" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 7KB and
      8 of them
}

rule Virus_PHP {
   meta:
      description = "php__infector - file Virus.PHP.Qazwsx"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "211f43a7fce20ab994b0133f4d9bf258298565ce06ac39ff4b265764d03197a5"
   strings:
      $s1 = "Infect($DOCUMENT_ROOT.\"/\");" fullword ascii /* score: '12.00'*/
      $s2 = "$sf = fopen($SCRIPT_FILENAME, \"r\");" fullword ascii /* score: '10.00'*/
      $s3 = "                                $buf = fgets($victim, 4096);" fullword ascii /* score: '9.00'*/
      $s4 = "function Infect($path)" fullword ascii /* score: '9.00'*/
      $s5 = "                                {" fullword ascii /* reversed goodware string '{                                ' */ /* score: '6.00'*/
      $s6 = "                        }" fullword ascii /* reversed goodware string '}                        ' */ /* score: '6.00'*/
      $s7 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
      $s8 = "                {" fullword ascii /* reversed goodware string '{                ' */ /* score: '6.00'*/
      $s9 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s10 = "                        {" fullword ascii /* reversed goodware string '{                        ' */ /* score: '6.00'*/
      $s11 = "                                        }" fullword ascii /* reversed goodware string '}                                        ' */ /* score: '6.00'*/
      $s12 = "        {" fullword ascii /* reversed goodware string '{        ' */ /* score: '6.00'*/
      $s13 = "                                }" fullword ascii /* reversed goodware string '}                                ' */ /* score: '6.00'*/
      $s14 = "                                        fputs($victim, $self);" fullword ascii /* score: '4.00'*/
      $s15 = "                                            $do_infect = false;" fullword ascii /* score: '4.00'*/
      $s16 = "                        Infect($path.$file.\"/\");" fullword ascii /* score: '4.00'*/
      $s17 = "PHP.QAZWSX" fullword ascii /* score: '4.00'*/
      $s18 = "        $s = fgets($sf, 4096);" fullword ascii /* score: '4.00'*/
      $s19 = "while (!feof($sf))" fullword ascii /* score: '4.00'*/
      $s20 = "                                fclose($victim);" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4850 and filesize < 6KB and
      8 of them
}

rule Virus_PHP_Skooop {
   meta:
      description = "php__infector - file Virus.PHP.Skooop.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "8e8b831e651711de5347ba94ac4324b3920cb051b700177a80dabbe5ea3ce3fa"
   strings:
      $s1 = "Virus.PHP.Skooop - written by Kluu in 2007." fullword ascii /* score: '18.00'*/
      $s2 = "@include($_GET['atk_script']);" fullword ascii /* score: '15.00'*/
      $s3 = "$self = strstr(file_get_contents(__FILE__), '//skooop!');" fullword ascii /* score: '14.00'*/
      $s4 = "echo '<b>Get the source of this phile <a href=\"'.$file.'s\">here</a></b>';" fullword ascii /* score: '9.00'*/
      $s5 = "function infect($dir) {" fullword ascii /* score: '9.00'*/
      $s6 = "                if (!strpos(fread($host, $filesize), '//skooop!')) {" fullword ascii /* score: '7.00'*/
      $s7 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
      $s8 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s9 = "            }" fullword ascii /* reversed goodware string '}            ' */ /* score: '6.00'*/
      $s10 = "                $host = fopen(\"$dir/$file\", 'r');" fullword ascii /* score: '4.00'*/
      $s11 = "                    fwrite($host, \"<?php\\n$self\");" fullword ascii /* score: '4.00'*/
      $s12 = "                if (($infected == false)) {" fullword ascii /* score: '4.00'*/
      $s13 = "//skooop!" fullword ascii /* score: '4.00'*/
      $s14 = "        $infected = true;" fullword ascii /* score: '4.00'*/
      $s15 = "                    $host = fopen(\"$dir/$file\", 'a');" fullword ascii /* score: '4.00'*/
      $s16 = "Revision 2007.12.30.0001" fullword ascii /* score: '4.00'*/
      $s17 = "                    $infected = false;" fullword ascii /* score: '4.00'*/
      $s18 = "infect('../../../../../../../../../../../../../../../../');" fullword ascii /* score: '4.00'*/
      $s19 = "                    fclose($host);" fullword ascii /* score: '4.00'*/
      $s20 = "            infect(\"$dir/$file\");" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule Virus_PHP_Polymorph_Rainbow {
   meta:
      description = "php__infector - file Virus.PHP.Polymorph-Rainbow.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "a4c9ca82b7f56ad4256b5a06c3ddc2b2058a66e567a2333c143f388ee7beab84"
   strings:
      $s1 = "- www.php.net & www.apachefriends.com" fullword ascii /* score: '22.00'*/
      $s2 = "  Execute this virus with PHP 4.3.3 + PEAR. I did it, and it worked really fine!" fullword ascii /* score: '22.00'*/
      $s3 = "<-- for the great sounds!!!" fullword ascii /* score: '17.00'*/
      $s4 = "<-- Great PHP information!!!" fullword ascii /* score: '17.00'*/
      $s5 = "<-- for helping me to don't commit suicide while searching" fullword ascii /* score: '14.00'*/
      $s6 = "lines (more lines --> more chance). But I tested about 30 generation" fullword ascii /* score: '13.00'*/
      $s7 = "- Theatre Of Tragedy | Darkfall" fullword ascii /* score: '13.00'*/
      $s8 = "if(strstr($filea,'.php')){$victim=fopen($filea,'r+');" fullword ascii /* score: '12.00'*/
      $s9 = "the victim file. Before infecting the virus checks, if there's already an " fullword ascii /* score: '12.00'*/
      $s10 = " $viccont=fread($victim,filesize($filea));" fullword ascii /* score: '12.00'*/
      $s11 = "if (!strstr(fread($victim, 25),'RainBow')){rewind($victim);" fullword ascii /* score: '12.00'*/
      $s12 = "  comes from, should understand it ;)" fullword ascii /* score: '11.00'*/
      $s13 = " $string=strtok(fread(fopen(__FILE__,'r'), filesize(__FILE__)),chr(13).chr(10));" fullword ascii /* score: '10.00'*/
      $s14 = "if($string{0}!='/' && $string{0}!='$'){$newcont.=$string.chr(13).chr(10);}}" fullword ascii /* score: '10.00'*/
      $s15 = "fwrite($victim,$allcont.$viccont);}" fullword ascii /* score: '9.00'*/
      $s16 = "This code is a prepender virus, which doesn't harm the victim file." fullword ascii /* score: '9.00'*/
      $s17 = "infection mark or the virus, which is 'RainBow'." fullword ascii /* score: '9.00'*/
      $s18 = " $changevars=array('changevars','string','newcont','curdir','filea','victim','viccont','newvars','returnvar','counti','countj','" ascii /* score: '9.00'*/
      $s19 = "  Polymorphism by SnakeByte. He wrote, that it will use more time to get many generations, which" fullword ascii /* score: '9.00'*/
      $s20 = "fclose($victim);}}" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2020 and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Virus_PHP_Newworld_Virus_PHP_Faces_0 {
   meta:
      description = "php__infector - from files Virus.PHP.Newworld.a, Virus.PHP.Faces.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "03b254a0f6c39a00b3f0d7427d4100f3ac2a94e3050c399a8d3c7a5668b0aeeb"
      hash2 = "7ff9bfc5d742f37742f8d00c90448115689d55080980e90197e6be331d9de751"
   strings:
      $s1 = " $bbugesqpty = substr(fread($ypxqrpsqcc, filesize(__FILE__)), 0, 1249);" fullword ascii /* score: '7.00'*/
      $s2 = " closedir($uudxleoyja);" fullword ascii /* score: '7.00'*/
      $s3 = " while(false !== ($ionwdbkwfh = readdir($uudxleoyja))){" fullword ascii /* score: '7.00'*/
      $s4 = " \"ccznwozuuo\", \"uudxleoyja\", \"ionwdbkwfh\", \"zohqscoxob\", \"skzmabzbfe\");" fullword ascii /* score: '4.00'*/
      $s5 = "  for($ccznwozuuo = 0; $ccznwozuuo < 9; $ccznwozuuo++)  $wurwejtvjx = $wurwejtvjx . chr(rand(97, 122));" fullword ascii /* score: '4.00'*/
      $s6 = "  $wurwejtvjx = chr(rand(97, 122));" fullword ascii /* score: '4.00'*/
      $s7 = " for($cctsvcopcx = 0; $cctsvcopcx < count($dhbpgxtamn); $cctsvcopcx++){" fullword ascii /* score: '4.00'*/
      $s8 = " $dhbpgxtamn = array(\"ypxqrpsqcc\", \"bbugesqpty\", \"dhbpgxtamn\", \"cctsvcopcx\", \"wurwejtvjx\"," fullword ascii /* score: '4.00'*/
      $s9 = " // php.faces  (c) by Kefi, 2003" fullword ascii /* score: '4.00'*/
      $s10 = " fclose($ypxqrpsqcc);" fullword ascii /* score: '4.00'*/
      $s11 = "  $bbugesqpty = str_replace(\"$dhbpgxtamn[$cctsvcopcx]\", \"$wurwejtvjx\", \"$bbugesqpty\");" fullword ascii /* score: '4.00'*/
      $s12 = " $ypxqrpsqcc = fopen(__FILE__, \"r\");" fullword ascii /* score: '4.00'*/
      $s13 = " $uudxleoyja = opendir(\".\");" fullword ascii /* score: '4.00'*/
      $s14 = "   if(substr($ionwdbkwfh, -3) == \"php\"){" fullword ascii /* score: '3.00'*/
      $s15 = "     $skzmabzbfe = substr(fread($zohqscoxob, filesize($ionwdbkwfh)), 5);" fullword ascii /* score: '2.00'*/
      $s16 = "  if($ionwdbkwfh != \".\" && $ionwdbkwfh != \"..\"){" fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 7KB and ( 8 of them )
      ) or ( all of them )
}

rule _Virus_PHP_VirusQuest_Virus_PHP_Webber_1 {
   meta:
      description = "php__infector - from files Virus.PHP.VirusQuest.a, Virus.PHP.Webber.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2878e1751cd2c34bbc664f59f85079f0e2e5538bda3c2046372faa6e1169c078"
      hash2 = "ddbbe97511b2d2816110d30cb1dfab06192d0d3802a84c7053e178d6e921fcc3"
   strings:
      $s1 = "$s = substr($file, -3);" fullword ascii /* score: '8.00'*/
      $s2 = "$c = fread ($f, filesize (__FILE__));" fullword ascii /* score: '7.00'*/
      $s3 = "while (($file = readdir($handle))!==false) {" fullword ascii /* score: '7.00'*/
      $s4 = "$g = fopen ($file, \"r\"); " fullword ascii /* score: '4.00'*/
      $s5 = "$f = fopen (__FILE__, \"r\");" fullword ascii /* score: '4.00'*/
      $s6 = "fclose ($g);" fullword ascii /* score: '4.00'*/
      $s7 = "closedir($handle); " fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "fwrite ($g,\"\\n\");" fullword ascii /* score: '4.00'*/
      $s9 = "fclose ($f);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "$c = \"\";" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "$g = fopen ($file, \"a+\"); " fullword ascii /* score: '4.00'*/
      $s12 = "$cont = fread ($g,filesize ($file));      " fullword ascii /* score: '2.00'*/
      $s13 = "if ($file != \".\" && $file != \"..\") " fullword ascii /* score: '2.00'*/
      $s14 = "if ($s==\"php\") " fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 2KB and ( 8 of them )
      ) or ( all of them )
}

rule _Virus_PHP_Indonesia_Virus_PHP_Newworld_2 {
   meta:
      description = "php__infector - from files Virus.PHP.Indonesia.a, Virus.PHP.Newworld.a"
      author = "Comps Team Malware Lab"
      reference = "php__infector php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "e4317d536b211994c9e29d1344bcab5875def0078685e3a58fa64f1339be3187"
      hash2 = "03b254a0f6c39a00b3f0d7427d4100f3ac2a94e3050c399a8d3c7a5668b0aeeb"
   strings:
      $s1 = "$all = opendir('C:\\Windows\\');" fullword ascii /* score: '10.00'*/
      $s2 = "if ( is_file($file) && is_writeable($file) )" fullword ascii /* score: '7.00'*/
      $s3 = "$look = fread($new, filesize($file));" fullword ascii /* score: '7.00'*/
      $s4 = "$fputs($new, __FILE__);" fullword ascii /* score: '4.00'*/
      $s5 = "$fputs($new, \"?>\");" fullword ascii /* score: '4.00'*/
      $s6 = "$new = fopen($file, \"a\");" fullword ascii /* score: '4.00'*/
      $s7 = "if ( ($inf=false) )" fullword ascii /* score: '4.00'*/
      $s8 = "$fputs($new, \"\\\"); \");" fullword ascii /* score: '4.00'*/
      $s9 = "$new = fopen($file, \"r\");" fullword ascii /* score: '4.00'*/
      $s10 = "$inf = true;" fullword ascii /* score: '1.00'*/
      $s11 = "if (!$yes) $inf = false;" fullword ascii /* score: '1.00'*/
      $s12 = "$exe = false;" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x6a24 or uint16(0) == 0x3f3c ) and filesize < 7KB and ( 8 of them )
      ) or ( all of them )
}

