/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__lanker
   Reference: php__lanker php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_Lanker {
   meta:
      description = "php__lanker - file Backdoor.PHP.Lanker.b"
      author = "Comps Team Malware Lab"
      reference = "php__lanker php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "fb156d9fd55ce8d4ec8f9673f086400dc6bc6db37a4063672b07b01db1df3b67"
   strings:
      $x1 = "frm.tmpcmd.value+=\"$c = $s->ShellExecute($a,$b);\\n\"" fullword ascii /* score: '32.00'*/
      $s2 = "frm.tmpcmd.value+=\"var_dump(@$shell->RegRead($regpath));\\n\"" fullword ascii /* score: '29.00'*/
      $s3 = ":<br><INPUT  size=24 name=\\\"cmdpath\\\" value=\\\"c:/winnt/system32/cmd.exe\\\"><br>" fullword ascii /* score: '28.00'*/
      $s4 = "frm.tmpcmd.value+=\"$exec = $wsh->exec(chr(99).chr(109).chr(100).chr(46).chr(101).chr(120).chr(101).chr(32).chr(47).chr(99).chr(" ascii /* score: '27.00'*/
      $s5 = "frm.tmpcmd.value+=\"if (isset($url)) {$proxycontents = @file_get_contents($url);\\n\"" fullword ascii /* score: '27.00'*/
      $s6 = "frm.tmpcmd.value+=\"$exec = $wsh->exec(chr(99).chr(109).chr(100).chr(46).chr(101).chr(120).chr(101).chr(32).chr(47).chr(99).chr(" ascii /* score: '25.00'*/
      $s7 = ":<br><INPUT size=24 name=\\\"runfile\\\" value=\\\"/c net user > c:/log.txt\\\"><br><INPUT   onclick='Javascipt:frm.tmpcmd.name=" ascii /* score: '23.00'*/
      $s8 = ":<br><INPUT size=24 name=\\\"runfile\\\" value=\\\"/c net user > c:/log.txt\\\"><br><INPUT   onclick='Javascipt:frm.tmpcmd.name=" ascii /* score: '23.00'*/
      $s9 = "frm.tmpcmd.value+=\"$dbpassword= \"" fullword ascii /* score: '22.00'*/
      $s10 = "frm.tmpcmd.value+=\"$shell= &new COM(chr(87).chr(83).chr(99).chr(114).chr(105).chr(112).chr(116).chr(46).chr(83).chr(104).chr(10" ascii /* score: '22.00'*/
      $s11 = "frm.tmpcmd.value+=\"@mysql_connect($servername,$dbusername,$dbpassword) or die($message);\\n\"" fullword ascii /* score: '22.00'*/
      $s12 = "frm.tmpcmd.value+=\"$stdout = $exec->StdOut ();\\n\"" fullword ascii /* score: '22.00'*/
      $s13 = "frm.tmpcmd.value+=\"$shell= &new COM(chr(87).chr(83).chr(99).chr(114).chr(105).chr(112).chr(116).chr(46).chr(83).chr(104).chr(10" ascii /* score: '22.00'*/
      $s14 = "frm.tmpcmd.value+=frm.execfun.value" fullword ascii /* score: '22.00'*/
      $s15 = "frm.tmpcmd.value+=duqu(frm.dbpassword.value)" fullword ascii /* score: '22.00'*/
      $s16 = "frm.tmpcmd.value+=\" echo ($proxycontents) ? $proxycontents:" fullword ascii /* score: '22.00'*/
      $s17 = "frm.tmpcmd.value+=\"$contents=@fread($fp, filesize($filename));\\n\"" fullword ascii /* score: '22.00'*/
      $s18 = "frm.tmpcmd.value+=\"header($h1.$fn);\\n\"" fullword ascii /* score: '19.00'*/
      $s19 = "frm.tmpcmd.value+=\"echo $s.$contents.$e;\\n\"" fullword ascii /* score: '19.00'*/
      $s20 = "frm.tmpcmd.value+=\"header($h2);\\n\"" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_Lanker_2 {
   meta:
      description = "php__lanker - file Backdoor.PHP.Lanker.a"
      author = "Comps Team Malware Lab"
      reference = "php__lanker php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "5266e935bcce93697554c2e5b66b397c5c79e7b7091fdc7203d2247fb2d99f54"
   strings:
      $s1 = "frm.tmpcmd.value+=\"@mysql_connect($servername,$dbusername,$dbpassword) or die($message);\\n\"" fullword ascii /* score: '22.00'*/
      $s2 = "frm.tmpcmd.value+=duqu(frm.dbpassword.value)" fullword ascii /* score: '22.00'*/
      $s3 = "frm.tmpcmd.value+=\"$contents=@fread($fp, filesize($filename));\\n\"" fullword ascii /* score: '22.00'*/
      $s4 = "frm.tmpcmd.value+=\"$dbpassword=\"" fullword ascii /* score: '22.00'*/
      $s5 = "frm.tmpcmd.value+=\"header($h1.$fn);\\n\"" fullword ascii /* score: '19.00'*/
      $s6 = "frm.tmpcmd.value+=\"echo $s.$contents.$e;\\n\"" fullword ascii /* score: '19.00'*/
      $s7 = "frm.tmpcmd.value+=\"header($h2);\\n\"" fullword ascii /* score: '19.00'*/
      $s8 = "frm.tmpcmd.value+=\"$contents=htmlspecialchars($contents);\\n\"" fullword ascii /* score: '19.00'*/
      $s9 = "frm.tmpcmd.value+=\"header($h.$fe);\\n\"" fullword ascii /* score: '19.00'*/
      $s10 = "size=85 value=http://127.0.0.1/door.php name=act> " fullword ascii /* score: '19.00'*/
      $s11 = "frm.tmpcmd.value+=\"@system($cmd);\\n\"" fullword ascii /* score: '19.00'*/
      $s12 = "frm.tmpcmd.value+=\"if($msg) echo chr(79).chr(75).chr(33);\\n\"" fullword ascii /* score: '17.00'*/
      $s13 = "frm.tmpcmd.value+=duqu(frm.dbusername.value)" fullword ascii /* score: '17.00'*/
      $s14 = "frm.tmpcmd.value+=\"$dbusername=\"" fullword ascii /* score: '17.00'*/
      $s15 = "frm.tmpcmd.value+=\"$h1=chr(67).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(45).chr(68).chr(105).chr(115).chr(112)" ascii /* score: '17.00'*/
      $s16 = "frm.tmpcmd.value+=\"$e=chr(60).chr(47).chr(112).chr(114).chr(101).chr(62);\\n\"" fullword ascii /* score: '17.00'*/
      $s17 = "all.act.value;frm.submit();frm.tmpcmd.name=tmpcmd' type=button value='" fullword ascii /* score: '17.00'*/
      $s18 = "frm.tmpcmd.value+=\"@readfile($df);\\n\"" fullword ascii /* score: '17.00'*/
      $s19 = "frm.tmpcmd.value+=\"if(@rmdir($dirs)) echo chr(79).chr(75).chr(33);\"" fullword ascii /* score: '17.00'*/
      $s20 = "frm.tmpcmd.value+=duqu(frm.sql.value)" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 50KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Backdoor_PHP_Lanker_Backdoor_PHP_Lanker_0 {
   meta:
      description = "php__lanker - from files Backdoor.PHP.Lanker.b, Backdoor.PHP.Lanker.a"
      author = "Comps Team Malware Lab"
      reference = "php__lanker php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "fb156d9fd55ce8d4ec8f9673f086400dc6bc6db37a4063672b07b01db1df3b67"
      hash2 = "5266e935bcce93697554c2e5b66b397c5c79e7b7091fdc7203d2247fb2d99f54"
   strings:
      $s1 = "frm.tmpcmd.value+=\"@mysql_connect($servername,$dbusername,$dbpassword) or die($message);\\n\"" fullword ascii /* score: '22.00'*/
      $s2 = "frm.tmpcmd.value+=duqu(frm.dbpassword.value)" fullword ascii /* score: '22.00'*/
      $s3 = "frm.tmpcmd.value+=\"$contents=@fread($fp, filesize($filename));\\n\"" fullword ascii /* score: '22.00'*/
      $s4 = "frm.tmpcmd.value+=\"header($h1.$fn);\\n\"" fullword ascii /* score: '19.00'*/
      $s5 = "frm.tmpcmd.value+=\"echo $s.$contents.$e;\\n\"" fullword ascii /* score: '19.00'*/
      $s6 = "frm.tmpcmd.value+=\"header($h2);\\n\"" fullword ascii /* score: '19.00'*/
      $s7 = "frm.tmpcmd.value+=\"$contents=htmlspecialchars($contents);\\n\"" fullword ascii /* score: '19.00'*/
      $s8 = "frm.tmpcmd.value+=\"header($h.$fe);\\n\"" fullword ascii /* score: '19.00'*/
      $s9 = "frm.tmpcmd.value+=\"if($msg) echo chr(79).chr(75).chr(33);\\n\"" fullword ascii /* score: '17.00'*/
      $s10 = "frm.tmpcmd.value+=duqu(frm.dbusername.value)" fullword ascii /* score: '17.00'*/
      $s11 = "frm.tmpcmd.value+=\"$dbusername=\"" fullword ascii /* score: '17.00'*/
      $s12 = "frm.tmpcmd.value+=\"$h1=chr(67).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(45).chr(68).chr(105).chr(115).chr(112)" ascii /* score: '17.00'*/
      $s13 = "frm.tmpcmd.value+=\"$e=chr(60).chr(47).chr(112).chr(114).chr(101).chr(62);\\n\"" fullword ascii /* score: '17.00'*/
      $s14 = "all.act.value;frm.submit();frm.tmpcmd.name=tmpcmd' type=button value='" fullword ascii /* score: '17.00'*/
      $s15 = "frm.tmpcmd.value+=\"@readfile($df);\\n\"" fullword ascii /* score: '17.00'*/
      $s16 = "frm.tmpcmd.value+=\"if(@rmdir($dirs)) echo chr(79).chr(75).chr(33);\"" fullword ascii /* score: '17.00'*/
      $s17 = "frm.tmpcmd.value+=duqu(frm.sql.value)" fullword ascii /* score: '17.00'*/
      $s18 = "frm.tmpcmd.value=\"$message=chr(102).chr(97).chr(105).chr(108).chr(33);\\n\"" fullword ascii /* score: '17.00'*/
      $s19 = "frm.tmpcmd.value+=\"$h2=(68).chr(101).chr(115).chr(99).chr(114).chr(105).chr(112).chr(116).chr(105).chr(111).chr(110).chr(58).ch" ascii /* score: '17.00'*/
      $s20 = "frm.tmpcmd.value+=\"$f = chr(60).chr(98).chr(114).chr(62);\"" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 80KB and ( 8 of them )
      ) or ( all of them )
}

