/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__albania
   Reference: php__albania php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_Albania {
   meta:
      description = "php__albania - file Backdoor.PHP.Albania.a"
      author = "Comps Team Malware Lab"
      reference = "php__albania php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "023286b911c54fe5e3e9545f0209bf8bd4a964c833d69396371ecb85f6355389"
   strings:
      $x1 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x2 = "  else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - s" ascii /* score: '37.00'*/
      $x3 = "'eng_text85'=>'Test bypass safe_mode with commands execute via MSSQL server'," fullword ascii /* score: '33.00'*/
      $x4 = "  if(@ftp_login($connection,$user,$user)) { echo \"[+] $user:$user - success\\r\\n\"; $suc++; }" fullword ascii /* score: '31.00'*/
      $s5 = "echo '</table>'.$table_up3.\"</div></div><div align=center id='n'><font face=Verdana size=-2><b>o---[  a.S.c - LONG LIVE ETHNIC " ascii /* score: '28.00'*/
      $s6 = "'eng_text99'=>'* use username from /etc/passwd for ftp login and password'," fullword ascii /* score: '28.00'*/
      $s7 = "echo sr(25,\"<b>\".$lang[$language.'_text38'].$arrow.\"</b>\",in('text','ftp_password',45,(!empty($_POST['ftp_password'])?($_POS" ascii /* score: '27.00'*/
      $s8 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$lang[$language.'_text41'].$arrow.\"</b>\",in('ch" ascii /* score: '27.00'*/
      $s9 = "'eng_text2' =>'Execute command on server'," fullword ascii /* score: '26.00'*/
      $s10 = "'eng_text1' =>'Executed command'," fullword ascii /* score: '26.00'*/
      $s11 = "'eng_text120'=>'Run Command in Safe-Mode <font color=\\\"red\\\">Vulnerable</font>'," fullword ascii /* score: '26.00'*/
      $s12 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner or UID\\r\\n- for CHGRP - group name or GID\\r\\n" ascii /* score: '26.00'*/
      $s13 = "echo (!empty($_POST['php_eval'])?($_POST['php_eval']):(\"/* delete script */\\r\\n//unlink(\\\"ghhghh.php\\\");\\r\\n//readfile(" ascii /* score: '25.00'*/
      $s14 = "     @mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii /* score: '24.00'*/
      $s15 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii /* score: '24.00'*/
      $s16 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_query\")&&($_POST['cmd']!=\"ftp_bru" ascii /* score: '24.00'*/
      $s17 = "  if(!@ftp_login($connection,$_POST['ftp_login'],$_POST['ftp_password'])) { err(4); }" fullword ascii /* score: '23.00'*/
      $s18 = "echo sr(15,\"<b>\".$lang[$language.'_text36'].$arrow.\"</b>\",in('text','test3_md',15,(!empty($_POST['test3_md'])?($_POST['test3" ascii /* score: '23.00'*/
      $s19 = " $_POST['cmd'] = which('fetch').\" -o \".$_POST['loc_file'].\" -p \".$_POST['rem_file'].\"\";" fullword ascii /* score: '22.00'*/
      $s20 = " else if(!$users=get_users()) { echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#660000><fo" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_Albania_2 {
   meta:
      description = "php__albania - file Backdoor.PHP.Albania.b"
      author = "Comps Team Malware Lab"
      reference = "php__albania php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "e1615b125ae38d904ae0eecdcc7273745f3bf15e7aa2fcb484d6e98e734bfc15"
   strings:
      $s1 = "elseif(function_exists('shell_exec')){" fullword ascii /* score: '14.00'*/
      $s2 = "$res = @ob_get_contents();" fullword ascii /* score: '14.00'*/
      $s3 = "$res = @shell_exec($cfe);" fullword ascii /* score: '14.00'*/
      $s4 = "$alb9 = get_current_user();" fullword ascii /* score: '12.00'*/
      $s5 = "if(function_exists('exec')){" fullword ascii /* score: '12.00'*/
      $s6 = "@exec($cfe,$res);" fullword ascii /* score: '12.00'*/
      $s7 = "echo \"Free:\".view_size($free).\"<br>\"; " fullword ascii /* score: '10.00'*/
      $s8 = "$alb4 = @getcwd();" fullword ascii /* score: '9.00'*/
      $s9 = "$alb5 = getenv(\"SERVER_SOFTWARE\");" fullword ascii /* score: '9.00'*/
      $s10 = "echo \"UNITED #D-Devils By The King Sir|ToTTi<br>\";" fullword ascii /* score: '9.00'*/
      $s11 = "$eseguicmd=ex($cmd);" fullword ascii /* score: '9.00'*/
      $s12 = "echo \"uname -a: $alb<br>\";" fullword ascii /* score: '8.00'*/
      $s13 = "$alb2 = system(uptime);" fullword ascii /* score: '7.00'*/
      $s14 = "$alb3 = system(id);" fullword ascii /* score: '7.00'*/
      $s15 = "echo \"user: $alb9<br>\";" fullword ascii /* score: '7.00'*/
      $s16 = "elseif(function_exists('passthru')){" fullword ascii /* score: '7.00'*/
      $s17 = "echo $eseguicmd;" fullword ascii /* score: '7.00'*/
      $s18 = "@system($cfe);" fullword ascii /* score: '7.00'*/
      $s19 = "@passthru($cfe);" fullword ascii /* score: '7.00'*/
      $s20 = "elseif(function_exists('system')){" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 5KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

