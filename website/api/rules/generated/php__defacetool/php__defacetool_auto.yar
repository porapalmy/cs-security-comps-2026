/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__defacetool
   Reference: php__defacetool php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_DefaceTool {
   meta:
      description = "php__defacetool - file Backdoor.PHP.DefaceTool.ah"
      author = "Comps Team Malware Lab"
      reference = "php__defacetool php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4960e025e00d2d14b2ae596a9230135201eabf129586207b056fe548821a4835"
   strings:
      $x1 = "function overwrite(){inclVar();if(confirm(\"O script tentara substituir todos os arquivos (do diretorio atual) que\\nteem no nom" ascii /* score: '31.00'*/
      $s2 = "<font size=2>by r3v3ng4ns - revengans@hotmail.com </font>" fullword ascii /* score: '22.00'*/
      $s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDigite a URL do frame\",\"http://www.geocities.com/" ascii /* score: '20.00'*/
      $s4 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword ascii /* score: '20.00'*/
      $s5 = "$login=@posix_getuid(); $euid=@posix_geteuid(); $gid=@posix_getgid();" fullword ascii /* score: '20.00'*/
      $s6 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n\\nchdir &lt;diretorio&gt;; outros; cmds;\\nMuda o" ascii /* score: '20.00'*/
      $s7 = "ho completo\\n-Abrir arquivos remotos, use http:// ou ftp://\",\"<?=$chdir;?>/index.php\"); var dir = o.substring(0,o.lastIndexO" ascii /* score: '18.00'*/
      $s8 = "revengans@hotmail.com" fullword ascii /* score: '18.00'*/
      $s9 = "a o novo arquivo, e se for remoto,\\nutilize http:// e ftp://\")){keyw=prompt(\"Digite a palavra chave\",\".jpg\");newf=prompt(" ascii /* score: '18.00'*/
      $s10 = " a origem do arquivo que substituira\",\"http://www.colegioparthenon.com.br/ingles/bins/revenmail.jpg\");if(confirm(\"Se ocorrer" ascii /* score: '17.00'*/
      $s11 = "<option value=\"5\">use shell_exec()" fullword ascii /* score: '17.00'*/
      $s12 = "function shell($what){echo(shell_exec($what));}" fullword ascii /* score: '17.00'*/
      $s13 = "$ip=@gethostbyname($_SERVER['HTTP_HOST']);" fullword ascii /* score: '17.00'*/
      $s14 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDigite a URL do frame\",\"http://www.geocities.com/" ascii /* score: '16.00'*/
      $s15 = "ir /diretorio/sub/;pwd;ls\\n\\nPHPget, PHPwriter, Fileditor, File List e Overwrite\\nfale com o r3v3ng4ns :P\");" fullword ascii /* score: '16.00'*/
      $s16 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword ascii /* score: '16.00'*/
      $s17 = "o completo\\n-Se for remoto, use http:// ou ftp://:\",\"http://www.fineca.net/music/\");var dir = c.substring(0,c.lastIndexOf('/" ascii /* score: '14.00'*/
      $s18 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite o nome do arquivo que deseja abrir\\n-Utilize ca" ascii /* score: '14.00'*/
      $s19 = "function PHPget(){inclVar();var c=prompt(\"[ PHPget ] by r3v3ng4ns\\nDigite a ORIGEM do arquivo (url) com ate 7Mb\\n-Utilize cam" ascii /* score: '14.00'*/
      $s20 = "$output=ob_get_contents();ob_end_clean();" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_DefaceTool_2 {
   meta:
      description = "php__defacetool - file Backdoor.PHP.DefaceTool.b"
      author = "Comps Team Malware Lab"
      reference = "php__defacetool php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "eab6bd1b0a9f2e6b54f0684ed8a2e88839278306fdb1710fe16d82dd9b7d608d"
   strings:
      $x1 = "function overwrite(){inclVar();if(confirm(\"O script tentara substituir todos os arquivos (do diretorio atual) que\\nteem no nom" ascii /* score: '31.00'*/
      $s2 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDigite a URL do frame\",\"http://hostinganime.com/t" ascii /* score: '29.00'*/
      $s3 = "mpleto\\n-Se for remoto, use http:// ou ftp://:\",\"http://hostinganime.com/tool/nc.dat\");var dir = c.substring(0,c.lastIndexOf" ascii /* score: '27.00'*/
      $s4 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDigite a URL do frame\",\"http://hostinganime.com/t" ascii /* score: '25.00'*/
      $s5 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pronta de urls,\\nvc soh precisa escolher qual arquiv" ascii /* score: '23.00'*/
      $s6 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>" fullword ascii /* score: '22.00'*/
      $s7 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword ascii /* score: '20.00'*/
      $s8 = "$login=@posix_getuid(); $euid=@posix_geteuid(); $gid=@posix_getgid();" fullword ascii /* score: '20.00'*/
      $s9 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n\\nchdir <diretorio>; outros; cmds;\\nMuda o diret" ascii /* score: '20.00'*/
      $s10 = "ho completo\\n-Abrir arquivos remotos, use http:// ou ftp://\",\"<?=$chdir;?>/index.php\"); var dir = o.substring(0,o.lastIndexO" ascii /* score: '18.00'*/
      $s11 = "a o novo arquivo, e se for remoto,\\nutilize http:// e ftp://\")){keyw=prompt(\"Digite a palavra chave\",\".jpg\");newf=prompt(" ascii /* score: '18.00'*/
      $s12 = "$process = @proc_open(\"$what\",$descpec,$pipes);" fullword ascii /* score: '18.00'*/
      $s13 = "revengans@gmail.com" fullword ascii /* score: '18.00'*/
      $s14 = "$remote_addr=\"http://dezu.webshells.org/\";" fullword ascii /* score: '18.00'*/
      $s15 = " a origem do arquivo que substituira\",\"http://www.colegioparthenon.com.br/ingles/bins/revenmail.jpg\");if(confirm(\"Se ocorrer" ascii /* score: '17.00'*/
      $s16 = "<option value=\"5\">use shell_exec()" fullword ascii /* score: '17.00'*/
      $s17 = "function shell($what){echo(shell_exec($what));}" fullword ascii /* score: '17.00'*/
      $s18 = "$ip=@gethostbyname($_SERVER['HTTP_HOST']);" fullword ascii /* score: '17.00'*/
      $s19 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword ascii /* score: '16.00'*/
      $s20 = "echo fgets($pipes[1], 4096);" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_DefaceTool_3 {
   meta:
      description = "php__defacetool - file Backdoor.PHP.DefaceTool.ag"
      author = "Comps Team Malware Lab"
      reference = "php__defacetool php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "0b75252152514aee86e523790955db6a3038d2e14ec18abb41dd5b9bd5151872"
   strings:
      $s1 = "Autor: r3v3ng4ns - revengans@hotmail.com" fullword ascii /* score: '26.00'*/
      $s2 = "function shell($what){//envia o cmd para o sistema usado shell_exec() (tb conhecido como `backtik operator`)" fullword ascii /* score: '25.00'*/
      $s3 = "$phpget_addr=$remote_addr.\"get17\".$format_addr;//nome do arquivo do script que faz download de arquivos" fullword ascii /* score: '24.00'*/
      $s4 = " while (list($info, $value) = each ($uname)) { ?><b><?= $info ?>:</b> <?= $value ?><br><?php } ?><b>default user:</b> uid(<?= $l" ascii /* score: '23.00'*/
      $s5 = "<font size=2>by r3v3ng4ns - revengans@hotmail.com </font>" fullword ascii /* score: '22.00'*/
      $s6 = "//pega as variaveis usadas no script da url do navegador (www.com.br/index.php?fu=1&list=1&cmd=id)" fullword ascii /* score: '22.00'*/
      $s7 = "use http:// ou ftp://:\",\"http://www.colegioparthenon.com.br/dirativo/bd/nc.gif\");" fullword ascii /* score: '22.00'*/
      $s8 = "$remote_addr=\"http://127.0.0.1/~snagnever/defacement/paginanova/\";//endereco remoto da pasta aonde estao os scripts" fullword ascii /* score: '21.00'*/
      $s9 = "var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDigite a URL do frame\",\"http://www.geocities.com/revensite/index.htm\");" fullword ascii /* score: '20.00'*/
      $s10 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n\\nchdir &lt;diretorio&gt;; outros; cmds;\\nMuda o" ascii /* score: '20.00'*/
      $s11 = "o ainda que vcs me enviem um email (revengans@hotmail.com) com a versao do script que voces fizeram." fullword ascii /* score: '20.00'*/
      $s12 = "$login=@posix_getuid();" fullword ascii /* score: '20.00'*/
      $s13 = "if(confirm(\"O script tentara substituir todos os arquivos (do diretorio atual) que\\nteem no nome a palavra chave especificada." ascii /* score: '20.00'*/
      $s14 = "var c=prompt(\"[ PHPget ] by r3v3ng4ns\\nDigite a ORIGEM do arquivo (url) com ate 7Mb\\n-Utilize caminho completo\\n-Se for remo" ascii /* score: '18.00'*/
      $s15 = "$cmd_addr=$remote_addr.\"pro17\".$format_addr;//nome do arquivo do script da cmd (esse aqui, o script principal)" fullword ascii /* score: '18.00'*/
      $s16 = "<option value=\"5\">use shell_exec()" fullword ascii /* score: '17.00'*/
      $s17 = "newf=prompt(\"Digite a origem do arquivo que substituira\",\"http://www.colegioparthenon.com.br/ingles/bins/revenmail.jpg\");" fullword ascii /* score: '17.00'*/
      $s18 = "$ip=@gethostbyname($_SERVER['HTTP_HOST']);//mostra o ip do usuario" fullword ascii /* score: '17.00'*/
      $s19 = "@closelog();//desliga o system logger" fullword ascii /* score: '17.00'*/
      $s20 = "function execc($what){//envia o cmd para o sistema usando exec()" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 70KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Backdoor_PHP_DefaceTool_Backdoor_PHP_DefaceTool_0 {
   meta:
      description = "php__defacetool - from files Backdoor.PHP.DefaceTool.ah, Backdoor.PHP.DefaceTool.b"
      author = "Comps Team Malware Lab"
      reference = "php__defacetool php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4960e025e00d2d14b2ae596a9230135201eabf129586207b056fe548821a4835"
      hash2 = "eab6bd1b0a9f2e6b54f0684ed8a2e88839278306fdb1710fe16d82dd9b7d608d"
   strings:
      $x1 = "function overwrite(){inclVar();if(confirm(\"O script tentara substituir todos os arquivos (do diretorio atual) que\\nteem no nom" ascii /* score: '31.00'*/
      $s2 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword ascii /* score: '20.00'*/
      $s3 = "$login=@posix_getuid(); $euid=@posix_geteuid(); $gid=@posix_getgid();" fullword ascii /* score: '20.00'*/
      $s4 = "ho completo\\n-Abrir arquivos remotos, use http:// ou ftp://\",\"<?=$chdir;?>/index.php\"); var dir = o.substring(0,o.lastIndexO" ascii /* score: '18.00'*/
      $s5 = "a o novo arquivo, e se for remoto,\\nutilize http:// e ftp://\")){keyw=prompt(\"Digite a palavra chave\",\".jpg\");newf=prompt(" ascii /* score: '18.00'*/
      $s6 = " a origem do arquivo que substituira\",\"http://www.colegioparthenon.com.br/ingles/bins/revenmail.jpg\");if(confirm(\"Se ocorrer" ascii /* score: '17.00'*/
      $s7 = "function shell($what){echo(shell_exec($what));}" fullword ascii /* score: '17.00'*/
      $s8 = "$ip=@gethostbyname($_SERVER['HTTP_HOST']);" fullword ascii /* score: '17.00'*/
      $s9 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword ascii /* score: '16.00'*/
      $s10 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite o nome do arquivo que deseja abrir\\n-Utilize ca" ascii /* score: '14.00'*/
      $s11 = "erro e o arquivo nao puder ser substituido, deseja\\nque o script apague os arquivos e crie-os novamente com o novo conteudo?\\n" ascii /* score: '13.00'*/
      $s12 = "else if(strpos($cmd, ';ls') !==false) $cmd = str_replace(';ls', ';ls -F', $cmd);" fullword ascii /* score: '13.00'*/
      $s13 = "else if($cmd=='ls') $cmd = \"ls -F\";" fullword ascii /* score: '13.00'*/
      $s14 = "else if(strpos($cmd, '; ls') !==false) $cmd = str_replace('; ls', ';ls -F', $cmd);" fullword ascii /* score: '13.00'*/
      $s15 = "if(strpos($cmd, 'ls --') !==false) $cmd = str_replace('ls --', 'ls -F --', $cmd);" fullword ascii /* score: '13.00'*/
      $s16 = "else if(strpos($cmd, 'ls -') !==false) $cmd = str_replace('ls -', 'ls -F', $cmd);" fullword ascii /* score: '13.00'*/
      $s17 = "$total_addr=\"http://\".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'];" fullword ascii /* score: '12.00'*/
      $s18 = "if (@file_exists(\"/usr/bin/lynx\")) $pro4=\"<i>lynx</i> at /usr/bin/lynx, \";" fullword ascii /* score: '11.00'*/
      $s19 = "if (@file_exists(\"/usr/bin/nc\")) $pro2=\"<i>nc</i> at /usr/bin/nc, \";" fullword ascii /* score: '11.00'*/
      $s20 = "if (@file_exists(\"/usr/bin/cc\")) $pro6=\"<i>cc</i> at /usr/bin/cc \";" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x213c and filesize < 40KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_DefaceTool_Backdoor_PHP_DefaceTool_Backdoor_PHP_DefaceTool_1 {
   meta:
      description = "php__defacetool - from files Backdoor.PHP.DefaceTool.ah, Backdoor.PHP.DefaceTool.b, Backdoor.PHP.DefaceTool.ag"
      author = "Comps Team Malware Lab"
      reference = "php__defacetool php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4960e025e00d2d14b2ae596a9230135201eabf129586207b056fe548821a4835"
      hash2 = "eab6bd1b0a9f2e6b54f0684ed8a2e88839278306fdb1710fe16d82dd9b7d608d"
      hash3 = "0b75252152514aee86e523790955db6a3038d2e14ec18abb41dd5b9bd5151872"
   strings:
      $s1 = "<option value=\"5\">use shell_exec()" fullword ascii /* score: '17.00'*/
      $s2 = "$output=ob_get_contents();ob_end_clean();" fullword ascii /* score: '14.00'*/
      $s3 = "  if($fu==5){$fe=\"shell\";$feshow=\"shell_exec\";}" fullword ascii /* score: '14.00'*/
      $s4 = "elseif($funE('shell_exec')){$fe=\"shell\";$feshow=\"shell_exec\";}" fullword ascii /* score: '14.00'*/
      $s5 = "  if($fu==3){$fe=\"execc\";$feshow=\"exec\";}" fullword ascii /* score: '12.00'*/
      $s6 = "elseif($funE('exec')){$fe=\"execc\";$feshow=\"exec\";}" fullword ascii /* score: '12.00'*/
      $s7 = "<option value=\"3\">use exec()" fullword ascii /* score: '12.00'*/
      $s8 = "<TR><TD><DIV class=\"infop\"><b>user:</b> uid(<?=$login;?>) euid(<?=$euid;?>) gid(<?=$gid;?>)</DIV></TD></TR>" fullword ascii /* score: '11.00'*/
      $s9 = "if (strpos($cmd, 'chdir')!==false and strpos($cmd, 'chdir')=='0'){" fullword ascii /* score: '9.00'*/
      $s10 = "<? if($chdir!=getcwd()){?>" fullword ascii /* score: '9.00'*/
      $s11 = "if($chdir==getcwd() or empty($chdir) or $chdir==\"\")$showdir=\"\";else $showdir=\"+'chdir=$chdir&'\";" fullword ascii /* score: '9.00'*/
      $s12 = "<td width=\"75\"><DIV class=\"algod\">command</DIV></td>" fullword ascii /* score: '8.00'*/
      $s13 = "<option value=\"1\">use passthru()" fullword ascii /* score: '7.00'*/
      $s14 = "<option value=\"2\">use system()" fullword ascii /* score: '7.00'*/
      $s15 = "elseif($funE('system')){$fe=\"system\";$feshow=$fe;}" fullword ascii /* score: '7.00'*/
      $s16 = "  if($fu==2){$fe=\"system\";$feshow=$fe;}" fullword ascii /* score: '7.00'*/
      $s17 = "  if($fu==1){$fe=\"passthru\";$feshow=$fe;}" fullword ascii /* score: '7.00'*/
      $s18 = "</select><input type=\"button\" name=\"getBtn\" value=\"PHPget\" class=\"campo\" onClick=\"PHPget()\"><input type=\"button\" nam" ascii /* score: '5.00'*/
      $s19 = "<TR><TD><DIV class=\"infop\"><b>original path: </b><?=getcwd() ?></DIV></TD></TR><? } ?>" fullword ascii /* score: '5.00'*/
      $s20 = "<td><input type=\"button\" name=\"snd\" value=\"send cmd\" class=\"campo\" style=\"background-color:#313654\" onClick=\"enviaCMD" ascii /* score: '5.00'*/
   condition:
      ( uint16(0) == 0x213c and filesize < 70KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_DefaceTool_Backdoor_PHP_DefaceTool_2 {
   meta:
      description = "php__defacetool - from files Backdoor.PHP.DefaceTool.ah, Backdoor.PHP.DefaceTool.ag"
      author = "Comps Team Malware Lab"
      reference = "php__defacetool php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4960e025e00d2d14b2ae596a9230135201eabf129586207b056fe548821a4835"
      hash2 = "0b75252152514aee86e523790955db6a3038d2e14ec18abb41dd5b9bd5151872"
   strings:
      $s1 = "<font size=2>by r3v3ng4ns - revengans@hotmail.com </font>" fullword ascii /* score: '22.00'*/
      $s2 = "orio para aquele especificado e permanece nele. Eh como se fosse o 'cd' numa shell, mas precisa ser o primeiro da linha. ex: chd" ascii /* score: '11.00'*/
      $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n\\nchdir &lt;diretorio&gt;; outros; cmds;\\nMuda o" ascii /* score: '9.00'*/
      $s4 = "if($funE('passthru')){$fe=\"passthru\";$feshow=$fe;}" fullword ascii /* score: '7.00'*/
      $s5 = "$fe(\"$cmd  2>&1\");" fullword ascii /* score: '6.00'*/
      $s6 = "else {$fe=\"safemode\";$feshow=$fe;}" fullword ascii /* score: '4.00'*/
      $s7 = "if($fu!=\"\" or !empty($fu)){" fullword ascii /* score: '4.00'*/
      $s8 = "<table width=\"690\" border=\"0\" align=\"center\" cellpadding=\"2\" cellspacing=\"0\" bgcolor=\"#FFFFFF\">" fullword ascii /* score: '4.00'*/
      $s9 = "   $boom = explode(\" \",$cmd,2);" fullword ascii /* score: '4.00'*/
      $s10 = "if (!empty($output)) echo str_replace(\">\", \"&gt;\", str_replace(\"<\", \"&lt;\", $output));" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x213c and filesize < 70KB and ( all of them )
      ) or ( all of them )
}

