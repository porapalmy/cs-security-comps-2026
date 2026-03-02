/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__loose__bin
   Reference: php__loose__bin php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule backdoor_php_solostell_a_e__d825c2e9f2b0 {
   meta:
      description = "php__loose__bin - file backdoor_php_solostell_a_e__d825c2e9f2b0"
      author = "Comps Team Malware Lab"
      reference = "php__loose__bin php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "d825c2e9f2b0fac4f90b2fc2eba0f5bcf5446f9fff5366fd8b6a1540b7126040"
   strings:
      $s1 = "          $output = command(\"cscript.exe /Nologo /E:Vbscript $tmpfname\");" fullword ascii /* score: '29.00'*/
      $s2 = "                   if (@ftp_login($connection,$login,$password))" fullword ascii /* score: '18.00'*/
      $s3 = "function compress(&$filedump)" fullword ascii /* score: '17.00'*/
      $s4 = "    if ($target_file && $upload_file && !$use_exec)" fullword ascii /* score: '17.00'*/
      $s5 = "function get_temp_filename()" fullword ascii /* score: '16.00'*/
      $s6 = "                $output .= command(\"mv -f $name1 $name2\");" fullword ascii /* score: '15.00'*/
      $s7 = "        $output .= command(\"dir /a $dfr\");" fullword ascii /* score: '15.00'*/
      $s8 = "                $output .= command(\"cp -f $name1 $name2\");" fullword ascii /* score: '15.00'*/
      $s9 = "#TODO: if version 4.2.3 - 4.0.3." fullword ascii /* score: '15.00'*/
      $s10 = "# if (@ini_get('file_uploads') == false) @ini_set('file_uploads',true);" fullword ascii /* score: '15.00'*/
      $s11 = "      $blah = command(\"gcc -o /tmp/backc /tmp/back.c\");" fullword ascii /* score: '15.00'*/
      $s12 = "                  $output .= command(\"rm -f $file\");" fullword ascii /* score: '15.00'*/
      $s13 = "        $output .= command(\"dir /S /a $dfra\");" fullword ascii /* score: '15.00'*/
      $s14 = "  if (!empty($HTTP_POST_FILES['userfile']['name']))" fullword ascii /* score: '15.00'*/
      $s15 = "  if (!empty($_REQUEST['not_exec']) && $_REQUEST['not_exec']) $safe_mode = 1;" fullword ascii /* score: '15.00'*/
      $s16 = "  $world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword ascii /* score: '14.00'*/
      $s17 = "  $s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']);" fullword ascii /* score: '14.00'*/
      $s18 = "  $s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']);" fullword ascii /* score: '14.00'*/
      $s19 = "  $s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']);" fullword ascii /* score: '14.00'*/
      $s20 = "  if( $mode & 0x200 ) $world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T';" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule backdoor_php_bajay__5f65cce93f2d {
   meta:
      description = "php__loose__bin - file backdoor_php_bajay__5f65cce93f2d"
      author = "Comps Team Malware Lab"
      reference = "php__loose__bin php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "5f65cce93f2db3f3e7a6bbba70a644103aa8d5530a0f2cb535543b207d33f34c"
   strings:
      $s1 = "  $remotehost = \"irc.dal.net\";" fullword ascii /* score: '20.00'*/
      $s2 = "$remotehost= $remotehst2[rand(0,count($remotehst2) - 1)];" fullword ascii /* score: '20.00'*/
      $s3 = "elseif ($com[3]==':`vhost' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '18.00'*/
      $s4 = "//fighter script - BAJAY" fullword ascii /* score: '18.00'*/
      $s5 = "ini_set('user_agent','MSIE 5\\.5;');" fullword ascii /* score: '17.00'*/
      $s6 = "  $Header .= 'USER '.$username.' '.$localhost.' '.$remotehost.' :'.$realname . CRL;" fullword ascii /* score: '16.00'*/
      $s7 = "$username = $usr1[rand(0,count($usr1) - 1)].$usr1[rand(0,count($usr1) - 1)].$usr1[rand(0,count($usr1) - 1)];" fullword ascii /* score: '15.00'*/
      $s8 = "$remotehst2= array(\"irc.mojok.org\",\"irc.indoirc.net\");" fullword ascii /* score: '15.00'*/
      $s9 = "} else { $remotehost = $com[4]; }" fullword ascii /* score: '15.00'*/
      $s10 = "fputs($fp,'NOTICE ' . $com[4] . ' :You`re Now Known As My '.$com[5].' Added By '.$dNick.' Now Type: pass <your pass33] <Spyderur" ascii /* score: '15.00'*/
      $s11 = "} else { fputs($fp,'NOTICE ' . $dcom[2] . ' :Pass salah cux! Type: pass <your pass> To Set Your Own Password then Auth Again ' ." ascii /* score: '15.00'*/
      $s12 = "} else { fputs($fp,'NOTICE ' . $dNick . ' :Wrong Command! Type: deluser <nick> ' . CRL); }" fullword ascii /* score: '13.00'*/
      $s13 = "elseif ($com[3]==':`botnick' && $com[4] && !$chan && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s14 = "elseif ($com[3]==':`part' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s15 = "elseif ($auth[\"$dNick\"][\"status\"] && $com[3]==':pass' && $com[4]) {" fullword ascii /* score: '13.00'*/
      $s16 = "elseif ($auth[\"$dNick\"][\"status\"] && $com[3]==':chgpass' && $com[4] && $com[5]) {" fullword ascii /* score: '13.00'*/
      $s17 = "elseif ($com[3]==':`join' && $com[4] && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s18 = "elseif ($com[3]==':`awaymsg' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s19 = "elseif ($com[3]==':`jump' && $auth[\"$dNick\"][\"status\"]==\"Admin\") {" fullword ascii /* score: '13.00'*/
      $s20 = "elseif ($auth[\"$dNick\"][\"status\"] && $com[3]==':adduser' && $com[4] && $com[4]!=$nick && $com[5]) {" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 90KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

