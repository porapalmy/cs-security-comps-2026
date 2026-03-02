/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__macker
   Reference: php__macker php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_Macker {
   meta:
      description = "php__macker - file Backdoor.PHP.Macker.b"
      author = "Comps Team Malware Lab"
      reference = "php__macker php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4abe9875f67c1fe6a007397189962a3d3b99a6251c601128936dfbd6709c193d"
   strings:
      $x1 = "  elseif ( $cmd==\"execute\" ) {/*<!-- Execute the executable -->*/" fullword ascii /* score: '34.00'*/
      $x2 = "elseif ( $cmd==\"uploadproc\" ) { /* <!-- Process Uploaded file --> */" fullword ascii /* score: '33.00'*/
      $x3 = "/* <!-- Execute --> */" fullword ascii /* score: '31.00'*/
      $s4 = "echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii /* score: '30.00'*/
      $s5 = "   is coded for unsecure servers, if your server is secured the script will hide commands" fullword ascii /* score: '25.00'*/
      $s6 = "<input name=\"submit_btn\" class=\"inputbutton\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '24.00'*/
      $s7 = "/* <!-- Download --> */" fullword ascii /* score: '23.00'*/
      $s8 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s9 = "/* HTTP Authorisation password, uncomment if you want to use this */" fullword ascii /* score: '22.00'*/
      $s10 = "elseif ( $cmd==\"deldir\" ) { /*<!-- Delete a directory and all it's files --> */" fullword ascii /* score: '22.00'*/
      $s11 = "elseif ( $cmd==\"newdir\" ) { /*<!-- Create new directory with default name --> */" fullword ascii /* score: '22.00'*/
      $s12 = "elseif ( $cmd==\"ren\" ) { /* <!-- File and Directory Rename --> */" fullword ascii /* score: '22.00'*/
      $s13 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword ascii /* score: '22.00'*/
      $s14 = "elseif ( $cmd==\"newfile\" ) { /*<!-- Create new file with default name --> */" fullword ascii /* score: '22.00'*/
      $s15 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword ascii /* score: '22.00'*/
      $s16 = "elseif ( $cmd==\"edit\" ) { /*<!-- Edit a file and save it afterwards with the saveedit block. --> */" fullword ascii /* score: '22.00'*/
      $s17 = " elseif ( $cmd==\"delfile\" ) { /*<!-- Delete a file --> */" fullword ascii /* score: '22.00'*/
      $s18 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s19 = "elseif ( $cmd==\"saveedit\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s20 = "header(\"Content-Disposition: attachment; filename=$downloadto$add\");" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule Backdoor_PHP_Macker_2 {
   meta:
      description = "php__macker - file Backdoor.PHP.Macker.a"
      author = "Comps Team Malware Lab"
      reference = "php__macker php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "c0cfb638e2fef23466e0c44af4b313eee978c3c09f4430c1dfd5f11048e4e724"
   strings:
      $x1 = "  elseif ( $cmd==\"execute\" ) {/*<!-- Execute the executable -->*/" fullword ascii /* score: '34.00'*/
      $x2 = "elseif ( $cmd==\"uploadproc\" ) { /* <!-- Process Uploaded file --> */" fullword ascii /* score: '33.00'*/
      $x3 = "/* <!-- Execute --> */" fullword ascii /* score: '31.00'*/
      $s4 = "echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii /* score: '30.00'*/
      $s5 = "   is coded for unsecure servers, if your server is secured the script will hide commands" fullword ascii /* score: '25.00'*/
      $s6 = "<input name=\"submit_btn\" class=\"inputbutton\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '24.00'*/
      $s7 = "/* <!-- Download --> */" fullword ascii /* score: '23.00'*/
      $s8 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s9 = "/* HTTP Authorisation password, uncomment if you want to use this */" fullword ascii /* score: '22.00'*/
      $s10 = "elseif ( $cmd==\"deldir\" ) { /*<!-- Delete a directory and all it's files --> */" fullword ascii /* score: '22.00'*/
      $s11 = "elseif ( $cmd==\"newdir\" ) { /*<!-- Create new directory with default name --> */" fullword ascii /* score: '22.00'*/
      $s12 = "elseif ( $cmd==\"ren\" ) { /* <!-- File and Directory Rename --> */" fullword ascii /* score: '22.00'*/
      $s13 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword ascii /* score: '22.00'*/
      $s14 = "elseif ( $cmd==\"newfile\" ) { /*<!-- Create new file with default name --> */" fullword ascii /* score: '22.00'*/
      $s15 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword ascii /* score: '22.00'*/
      $s16 = "elseif ( $cmd==\"edit\" ) { /*<!-- Edit a file and save it afterwards with the saveedit block. --> */" fullword ascii /* score: '22.00'*/
      $s17 = " elseif ( $cmd==\"delfile\" ) { /*<!-- Delete a file --> */" fullword ascii /* score: '22.00'*/
      $s18 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s19 = "elseif ( $cmd==\"saveedit\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s20 = "header(\"Content-Disposition: attachment; filename=$downloadto$add\");" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Backdoor_PHP_Macker_Backdoor_PHP_Macker_0 {
   meta:
      description = "php__macker - from files Backdoor.PHP.Macker.b, Backdoor.PHP.Macker.a"
      author = "Comps Team Malware Lab"
      reference = "php__macker php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "4abe9875f67c1fe6a007397189962a3d3b99a6251c601128936dfbd6709c193d"
      hash2 = "c0cfb638e2fef23466e0c44af4b313eee978c3c09f4430c1dfd5f11048e4e724"
   strings:
      $x1 = "  elseif ( $cmd==\"execute\" ) {/*<!-- Execute the executable -->*/" fullword ascii /* score: '34.00'*/
      $x2 = "elseif ( $cmd==\"uploadproc\" ) { /* <!-- Process Uploaded file --> */" fullword ascii /* score: '33.00'*/
      $x3 = "/* <!-- Execute --> */" fullword ascii /* score: '31.00'*/
      $s4 = "echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii /* score: '30.00'*/
      $s5 = "   is coded for unsecure servers, if your server is secured the script will hide commands" fullword ascii /* score: '25.00'*/
      $s6 = "<input name=\"submit_btn\" class=\"inputbutton\" type=\"submit\" value=\"Execute Command\"></p>" fullword ascii /* score: '24.00'*/
      $s7 = "/* <!-- Download --> */" fullword ascii /* score: '23.00'*/
      $s8 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii /* score: '23.00'*/
      $s9 = "/* HTTP Authorisation password, uncomment if you want to use this */" fullword ascii /* score: '22.00'*/
      $s10 = "elseif ( $cmd==\"deldir\" ) { /*<!-- Delete a directory and all it's files --> */" fullword ascii /* score: '22.00'*/
      $s11 = "elseif ( $cmd==\"newdir\" ) { /*<!-- Create new directory with default name --> */" fullword ascii /* score: '22.00'*/
      $s12 = "elseif ( $cmd==\"ren\" ) { /* <!-- File and Directory Rename --> */" fullword ascii /* score: '22.00'*/
      $s13 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword ascii /* score: '22.00'*/
      $s14 = "elseif ( $cmd==\"newfile\" ) { /*<!-- Create new file with default name --> */" fullword ascii /* score: '22.00'*/
      $s15 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword ascii /* score: '22.00'*/
      $s16 = "elseif ( $cmd==\"edit\" ) { /*<!-- Edit a file and save it afterwards with the saveedit block. --> */" fullword ascii /* score: '22.00'*/
      $s17 = " elseif ( $cmd==\"delfile\" ) { /*<!-- Delete a file --> */" fullword ascii /* score: '22.00'*/
      $s18 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s19 = "elseif ( $cmd==\"saveedit\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii /* score: '22.00'*/
      $s20 = "header(\"Content-Disposition: attachment; filename=$downloadto$add\");" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

