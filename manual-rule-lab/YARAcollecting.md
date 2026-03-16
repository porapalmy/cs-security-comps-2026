# Background for our collection of YARA rules

After collecting malwares, we now need to collect YARA rules. Usually we need very specific YARA rules to detect specific malware. But they are hard to find because when people post their rules online they don’t usually include the malware source code they created it from, or they could name files differently, so there is a lot of opportunity for mixmatch variations out there.

Because of this we decided to broaden our groupings of malware categories to collect broader rules. Instead of focusing on trying to find one to one matches, we just found general YARA rules based on the categories of malware we collected hoping there may be some overlap because they are all categorised in the same group.

With this reasoning we are able to find general yara rules for our web based malware and general yara rules for files.

The initial rules set collected from online research and literature review is stored in the `initial-rules-literature` folder. This folder contains curated YARA rules for both web-based and file-based malware. These rules were gathered from various trusted sources and categorized to ensure broad coverage of malware detection. The rules include:

- Web-based malware rules: Focused on detecting obfuscated JavaScript, phishing-related keywords, and web shell patterns.
- File-based malware rules: Targeting ransomware, Trojans, and other file-based threats.

These are some of the example sources we took from to get YARA rules:

- https://github.com/imp0rtp3/js-yara-rules/tree/main/yara
- https://github.com/codewatchorg/Burp-Yara-Rules/blob/master/javascript_exploit_and_obfuscation.yar
- https://github.com/t4d/PhishingKit-Yara-Rules
- https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/core.webshell_detection.yara
- https://github.com/Yara-Rules/rules/tree/master/webshells
- https://github.com/codewatchorg/Burp-Yara-Rules

The `initial-rules-literature` folder serves as a foundational collection for further refinement and integration into the pipeline.
