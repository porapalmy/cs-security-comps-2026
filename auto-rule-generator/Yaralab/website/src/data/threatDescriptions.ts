/**
 * Threat descriptions for YARA rules and heuristic checks.
 * 
 * To add a description for a new YARA rule:
 *   1. Add the rule to api/rules/malware.yar (the backend picks it up automatically)
 *   2. Optionally add an entry here with the rule name as key for rich educational content
 *   3. If no entry exists, the frontend auto-generates a title from the rule name
 *      (e.g., "WEB_Forced_Download_High" → "Web Forced Download High")
 */

export type ThreatDescription = {
    title: string;
    description: string;
    explanation: string;
    learnMore?: string;
};

export const THREAT_DESCRIPTIONS: Record<string, ThreatDescription> = {
    WEB_JS_Obfuscation_Stack_Medium: {
        title: "Hidden Malicious Code",
        description: "The site uses complex techniques to hide its true behavior.",
        explanation: "Think of this like writing a letter in invisible ink — the website is deliberately scrambling its code so that security tools and humans can't easily read what it does. Attackers use this technique to hide malware, credential-stealing scripts, or crypto miners. The code shown below was intentionally made unreadable, which is a strong indicator of malicious intent.",
        learnMore: "https://en.wikipedia.org/wiki/Obfuscation_(software)",
    },
    WEB_Redirect_Primitives_Medium: {
        title: "Forced Redirect",
        description: "Contains code that moves you to a different page without permission.",
        explanation: "Imagine someone grabbing your steering wheel and turning it — this code forces your browser to navigate to a completely different website without your consent. Legitimate websites almost never do this. Attackers use forced redirects to send you to phishing pages, malware download sites, or scam pages that look like real login forms.",
        learnMore: "https://en.wikipedia.org/wiki/URL_redirection#Manipulating_visitors",
    },
    WEB_MetaRefresh_Redirect_Medium: {
        title: "Instant Redirect",
        description: "Uses HTML to immediately send you to another website.",
        explanation: "This is a classic trick embedded directly in the page's HTML that tells your browser 'go somewhere else right now.' Unlike JavaScript redirects, this works even if scripts are disabled. It's commonly used in phishing campaigns where you think you're visiting one site but are silently sent to a lookalike page designed to steal your credentials.",
        learnMore: "https://en.wikipedia.org/wiki/Meta_refresh",
    },
    WEB_Forced_Download_High: {
        title: "Automatic Download",
        description: "Attempts to download a file to your computer automatically.",
        explanation: "This site is trying to push a file onto your computer without you clicking a download button. This is one of the most dangerous behaviors on the web — it's the primary way malware, ransomware, and trojans are distributed. The code creates an invisible download link and automatically 'clicks' it, bypassing your normal download prompts.",
        learnMore: "https://en.wikipedia.org/wiki/Drive-by_download",
    },
    WEB_Permission_Abuse_Notifications_Push_High: {
        title: "Notification Spam",
        description: "Aggressively requests browser notification permissions.",
        explanation: "The site is trying to trick you into clicking 'Allow' on a browser notification popup. Once you grant permission, it can send you an endless stream of fake virus warnings, scam ads, and clickbait notifications — even when you're not on the site. Some use this to redirect you to phishing or malware sites through notification clicks.",
        learnMore: "https://en.wikipedia.org/wiki/Browser_notification_spam",
    },
    WEB_ClickFraud_AdStuffing_Signals_Low: {
        title: "Ad Fraud / Hidden Windows",
        description: "Contains hidden elements used for fake ad clicks.",
        explanation: "This site has invisible elements (like 1×1 pixel iframes or hidden popups) designed to generate fake advertisement clicks in the background. While this primarily defrauds advertisers, it also slows down your browser, drains your battery, and can expose you to malicious ad networks that serve malware.",
    },
    Suspicious_Script: {
        title: "Suspicious Script",
        description: "Contains script tags with unusual or dangerous patterns.",
        explanation: "We found multiple suspicious patterns combined in the same page — things like inline scripts, base64-encoded data, eval() calls, and document.write(). While each of these can be innocent on their own, seeing several together in a small page is a classic fingerprint of injected malicious code, often from a compromised website.",
        learnMore: "https://en.wikipedia.org/wiki/Cross-site_scripting",
    },
    Auto_Redirect: {
        title: "Automatic Redirect",
        description: "Code that forces your browser to navigate away.",
        explanation: "Multiple redirect commands were found that force your browser to leave the current page. This is like being in a store where the doors automatically push you into a different room. Attackers chain these redirects to bounce you through several sites before landing on the final malicious page, making it harder to trace where the attack came from.",
        learnMore: "https://en.wikipedia.org/wiki/URL_redirection",
    },
    Hidden_Iframe: {
        title: "Hidden Webpage (Iframe)",
        description: "Loads an invisible webpage in the background.",
        explanation: "An iframe is like a picture frame that shows another webpage inside the current one. A hidden iframe (with 0 width/height) is invisible to you but fully functional — it can load a malicious page, execute drive-by downloads, steal cookies, or run cryptocurrency miners, all while you see nothing unusual on screen.",
        learnMore: "https://en.wikipedia.org/wiki/Iframe#Security",
    },
    Phishing_Keywords: {
        title: "Phishing Language",
        description: "Contains language commonly used in phishing attacks.",
        explanation: "The page contains phrases like 'verify your account' or 'update payment' that are hallmarks of phishing emails and websites. These social engineering tactics create a false sense of urgency to trick you into entering sensitive information like passwords, credit card numbers, or personal details on a fake form.",
        learnMore: "https://en.wikipedia.org/wiki/Phishing",
    },
    Executable_Header: {
        title: "Windows Executable",
        description: "This file is a Windows program (.exe).",
        explanation: "This file starts with 'MZ' — the signature of a Windows executable program. If you didn't expect to download a program, this is a major red flag. Executable files can do anything on your computer: install malware, steal data, encrypt your files for ransom, or add your machine to a botnet.",
        learnMore: "https://en.wikipedia.org/wiki/Portable_Executable",
    },
    "Suspicious Redirects": {
        title: "Suspicious Redirect",
        description: "Multiple redirect patterns detected in the code.",
        explanation: "We found 3 or more places in the code that try to move your browser to a different URL. While a single redirect can be normal (like after login), having many redirect commands scattered through the code suggests the site is part of a redirect chain — a common technique in phishing and malvertising campaigns.",
    },
    "Eval/Obfuscation": {
        title: "Code Obfuscation",
        description: "The site uses techniques to hide its code's purpose.",
        explanation: "Functions like eval(), unescape(), and document.write() are often used together to decode and run hidden code. Think of it like receiving a sealed envelope inside another sealed envelope — the code unpacks itself at runtime, making it impossible to see what it really does by just reading the source. This is the #1 technique used to hide malware in websites.",
        learnMore: "https://en.wikipedia.org/wiki/Obfuscation_(software)",
    },
};

/**
 * Get threat info for a rule, with smart fallback for unknown rules.
 * Auto-generates a title from the rule name (e.g., "Auto_Redirect" → "Auto Redirect").
 */
export function getThreatInfo(ruleName: string): ThreatDescription {
    if (THREAT_DESCRIPTIONS[ruleName]) {
        return THREAT_DESCRIPTIONS[ruleName];
    }
    // Auto-generate from rule name for unknown rules
    const autoTitle = ruleName
        .replace(/_/g, " ")
        .replace(/WEB /i, "")
        .replace(/ (Low|Medium|High)$/i, "")
        .replace(/\b\w/g, (c) => c.toUpperCase());
    return {
        title: autoTitle,
        description: `Detection rule "${ruleName}" was triggered.`,
        explanation: `Our scanner matched the pattern defined in the "${ruleName}" rule against the scanned content. This indicates potentially suspicious behavior that warrants further investigation. Expand the YARA Rule section below to see exactly what patterns were searched for.`,
    };
}
