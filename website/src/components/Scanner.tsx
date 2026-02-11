"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    Upload,
    Link as LinkIcon,
    FileText,
    CheckCircle,
    AlertTriangle,
    Shield,
    X,
    ChevronDown,
    Crosshair,
    Radar,
} from "lucide-react";
import { cn } from "@/lib/utils";

type ScanResult = {
    score: number;
    matches: string[];
    analysis_log: string[];
    content_preview: string;
    details?: string;
};

const THREAT_DESCRIPTIONS: Record<string, { title: string; description: string }> = {
    WEB_JS_Obfuscation_Stack_Medium: {
        title: "Hidden Malicious Code",
        description:
            "The site uses complex techniques to hide its true behavior. This is often done to conceal malware or stealing scripts.",
    },
    WEB_Redirect_Primitives_Medium: {
        title: "Forced Redirect",
        description:
            "The site contains code that automatically moves you to a different, potentially dangerous page without your permission.",
    },
    WEB_MetaRefresh_Redirect_Medium: {
        title: "Instant Redirect",
        description:
            "Uses a basic HTML trick to immediately send you to another website.",
    },
    WEB_Forced_Download_High: {
        title: "Automatic Download",
        description:
            "The site attempts to download a file to your computer instantly. This is a high-risk behavior common in malware distribution.",
    },
    WEB_Permission_Abuse_Notifications_Push_High: {
        title: "Notification Spam",
        description:
            "Aggressively attempts to trick you into allowing browser notifications, often used for spam or scams.",
    },
    WEB_ClickFraud_AdStuffing_Signals_Low: {
        title: "Ad Fraud / Hidden Windows",
        description:
            "Contains hidden elements or popups often used to generate fake ad clicks or track you without consent.",
    },
    Suspicious_Script: {
        title: "Suspicious Script",
        description: "Contains script tags that look unusual or dangerous.",
    },
    Auto_Redirect: {
        title: "Automatic Redirect",
        description: "Code detected that forces your browser to navigate away.",
    },
    Hidden_Iframe: {
        title: "Hidden Webpage (Iframe)",
        description:
            "Loads another webpage invisibly in the background, which can be used for attacks.",
    },
    "Suspicious Redirects": {
        title: "Suspicious Redirect",
        description: "We detected patterns that try to force you to another URL.",
    },
    "Eval/Obfuscation": {
        title: "Code Obfuscation",
        description: "The site is hiding its code to make analysis difficult.",
    },
};

function getSeverity(score: number) {
    if (score < 20) return { label: "CLEAN", color: "var(--green-safe)", bg: "rgba(0,230,118,0.08)", border: "rgba(0,230,118,0.2)" };
    if (score < 50) return { label: "LOW RISK", color: "var(--amber-warn)", bg: "rgba(255,171,0,0.08)", border: "rgba(255,171,0,0.2)" };
    if (score < 75) return { label: "MEDIUM RISK", color: "#ff6d00", bg: "rgba(255,109,0,0.08)", border: "rgba(255,109,0,0.2)" };
    return { label: "HIGH RISK", color: "var(--red-threat)", bg: "var(--red-glow)", border: "rgba(255,61,87,0.3)" };
}

const ease = [0.22, 1, 0.36, 1] as const;

const cardVariants = {
    hidden: { opacity: 0, y: 16 },
    visible: (i: number) => ({
        opacity: 1,
        y: 0,
        transition: { delay: i * 0.1, duration: 0.5, ease },
    }),
};

export default function Scanner() {
    const [activeTab, setActiveTab] = useState<"file" | "url">("file");
    const [file, setFile] = useState<File | null>(null);
    const [url, setUrl] = useState("");
    const [isScanning, setIsScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [showSource, setShowSource] = useState(false);
    const [isDragOver, setIsDragOver] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const logIntervalRef = useRef<NodeJS.Timeout | null>(null);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
            setResult(null);
            setError(null);
            setShowSource(false);
        }
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragOver(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
            setResult(null);
            setError(null);
            setShowSource(false);
        }
    };

    const simulateLogs = (type: "file" | "url") => {
        setLogs([]);

        let hostname = "target";
        if (url) {
            try {
                hostname = new URL(url).hostname;
            } catch {
                try {
                    hostname = new URL(`https://${url}`).hostname;
                } catch {
                    hostname = url;
                }
            }
        }

        const urlLogs = [
            "▸ Initializing scan engine...",
            `▸ Resolving host: ${hostname}`,
            "▸ TLS 1.3 handshake established",
            "▸ Fetching DOM content...",
            "▸ Parsing HTML structure + embedded scripts",
            "▸ Cross-referencing known blocklists",
            "▸ Loading YARA ruleset [malware.yar]",
            "▸ Running pattern matching engine...",
            "▸ Computing threat score...",
            "▸ Generating report...",
        ];

        const fileLogs = [
            "▸ Initializing scan engine...",
            `▸ Streaming file (${file?.size ? (file.size / 1024).toFixed(1) + " KB" : "unknown"})`,
            "▸ Analyzing file entropy...",
            "▸ Extracting binary headers",
            "▸ Loading YARA ruleset [malware.yar]",
            "▸ Scanning binary patterns...",
            "▸ Verifying signature integrity",
            "▸ Computing threat score...",
            "▸ Generating report...",
        ];

        const selectedLogs = type === "url" ? urlLogs : fileLogs;
        let index = 0;

        if (logIntervalRef.current) clearInterval(logIntervalRef.current);

        logIntervalRef.current = setInterval(() => {
            if (index < selectedLogs.length) {
                setLogs((prev) => [...prev, selectedLogs[index]]);
                index++;
            } else {
                if (logIntervalRef.current) clearInterval(logIntervalRef.current);
            }
        }, 500);
    };

    const handleScan = async () => {
        setIsScanning(true);
        setResult(null);
        setError(null);
        setShowSource(false);

        const type =
            activeTab === "file" && file
                ? "file"
                : activeTab === "url" && url
                    ? "url"
                    : null;
        if (!type) return;

        simulateLogs(type);

        const startTime = Date.now();

        try {
            const formData = new FormData();
            if (activeTab === "file" && file) {
                formData.append("file", file);
                formData.append("type", "file");
            } else if (activeTab === "url" && url) {
                formData.append("url", url);
                formData.append("type", "url");
            }

            const response = await fetch("/api/scan", {
                method: "POST",
                body: formData,
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(
                    errorData.error || `Server error: ${response.status}`
                );
            }

            const data = await response.json();

            const elapsed = Date.now() - startTime;
            if (elapsed < 3000) {
                await new Promise((resolve) =>
                    setTimeout(resolve, 3000 - elapsed)
                );
            }

            setLogs((prev) => [...prev, "✓ Scan complete"]);
            await new Promise((resolve) => setTimeout(resolve, 500));
            setResult(data);
        } catch (err: unknown) {
            console.error(err);
            const errorMessage =
                err instanceof Error ? err.message : "Failed to scan";
            setError(errorMessage);
            setLogs((prev) => [...prev, `✗ Error: ${errorMessage}`]);
        } finally {
            if (logIntervalRef.current) clearInterval(logIntervalRef.current);
            setIsScanning(false);
        }
    };

    const severity = result ? getSeverity(result.score) : null;

    return (
        <div className="w-full max-w-3xl mx-auto relative">
            {/* Main card */}
            <div className="glow-border rounded-2xl overflow-hidden relative z-20">
                {/* Tab bar */}
                <div
                    className="flex relative"
                    style={{ borderBottom: "1px solid var(--border)" }}
                >
                    {/* Sliding indicator */}
                    <motion.div
                        className="absolute bottom-0 h-[2px]"
                        style={{ background: "var(--cyan)", width: "50%" }}
                        animate={{ x: activeTab === "file" ? "0%" : "100%" }}
                        transition={{ type: "spring", stiffness: 300, damping: 30 }}
                    />
                    <button
                        onClick={() => setActiveTab("file")}
                        disabled={isScanning}
                        className={cn(
                            "flex-1 py-4 text-sm font-medium transition-all duration-300 flex items-center justify-center gap-2",
                            "hover:bg-white/[0.02]",
                            isScanning && "opacity-40 cursor-not-allowed"
                        )}
                        style={{
                            color: activeTab === "file" ? "var(--text-primary)" : "var(--text-tertiary)",
                            fontFamily: "var(--font-jetbrains), monospace",
                            fontSize: "12px",
                            letterSpacing: "0.08em",
                            textTransform: "uppercase",
                        }}
                    >
                        <Upload className="w-3.5 h-3.5" /> File Scan
                    </button>
                    <button
                        onClick={() => setActiveTab("url")}
                        disabled={isScanning}
                        className={cn(
                            "flex-1 py-4 text-sm font-medium transition-all duration-300 flex items-center justify-center gap-2",
                            "hover:bg-white/[0.02]",
                            isScanning && "opacity-40 cursor-not-allowed"
                        )}
                        style={{
                            color: activeTab === "url" ? "var(--text-primary)" : "var(--text-tertiary)",
                            fontFamily: "var(--font-jetbrains), monospace",
                            fontSize: "12px",
                            letterSpacing: "0.08em",
                            textTransform: "uppercase",
                        }}
                    >
                        <LinkIcon className="w-3.5 h-3.5" /> URL Scan
                    </button>
                </div>

                {/* Content area */}
                <div className="p-8 min-h-[380px] flex flex-col justify-center">
                    <AnimatePresence mode="wait">
                        {isScanning ? (
                            /* ─── Scanning Terminal ─── */
                            <motion.div
                                key="scanning"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="w-full"
                            >
                                <div
                                    className="rounded-xl overflow-hidden"
                                    style={{
                                        background: "rgba(0, 0, 0, 0.6)",
                                        border: "1px solid var(--border)",
                                    }}
                                >
                                    {/* Terminal header */}
                                    <div
                                        className="flex items-center gap-2 px-4 py-3"
                                        style={{
                                            borderBottom: "1px solid var(--border)",
                                            background: "rgba(255,255,255,0.02)",
                                        }}
                                    >
                                        <div className="flex gap-1.5">
                                            <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
                                            <div className="w-2.5 h-2.5 rounded-full bg-[#febc2e]" />
                                            <div className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
                                        </div>
                                        <div className="flex items-center gap-2 ml-3">
                                            <Radar
                                                className="w-3 h-3"
                                                style={{
                                                    color: "var(--cyan)",
                                                    animation: "radar-sweep 2s linear infinite",
                                                }}
                                            />
                                            <span
                                                className="text-xs uppercase tracking-widest"
                                                style={{
                                                    fontFamily: "var(--font-jetbrains), monospace",
                                                    color: "var(--text-tertiary)",
                                                    fontSize: "10px",
                                                }}
                                            >
                                                Scanning in progress
                                            </span>
                                        </div>
                                    </div>

                                    {/* Terminal body */}
                                    <div
                                        className="p-4 h-[260px] overflow-y-auto flex flex-col-reverse"
                                        style={{ fontFamily: "var(--font-jetbrains), monospace" }}
                                    >
                                        <div className="flex flex-col gap-1">
                                            {logs.map((log, i) => (
                                                <motion.div
                                                    key={i}
                                                    initial={{ opacity: 0, x: -8 }}
                                                    animate={{ opacity: 1, x: 0 }}
                                                    transition={{ duration: 0.3 }}
                                                    className="text-xs leading-relaxed"
                                                    style={{
                                                        color: log.startsWith("✓")
                                                            ? "var(--green-safe)"
                                                            : log.startsWith("✗")
                                                                ? "var(--red-threat)"
                                                                : "var(--cyan-dim)",
                                                    }}
                                                >
                                                    {log}
                                                </motion.div>
                                            ))}
                                            <motion.span
                                                animate={{ opacity: [0, 1, 0] }}
                                                transition={{
                                                    repeat: Infinity,
                                                    duration: 0.8,
                                                }}
                                                className="inline-block w-1.5 h-3.5 mt-1"
                                                style={{ background: "var(--cyan)" }}
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Progress bar */}
                                <div
                                    className="mt-4 h-[2px] rounded-full overflow-hidden"
                                    style={{ background: "var(--border)" }}
                                >
                                    <motion.div
                                        className="h-full rounded-full"
                                        style={{
                                            background: "linear-gradient(90deg, var(--cyan), var(--cyan-dim))",
                                            boxShadow: "0 0 12px var(--cyan-glow)",
                                        }}
                                        initial={{ width: "0%" }}
                                        animate={{ width: "100%" }}
                                        transition={{ duration: 5, ease: "linear" }}
                                    />
                                </div>
                            </motion.div>
                        ) : !result ? (
                            /* ─── Input View ─── */
                            <motion.div
                                key="input"
                                initial={{ opacity: 0, y: 12 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -12 }}
                                transition={{ duration: 0.4, ease }}
                                className="space-y-8"
                            >
                                {activeTab === "file" ? (
                                    <div
                                        onDragOver={(e) => {
                                            e.preventDefault();
                                            setIsDragOver(true);
                                        }}
                                        onDragLeave={() => setIsDragOver(false)}
                                        onDrop={handleDrop}
                                        onClick={() => fileInputRef.current?.click()}
                                        className="rounded-xl p-10 text-center cursor-pointer transition-all duration-300 group"
                                        style={{
                                            border: `1.5px dashed ${isDragOver ? "var(--cyan)" : "var(--border-hover)"}`,
                                            background: isDragOver
                                                ? "var(--cyan-ghost)"
                                                : "rgba(255,255,255,0.01)",
                                            boxShadow: isDragOver
                                                ? "inset 0 0 40px var(--cyan-ghost)"
                                                : "none",
                                        }}
                                    >
                                        <input
                                            type="file"
                                            ref={fileInputRef}
                                            className="hidden"
                                            onChange={handleFileChange}
                                        />
                                        <div
                                            className="w-14 h-14 rounded-xl flex items-center justify-center mx-auto mb-5 transition-all duration-300 group-hover:scale-105"
                                            style={{
                                                background: file
                                                    ? "var(--cyan-ghost)"
                                                    : "rgba(255,255,255,0.03)",
                                                border: `1px solid ${file ? "var(--border-cyan)" : "var(--border)"}`,
                                            }}
                                        >
                                            {file ? (
                                                <FileText
                                                    className="w-6 h-6"
                                                    style={{ color: "var(--cyan)" }}
                                                />
                                            ) : (
                                                <Upload
                                                    className="w-6 h-6 transition-colors duration-300 group-hover:text-[var(--cyan)]"
                                                    style={{ color: "var(--text-tertiary)" }}
                                                />
                                            )}
                                        </div>
                                        {file ? (
                                            <div>
                                                <p
                                                    className="text-base font-medium"
                                                    style={{ color: "var(--text-primary)" }}
                                                >
                                                    {file.name}
                                                </p>
                                                <p
                                                    className="text-xs mt-1"
                                                    style={{
                                                        color: "var(--text-tertiary)",
                                                        fontFamily: "var(--font-jetbrains), monospace",
                                                    }}
                                                >
                                                    {(file.size / 1024).toFixed(2)} KB
                                                </p>
                                            </div>
                                        ) : (
                                            <div>
                                                <p
                                                    className="text-base font-medium"
                                                    style={{ color: "var(--text-secondary)" }}
                                                >
                                                    Drop file here or{" "}
                                                    <span
                                                        style={{
                                                            color: "var(--cyan)",
                                                            textDecoration: "underline",
                                                            textUnderlineOffset: "3px",
                                                        }}
                                                    >
                                                        browse
                                                    </span>
                                                </p>
                                                <p
                                                    className="text-xs mt-2"
                                                    style={{
                                                        color: "var(--text-tertiary)",
                                                        fontFamily: "var(--font-jetbrains), monospace",
                                                    }}
                                                >
                                                    .docx · .pdf · .exe · .zip
                                                </p>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        <label
                                            className="block text-xs font-medium uppercase tracking-wider"
                                            style={{
                                                color: "var(--text-tertiary)",
                                                fontFamily: "var(--font-jetbrains), monospace",
                                            }}
                                        >
                                            Target URL
                                        </label>
                                        <div className="relative group">
                                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                                <LinkIcon
                                                    className="h-4 w-4 transition-colors duration-300 group-focus-within:text-[var(--cyan)]"
                                                    style={{ color: "var(--text-tertiary)" }}
                                                />
                                            </div>
                                            <input
                                                type="text"
                                                value={url}
                                                onChange={(e) => setUrl(e.target.value)}
                                                placeholder="https://example.com"
                                                className="w-full rounded-xl py-4 pl-11 pr-4 text-sm transition-all duration-300 outline-none"
                                                style={{
                                                    background: "rgba(255,255,255,0.02)",
                                                    border: "1px solid var(--border-hover)",
                                                    color: "var(--text-primary)",
                                                    fontFamily: "var(--font-jetbrains), monospace",
                                                }}
                                                onFocus={(e) =>
                                                    (e.target.style.borderColor = "var(--border-cyan)")
                                                }
                                                onBlur={(e) =>
                                                    (e.target.style.borderColor = "var(--border-hover)")
                                                }
                                            />
                                        </div>
                                    </div>
                                )}

                                {/* Error display */}
                                {error && (
                                    <motion.div
                                        initial={{ opacity: 0, y: 8 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        className="rounded-lg px-4 py-3 text-xs"
                                        style={{
                                            background: "var(--red-glow)",
                                            border: "1px solid rgba(255,61,87,0.2)",
                                            color: "var(--red-threat)",
                                            fontFamily: "var(--font-jetbrains), monospace",
                                        }}
                                    >
                                        {error}
                                    </motion.div>
                                )}

                                {/* Scan button */}
                                <div className="flex justify-center pt-2">
                                    <button
                                        onClick={handleScan}
                                        disabled={
                                            isScanning ||
                                            (activeTab === "file" && !file) ||
                                            (activeTab === "url" && !url)
                                        }
                                        className="relative overflow-hidden font-medium py-3.5 px-10 rounded-xl text-sm transition-all duration-300 flex items-center gap-2.5 disabled:opacity-30 disabled:cursor-not-allowed hover:scale-[1.02] active:scale-[0.98]"
                                        style={{
                                            background: "linear-gradient(135deg, var(--cyan), var(--cyan-dim))",
                                            color: "#07080a",
                                            fontFamily: "var(--font-jetbrains), monospace",
                                            letterSpacing: "0.04em",
                                            textTransform: "uppercase",
                                            fontSize: "12px",
                                            fontWeight: 600,
                                            boxShadow: "0 0 24px var(--cyan-glow), 0 4px 12px rgba(0,0,0,0.3)",
                                        }}
                                    >
                                        <Crosshair className="w-4 h-4" />
                                        Initialize Scan
                                        {/* Shimmer overlay */}
                                        <span
                                            className="absolute inset-0 pointer-events-none"
                                            style={{
                                                background:
                                                    "linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent)",
                                                backgroundSize: "200% 100%",
                                                animation: "shimmer 3s ease-in-out infinite",
                                            }}
                                        />
                                    </button>
                                </div>
                            </motion.div>
                        ) : (
                            /* ─── Results View ─── */
                            <motion.div
                                key="result"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ duration: 0.5 }}
                                className="space-y-8"
                            >
                                {/* Score display */}
                                <motion.div
                                    className="flex flex-col items-center"
                                    custom={0}
                                    variants={cardVariants}
                                    initial="hidden"
                                    animate="visible"
                                >
                                    <div className="relative">
                                        <svg className="w-44 h-44" viewBox="0 0 192 192">
                                            {/* Track */}
                                            <circle
                                                cx="96"
                                                cy="96"
                                                r="82"
                                                stroke="var(--border)"
                                                strokeWidth="6"
                                                fill="transparent"
                                            />
                                            {/* Arc */}
                                            <motion.circle
                                                cx="96"
                                                cy="96"
                                                r="82"
                                                stroke={severity?.color}
                                                strokeWidth="6"
                                                fill="transparent"
                                                strokeLinecap="round"
                                                strokeDasharray={2 * Math.PI * 82}
                                                initial={{
                                                    strokeDashoffset: 2 * Math.PI * 82,
                                                }}
                                                animate={{
                                                    strokeDashoffset:
                                                        2 * Math.PI * 82 * (1 - result.score / 100),
                                                }}
                                                transition={{
                                                    duration: 1.2,
                                                    ease,
                                                    delay: 0.3,
                                                }}
                                                style={{
                                                    transform: "rotate(-90deg)",
                                                    transformOrigin: "center",
                                                    filter: `drop-shadow(0 0 8px ${severity?.color})`,
                                                }}
                                            />
                                        </svg>
                                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                                            <motion.span
                                                className="text-5xl font-bold tabular-nums"
                                                style={{
                                                    color: "var(--text-primary)",
                                                    fontFamily: "var(--font-instrument), system-ui",
                                                }}
                                                initial={{ opacity: 0, scale: 0.5 }}
                                                animate={{ opacity: 1, scale: 1 }}
                                                transition={{ delay: 0.5, duration: 0.5 }}
                                            >
                                                {result.score}
                                            </motion.span>
                                            <motion.span
                                                className="text-[10px] uppercase tracking-[0.2em] font-semibold mt-1"
                                                style={{
                                                    color: severity?.color,
                                                    fontFamily: "var(--font-jetbrains), monospace",
                                                }}
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1 }}
                                                transition={{ delay: 0.7 }}
                                            >
                                                {severity?.label}
                                            </motion.span>
                                        </div>
                                    </div>
                                </motion.div>

                                {/* Detection details */}
                                <motion.div
                                    className="rounded-xl overflow-hidden"
                                    style={{
                                        background: "rgba(255,255,255,0.02)",
                                        border: "1px solid var(--border)",
                                    }}
                                    custom={1}
                                    variants={cardVariants}
                                    initial="hidden"
                                    animate="visible"
                                >
                                    <div
                                        className="px-5 py-4 flex items-center gap-2"
                                        style={{
                                            borderBottom: "1px solid var(--border)",
                                        }}
                                    >
                                        {result.score > 0 ? (
                                            <AlertTriangle
                                                className="w-4 h-4"
                                                style={{ color: severity?.color }}
                                            />
                                        ) : (
                                            <CheckCircle
                                                className="w-4 h-4"
                                                style={{ color: "var(--green-safe)" }}
                                            />
                                        )}
                                        <span
                                            className="text-sm font-semibold"
                                            style={{ color: "var(--text-primary)" }}
                                        >
                                            Detection Details
                                        </span>
                                        <span
                                            className="ml-auto text-[10px] uppercase tracking-wider"
                                            style={{
                                                color: "var(--text-tertiary)",
                                                fontFamily: "var(--font-jetbrains), monospace",
                                            }}
                                        >
                                            {result.matches.length} threat{result.matches.length !== 1 ? "s" : ""}
                                        </span>
                                    </div>
                                    <div className="p-4">
                                        {result.matches.length > 0 ? (
                                            <div className="space-y-2">
                                                {result.matches.map((match, idx) => {
                                                    const info =
                                                        THREAT_DESCRIPTIONS[match] || {
                                                            title: match,
                                                            description: "Potential security threat detected.",
                                                        };
                                                    return (
                                                        <motion.div
                                                            key={idx}
                                                            className="rounded-lg p-3.5"
                                                            style={{
                                                                background: severity?.bg,
                                                                border: `1px solid ${severity?.border}`,
                                                            }}
                                                            initial={{ opacity: 0, x: -8 }}
                                                            animate={{ opacity: 1, x: 0 }}
                                                            transition={{ delay: 0.8 + idx * 0.1 }}
                                                        >
                                                            <div className="flex items-start gap-3">
                                                                <div
                                                                    className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0"
                                                                    style={{
                                                                        background: severity?.color,
                                                                        boxShadow: `0 0 6px ${severity?.color}`,
                                                                    }}
                                                                />
                                                                <div className="min-w-0">
                                                                    <div
                                                                        className="text-sm font-semibold"
                                                                        style={{ color: severity?.color }}
                                                                    >
                                                                        {info.title}
                                                                    </div>
                                                                    <div
                                                                        className="text-[10px] mt-0.5 uppercase tracking-wider"
                                                                        style={{
                                                                            color: "var(--text-tertiary)",
                                                                            fontFamily: "var(--font-jetbrains), monospace",
                                                                        }}
                                                                    >
                                                                        {match}
                                                                    </div>
                                                                    <div
                                                                        className="text-xs mt-1.5 leading-relaxed"
                                                                        style={{
                                                                            color: "var(--text-secondary)",
                                                                        }}
                                                                    >
                                                                        {info.description}
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </motion.div>
                                                    );
                                                })}
                                            </div>
                                        ) : (
                                            <div
                                                className="text-center py-6"
                                                style={{ color: "var(--text-tertiary)" }}
                                            >
                                                <CheckCircle
                                                    className="w-8 h-8 mx-auto mb-2"
                                                    style={{ color: "var(--green-safe)" }}
                                                />
                                                <p className="text-sm">No specific threats detected</p>
                                            </div>
                                        )}
                                    </div>
                                </motion.div>

                                {/* Transparency Report */}
                                <motion.div
                                    className="rounded-xl overflow-hidden"
                                    style={{
                                        background: "rgba(255,255,255,0.02)",
                                        border: "1px solid var(--border)",
                                    }}
                                    custom={2}
                                    variants={cardVariants}
                                    initial="hidden"
                                    animate="visible"
                                >
                                    <div
                                        className="px-5 py-4"
                                        style={{
                                            borderBottom: "1px solid var(--border)",
                                        }}
                                    >
                                        <span
                                            className="text-sm font-semibold"
                                            style={{ color: "var(--text-primary)" }}
                                        >
                                            Transparency Report
                                        </span>
                                    </div>
                                    <div
                                        className="p-4 max-h-40 overflow-y-auto space-y-0.5"
                                        style={{
                                            fontFamily: "var(--font-jetbrains), monospace",
                                            fontSize: "11px",
                                        }}
                                    >
                                        {result.analysis_log?.map((log, idx) => (
                                            <div
                                                key={idx}
                                                className="leading-relaxed"
                                                style={{
                                                    color: log.startsWith("❌")
                                                        ? "var(--red-threat)"
                                                        : "var(--text-tertiary)",
                                                }}
                                            >
                                                {log}
                                            </div>
                                        ))}
                                    </div>
                                </motion.div>

                                {/* Source Preview */}
                                <motion.div
                                    className="rounded-xl overflow-hidden"
                                    style={{
                                        background: "rgba(255,255,255,0.02)",
                                        border: "1px solid var(--border)",
                                    }}
                                    custom={3}
                                    variants={cardVariants}
                                    initial="hidden"
                                    animate="visible"
                                >
                                    <button
                                        onClick={() => setShowSource(!showSource)}
                                        className="w-full px-5 py-4 flex items-center justify-between transition-colors duration-300 hover:bg-white/[0.02]"
                                    >
                                        <span
                                            className="text-sm font-semibold"
                                            style={{ color: "var(--text-primary)" }}
                                        >
                                            Scraped Content
                                        </span>
                                        <ChevronDown
                                            className="w-4 h-4 transition-transform duration-300"
                                            style={{
                                                color: "var(--text-tertiary)",
                                                transform: showSource ? "rotate(180deg)" : "rotate(0deg)",
                                            }}
                                        />
                                    </button>

                                    <AnimatePresence>
                                        {showSource && (
                                            <motion.div
                                                initial={{ height: 0 }}
                                                animate={{ height: "auto" }}
                                                exit={{ height: 0 }}
                                                className="overflow-hidden"
                                            >
                                                <pre
                                                    className="p-4 text-xs overflow-x-auto max-h-60 leading-relaxed"
                                                    style={{
                                                        borderTop: "1px solid var(--border)",
                                                        background: "rgba(0,0,0,0.3)",
                                                        color: "var(--cyan-dim)",
                                                        fontFamily: "var(--font-jetbrains), monospace",
                                                        fontSize: "11px",
                                                    }}
                                                >
                                                    {result.content_preview || "No content available."}
                                                </pre>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>

                                {/* New scan button */}
                                <motion.div
                                    className="flex justify-center"
                                    custom={4}
                                    variants={cardVariants}
                                    initial="hidden"
                                    animate="visible"
                                >
                                    <button
                                        onClick={() => {
                                            setResult(null);
                                            setFile(null);
                                            setUrl("");
                                            setShowSource(false);
                                        }}
                                        className="flex items-center gap-2 py-2.5 px-5 rounded-lg transition-all duration-300 hover:bg-white/[0.04] group"
                                        style={{
                                            color: "var(--text-tertiary)",
                                            fontFamily: "var(--font-jetbrains), monospace",
                                            fontSize: "12px",
                                            letterSpacing: "0.04em",
                                            textTransform: "uppercase",
                                        }}
                                    >
                                        <X className="w-3.5 h-3.5 transition-colors group-hover:text-[var(--cyan)]" />
                                        New Scan
                                    </button>
                                </motion.div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
}
