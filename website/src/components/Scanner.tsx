"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Upload, Link as LinkIcon, FileText, CheckCircle, AlertTriangle, Shield, Loader2, X } from "lucide-react";
import { cn } from "@/lib/utils";

type ScanResult = {
    score: number;
    matches: string[];
    details?: string;
};

export default function Scanner() {
    const [activeTab, setActiveTab] = useState<"file" | "url">("file");
    const [file, setFile] = useState<File | null>(null);
    const [url, setUrl] = useState("");
    const [isScanning, setIsScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const logIntervalRef = useRef<NodeJS.Timeout | null>(null);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
            setResult(null);
            setError(null);
        }
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
            setResult(null);
            setError(null);
        }
    };

    const simulateLogs = (type: "file" | "url") => {
        setLogs([]);

        let hostname = 'target';
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
            "Initializing visual engine...",
            `Resolving host: ${hostname}...`,
            "Handshaking (TLS 1.3)...",
            "Fetching DOM content...",
            "Parsing HTML and scripts...",
            "Checking against known blocklists...",
            "Running YARA pattern matching...",
            "Calculating threat score...",
            "Finalizing report..."
        ];

        const fileLogs = [
            "Uploading file stream...",
            `Analyzing file entropy (${file?.size ? (file.size / 1024).toFixed(1) + 'KB' : 'unknown'})...`,
            "Extracting headers...",
            "Loading YARA ruleset (malware.yar)...",
            "Scanning binary patterns...",
            "Verifying signature integrity...",
            "Compiling risk assessment...",
            "Finalizing report..."
        ];

        const selectedLogs = type === 'url' ? urlLogs : fileLogs;
        let index = 0;

        // Clear existing interval if any
        if (logIntervalRef.current) clearInterval(logIntervalRef.current);

        logIntervalRef.current = setInterval(() => {
            if (index < selectedLogs.length) {
                setLogs(prev => [...prev, selectedLogs[index]]);
                index++;
            } else {
                if (logIntervalRef.current) clearInterval(logIntervalRef.current);
            }
        }, 600); // Add a new log every 600ms
    };

    const handleScan = async () => {
        setIsScanning(true);
        setResult(null);
        setError(null);

        const type = activeTab === 'file' && file ? 'file' : (activeTab === 'url' && url ? 'url' : null);
        if (!type) return;

        simulateLogs(type);

        // Minimum scan time to show some logs
        const startTime = Date.now();

        try {
            const formData = new FormData();
            if (activeTab === 'file' && file) {
                formData.append('file', file);
                formData.append('type', 'file');
            }
            else if (activeTab === 'url' && url) {
                formData.append('url', url);
                formData.append('type', 'url');
            }

            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Server error: ${response.status}`);
            }

            const data = await response.json();

            // Ensure we show logs for at least a few seconds
            const elapsed = Date.now() - startTime;
            if (elapsed < 3000) {
                await new Promise(resolve => setTimeout(resolve, 3000 - elapsed));
            }

            // Complete the logs
            setLogs(prev => [...prev, "Scan complete."]);

            // Small delay to let the user see "Scan complete"
            await new Promise(resolve => setTimeout(resolve, 500));

            setResult(data);

        } catch (err: any) {
            console.error(err);
            setError(err.message || "Failed to scan. Please try again.");
            setLogs(prev => [...prev, `Error: ${err.message || "Failed to scan"}`]);
        } finally {
            if (logIntervalRef.current) clearInterval(logIntervalRef.current);
            setIsScanning(false);
        }
    };

    return (
        <div className="w-full max-w-3xl mx-auto p-6">
            <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-3xl overflow-hidden shadow-2xl">
                <div className="flex border-b border-white/10">
                    <button
                        onClick={() => setActiveTab("file")}
                        disabled={isScanning}
                        className={cn(
                            "flex-1 py-4 text-sm font-medium transition-colors flex items-center justify-center gap-2",
                            activeTab === "file" ? "bg-white/10 text-white" : "text-gray-400 hover:text-white hover:bg-white/5",
                            isScanning && "opacity-50 cursor-not-allowed"
                        )}
                    >
                        <Upload className="w-4 h-4" /> File Scan
                    </button>
                    <button
                        onClick={() => setActiveTab("url")}
                        disabled={isScanning}
                        className={cn(
                            "flex-1 py-4 text-sm font-medium transition-colors flex items-center justify-center gap-2",
                            activeTab === "url" ? "bg-white/10 text-white" : "text-gray-400 hover:text-white hover:bg-white/5",
                            isScanning && "opacity-50 cursor-not-allowed"
                        )}
                    >
                        <LinkIcon className="w-4 h-4" /> URL Scan
                    </button>
                </div>

                <div className="p-8 min-h-[400px] flex flex-col justify-center">
                    <AnimatePresence mode="wait">
                        {isScanning ? (
                            <motion.div
                                key="scanning"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="w-full h-full bg-black/80 rounded-xl p-6 font-mono text-sm overflow-hidden border border-white/10 shadow-inner"
                            >
                                <div className="flex items-center gap-2 mb-4 border-b border-white/10 pb-2">
                                    <div className="w-3 h-3 rounded-full bg-red-500" />
                                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                                    <div className="w-3 h-3 rounded-full bg-green-500" />
                                    <span className="ml-2 text-xs text-gray-500">Security Terminal</span>
                                </div>
                                <div className="space-y-2 h-[250px] overflow-y-auto flex flex-col-reverse">
                                    {/* Using flex-col-reverse to keep bottom pinned */}
                                    <div className="flex flex-col gap-1">
                                        {logs.map((log, i) => (
                                            <motion.div
                                                key={i}
                                                initial={{ opacity: 0, x: -10 }}
                                                animate={{ opacity: 1, x: 0 }}
                                                className="text-green-400"
                                            >
                                                <span className="text-gray-600 mr-2">$</span>
                                                {log}
                                            </motion.div>
                                        ))}
                                        <motion.div
                                            animate={{ opacity: [0, 1, 0] }}
                                            transition={{ repeat: Infinity, duration: 0.8 }}
                                            className="w-2 h-4 bg-green-500 ml-2"
                                        />
                                    </div>
                                </div>
                            </motion.div>
                        ) : !result ? (
                            <motion.div
                                key="input"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="space-y-8"
                            >
                                {activeTab === "file" ? (
                                    <div
                                        onDragOver={(e) => e.preventDefault()}
                                        onDrop={handleDrop}
                                        onClick={() => fileInputRef.current?.click()}
                                        className="border-2 border-dashed border-white/20 rounded-2xl p-12 text-center cursor-pointer hover:border-blue-500/50 hover:bg-white/5 transition-all group"
                                    >
                                        <input
                                            type="file"
                                            ref={fileInputRef}
                                            className="hidden"
                                            onChange={handleFileChange}
                                        />
                                        <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform">
                                            {file ? <FileText className="w-8 h-8 text-blue-400" /> : <Upload className="w-8 h-8 text-gray-400 group-hover:text-blue-400" />}
                                        </div>
                                        {file ? (
                                            <div>
                                                <p className="text-lg font-medium text-white">{file.name}</p>
                                                <p className="text-sm text-gray-400">{(file.size / 1024).toFixed(2)} KB</p>
                                            </div>
                                        ) : (
                                            <div>
                                                <p className="text-lg font-medium text-white">Drop your file here or click to browse</p>
                                                <p className="text-sm text-gray-400 mt-2">Supports .docx, .pdf, .exe, .zip</p>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="space-y-4">
                                        <label className="block text-sm font-medium text-gray-300">Enter Website URL</label>
                                        <div className="relative">
                                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                                <LinkIcon className="h-5 w-5 text-gray-500" />
                                            </div>
                                            <input
                                                type="text"
                                                value={url}
                                                onChange={(e) => setUrl(e.target.value)}
                                                placeholder="https://example.com"
                                                className="w-full bg-white/5 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all shadow-inner"
                                            />
                                        </div>
                                    </div>
                                )}

                                <div className="flex justify-center pt-4">
                                    <button
                                        onClick={handleScan}
                                        disabled={isScanning || (activeTab === 'file' && !file) || (activeTab === 'url' && !url)}
                                        className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium py-4 px-12 rounded-full shadow-lg shadow-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:scale-105 active:scale-95 flex items-center gap-2"
                                    >
                                        <Shield className="w-5 h-5" /> Start Scan
                                    </button>
                                </div>
                            </motion.div>
                        ) : (
                            <motion.div
                                key="result"
                                initial={{ opacity: 0, scale: 0.95 }}
                                animate={{ opacity: 1, scale: 1 }}
                                className="text-center space-y-8"
                            >
                                <div className="relative inline-block">
                                    <svg className="w-48 h-48 transform -rotate-90">
                                        <circle
                                            cx="96"
                                            cy="96"
                                            r="88"
                                            stroke="currentColor"
                                            strokeWidth="12"
                                            fill="transparent"
                                            className="text-white/10"
                                        />
                                        <circle
                                            cx="96"
                                            cy="96"
                                            r="88"
                                            stroke="currentColor"
                                            strokeWidth="12"
                                            fill="transparent"
                                            strokeDasharray={2 * Math.PI * 88}
                                            strokeDashoffset={2 * Math.PI * 88 * (1 - result.score / 100)}
                                            className={cn(
                                                "transition-all duration-1000 ease-out",
                                                result.score < 30 ? "text-green-500" : result.score < 70 ? "text-yellow-500" : "text-red-500"
                                            )}
                                        />
                                    </svg>
                                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                                        <span className="text-5xl font-bold text-white">{result.score}</span>
                                        <span className="text-sm text-gray-400 uppercase tracking-wider">Risk Score</span>
                                    </div>
                                </div>

                                <div className="bg-white/5 rounded-2xl p-6 text-left border border-white/10">
                                    <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                                        {result.score > 0 ? <AlertTriangle className="text-yellow-500" /> : <CheckCircle className="text-green-500" />}
                                        Detection Details
                                    </h3>
                                    {result.matches.length > 0 ? (
                                        <ul className="space-y-2">
                                            {result.matches.map((match, idx) => (
                                                <li key={idx} className="flex items-start gap-2 text-red-300 bg-red-500/10 p-2 rounded">
                                                    <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-red-400 block shrink-0"></span>
                                                    {match}
                                                </li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <p className="text-gray-400">No threats detected.</p>
                                    )}
                                </div>

                                <button
                                    onClick={() => { setResult(null); setFile(null); setUrl(""); }}
                                    className="text-gray-400 hover:text-white transition-colors flex items-center gap-2 mx-auto"
                                >
                                    <X className="w-4 h-4" /> Start New Scan
                                </button>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
}
