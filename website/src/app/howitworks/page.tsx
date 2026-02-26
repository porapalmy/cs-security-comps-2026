"use client";

import Navbar from "@/components/Navbar";
import { motion } from "framer-motion";
import { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const ease = [0.22, 1, 0.36, 1] as const;

type DocId = "simplified" | "detailed" | "whitepaper";

const DOC_TABS: { id: DocId; label: string; file: string }[] = [
    { id: "simplified", label: "Simplified", file: "HOW-IT-WORKS-SIMPLIFIED.md" },
    { id: "detailed", label: "Deep Dive", file: "HOW-IT-WORKS.md" },
    { id: "whitepaper", label: "Whitepaper", file: "HOW-IT-WORKS-WHITEPAPER.md" },
];

export default function HowItWorksPage() {
    const [activeDoc, setActiveDoc] = useState<DocId>("simplified");
    const [content, setContent] = useState("");
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        setIsLoading(true);
        fetch(`/api/docs?doc=${activeDoc}`)
            .then((r) => r.json())
            .then((data) => {
                setContent(data.content || "Failed to load content.");
                setIsLoading(false);
            })
            .catch(() => {
                setContent("Error loading documentation.");
                setIsLoading(false);
            });
    }, [activeDoc]);

    return (
        <main className="min-h-screen flex flex-col relative">
            {/* Background layers */}
            <div className="bg-mesh" />
            <div className="grid-overlay" />

            {/* Navbar */}
            <Navbar />

            {/* Content */}
            <motion.div
                className="z-10 w-full max-w-5xl mx-auto px-6 flex flex-col flex-1 pt-20"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.7, ease }}
            >
                {/* Page heading */}
                <div className="text-center mb-8">
                    <h1
                        className="text-4xl md:text-5xl font-bold tracking-[-0.04em] leading-[0.9] mb-3"
                        style={{ fontFamily: "var(--font-instrument), system-ui, sans-serif" }}
                    >
                        <span className="text-gradient-white">How It</span>{" "}
                        <span className="text-gradient-cyan">Works</span>
                    </h1>
                </div>

                {/* Tab switcher */}
                <div className="flex items-center justify-center gap-1 mb-8">
                    {DOC_TABS.map((tab) => {
                        const isActive = activeDoc === tab.id;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => setActiveDoc(tab.id)}
                                className="relative px-5 py-2 rounded-lg text-[11px] tracking-widest uppercase transition-colors duration-200 cursor-pointer"
                                style={{
                                    fontFamily: "var(--font-jetbrains), monospace",
                                    color: isActive ? "var(--cyan)" : "var(--text-tertiary)",
                                    background: isActive ? "var(--cyan-ghost)" : "transparent",
                                    border: isActive
                                        ? "1px solid var(--border-cyan)"
                                        : "1px solid transparent",
                                }}
                            >
                                {tab.label}
                            </button>
                        );
                    })}
                </div>

                {/* Markdown content */}
                <div
                    className="flex-1 rounded-xl border p-8 lg:p-12 mb-8 overflow-auto"
                    style={{
                        background: "var(--bg-card)",
                        borderColor: "var(--border)",
                    }}
                >
                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div
                                className="w-5 h-5 border-2 rounded-full animate-spin"
                                style={{
                                    borderColor: "var(--border)",
                                    borderTopColor: "var(--cyan)",
                                }}
                            />
                            <span
                                className="ml-3 text-sm"
                                style={{
                                    color: "var(--text-secondary)",
                                    fontFamily: "var(--font-jetbrains)",
                                }}
                            >
                                Loading docs...
                            </span>
                        </div>
                    ) : (
                        <div className="docs-prose max-w-4xl mx-auto">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                {content}
                            </ReactMarkdown>
                        </div>
                    )}
                </div>
            </motion.div>

            {/* Ambient orbs */}
            <div className="orb orb-cyan" style={{ top: "10%", right: "-5%", animationDelay: "0s" }} />
            <div className="orb orb-blue" style={{ bottom: "15%", left: "-8%", animationDelay: "-10s" }} />
        </main>
    );
}
