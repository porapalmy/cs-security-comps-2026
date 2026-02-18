"use client";

import Scanner from "@/components/Scanner";
import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";

const ease = [0.22, 1, 0.36, 1] as const;

const stagger = {
    hidden: {},
    visible: {
        transition: { staggerChildren: 0.12, delayChildren: 0.2 },
    },
};

const fadeUp = {
    hidden: { opacity: 0, y: 20 },
    visible: {
        opacity: 1,
        y: 0,
        transition: { duration: 0.7, ease },
    },
};

const fadeIn = {
    hidden: { opacity: 0 },
    visible: {
        opacity: 1,
        transition: { duration: 1, ease: "easeOut" as const },
    },
};

export default function Home() {
    const [isAboutOpen, setIsAboutOpen] = useState(false);
    return (
        <main className="min-h-screen flex flex-col items-center relative">
            {/* Background layers */}
            <div className="bg-mesh" />
            <div className="grid-overlay" />

            {/* Content */}
            <motion.div
                className="z-10 w-full max-w-5xl mx-auto px-6 flex flex-col items-center justify-center flex-1"
                variants={stagger}
                initial="hidden"
                animate="visible"
            >
                {/* Status badges */}
                <motion.div
                    className="flex flex-wrap items-center justify-center gap-3 mb-6"
                    variants={fadeUp}
                >
                    <div className="status-badge">
                        <span className="dot dot-cyan" />
                        Powered with YARA
                    </div>
                    {/* <div className="status-badge">
                        <span className="dot dot-green" />
                        something
                    </div> */}
                </motion.div>

                {/* Headline */}
                <motion.div
                    className="text-center mb-3"
                    variants={fadeUp}
                >
                    <h1 className="text-5xl md:text-7xl font-bold tracking-[-0.04em] leading-[0.9]"
                        style={{ fontFamily: "var(--font-instrument), system-ui, sans-serif" }}
                    >
                        <span className="text-gradient-white">Malware</span>
                        <br />
                        <span className="text-gradient-cyan">Scanner</span>
                        <span
                            className="inline-block w-[3px] h-[0.75em] ml-2 align-baseline"
                            style={{
                                background: "var(--cyan)",
                                animation: "typing-cursor 1s step-end infinite",
                                boxShadow: "0 0 12px var(--cyan-glow)",
                            }}
                        />
                    </h1>
                </motion.div>

                {/* Subtitle */}
                <motion.p
                    className="text-center max-w-lg mx-auto mb-8 leading-relaxed"
                    style={{
                        color: "var(--text-secondary)",
                        fontSize: "14px",
                        fontFamily: "var(--font-instrument), system-ui, sans-serif",
                    }}
                    variants={fadeUp}
                >
                    via YARA.
                </motion.p>

                {/* Scanner */}
                <motion.div className="w-full max-w-3xl" variants={fadeUp}>
                    <Scanner />
                </motion.div>
            </motion.div>

            {/* Footer — pinned to bottom */}
            <motion.footer
                className="z-10 pb-5 pt-3 flex flex-col items-center gap-1.5 shrink-0"
                variants={fadeIn}
                initial="hidden"
                animate="visible"
            >
                <div
                    className="flex items-center gap-2 text-[10px] tracking-widest uppercase"
                    style={{
                        fontFamily: "var(--font-jetbrains), monospace",
                        color: "var(--text-tertiary)",
                    }}
                >
                    {/* <span
                        className="inline-block w-4 h-[1px]"
                        style={{ background: "var(--text-tertiary)" }}
                    />
                    2026 CS Security Comps
                    <span
                        className="inline-block w-4 h-[1px]"
                        style={{ background: "var(--text-tertiary)" }}
                    /> */}

                    {/* About Button */}
                    <button
                        onClick={() => setIsAboutOpen(true)}
                        className="ml-2 hover:text-[var(--cyan)] transition-colors cursor-pointer"
                        style={{ fontFamily: "var(--font-jetbrains), monospace" }}
                    >
                        [ABOUT]
                    </button>
                </div>
            </motion.footer>

            {/* About Modal */}
            <AnimatePresence>
                {isAboutOpen && (
                    <>
                        {/* Backdrop */}
                        <motion.div
                            className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-sm"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            onClick={() => setIsAboutOpen(false)}
                        />
                        {/* Modal Content */}
                        <motion.div
                            className="fixed top-1/2 left-1/2 z-[101] w-full max-w-md p-6 rounded-xl border border-[var(--border)] bg-[#0A0A0A] shadow-2xl overflow-hidden"
                            style={{ x: "-50%", y: "-50%" }}
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                        >
                            <div className="absolute inset-0 bg-mesh opacity-20 pointer-events-none" />
                            <div className="relative z-10 text-center">
                                <h3 className="text-2xl font-bold mb-4 text-[var(--cyan)]" style={{ fontFamily: "var(--font-instrument)" }}>
                                    Carleton College Security Comps 2026
                                </h3>
                                <p className="text-[var(--text-secondary)] mb-6 leading-relaxed" style={{ fontFamily: "var(--font-jetbrains)" }}>
                                    Made by <br /> <span className="text-[var(--text-primary)]">Palmy, Rachel, Daniel, Jeremy</span>
                                    <br />
                                    Supervised by Jeff Onidch.
                                </p>
                                <button
                                    onClick={() => setIsAboutOpen(false)}
                                    className="px-6 py-2 rounded-lg bg-[var(--cyan-dim)] text-[var(--cyan)] border border-[var(--cyan-dim)] hover:bg-[var(--cyan)] hover:text-black transition-all font-medium text-sm"
                                    style={{ fontFamily: "var(--font-jetbrains)" }}
                                >
                                    Close
                                </button>
                            </div>
                        </motion.div>
                    </>
                )}
            </AnimatePresence>

            {/* Ambient orbs */}
            <div className="orb orb-cyan" style={{ top: "10%", right: "-5%", animationDelay: "0s" }} />
            <div className="orb orb-blue" style={{ bottom: "15%", left: "-8%", animationDelay: "-10s" }} />
        </main>
    );
}
