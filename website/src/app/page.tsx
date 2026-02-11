"use client";

import Scanner from "@/components/Scanner";
import { motion } from "framer-motion";

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
                    <span
                        className="inline-block w-4 h-[1px]"
                        style={{ background: "var(--text-tertiary)" }}
                    />
                    Jeff Ondich&apos;s 2026 CS Security Comps
                    <span
                        className="inline-block w-4 h-[1px]"
                        style={{ background: "var(--text-tertiary)" }}
                    />
                </div>
            </motion.footer>

            {/* Ambient orbs */}
            <div className="orb orb-cyan" style={{ top: "10%", right: "-5%", animationDelay: "0s" }} />
            <div className="orb orb-blue" style={{ bottom: "15%", left: "-8%", animationDelay: "-10s" }} />
        </main>
    );
}
