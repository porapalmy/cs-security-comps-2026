"use client";

import Navbar from "@/components/Navbar";
import { motion } from "framer-motion";

const ease = [0.22, 1, 0.36, 1] as const;

export default function SimulationPage() {
    return (
        <main className="min-h-screen flex flex-col items-center relative">
            {/* Background layers */}
            <div className="bg-mesh" />
            <div className="grid-overlay" />

            {/* Navbar */}
            <Navbar />

            {/* Content */}
            <motion.div
                className="z-10 w-full max-w-5xl mx-auto px-6 flex flex-col items-center justify-center flex-1 pt-20"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.7, ease }}
            >
                <h1
                    className="text-5xl md:text-7xl font-bold tracking-[-0.04em] leading-[0.9] text-center mb-4"
                    style={{ fontFamily: "var(--font-instrument), system-ui, sans-serif" }}
                >
                    <span className="text-gradient-white">Animated</span>
                    <br />
                    <span className="text-gradient-cyan">Simulator</span>
                    <span
                        className="inline-block w-[3px] h-[0.75em] ml-2 align-baseline"
                        style={{
                            background: "var(--cyan)",
                            animation: "typing-cursor 1s step-end infinite",
                            boxShadow: "0 0 12px var(--cyan-glow)",
                        }}
                    />
                </h1>

                <p
                    className="text-center max-w-lg mx-auto mb-8 leading-relaxed"
                    style={{
                        color: "var(--text-secondary)",
                        fontSize: "14px",
                        fontFamily: "var(--font-instrument), system-ui, sans-serif",
                    }}
                >
                    Coming soon — interactive visualization of the scan pipeline.
                </p>
            </motion.div>

            {/* Ambient orbs */}
            <div className="orb orb-cyan" style={{ top: "10%", right: "-5%", animationDelay: "0s" }} />
            <div className="orb orb-blue" style={{ bottom: "15%", left: "-8%", animationDelay: "-10s" }} />
        </main>
    );
}
