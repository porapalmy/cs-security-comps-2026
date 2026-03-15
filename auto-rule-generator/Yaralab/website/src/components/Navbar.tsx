"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";

const NAV_ITEMS = [
    { label: "Scanner", href: "/" },
    { label: "Animated Simulator", href: "/simulator" },
    { label: "How It Works", href: "/howitworks" },
];

export default function Navbar() {
    const pathname = usePathname();

    return (
        <motion.nav
            className="fixed top-0 left-0 right-0 z-50 flex items-center justify-center py-3 px-6"
            style={{
                background: "rgba(7, 8, 10, 0.6)",
                backdropFilter: "blur(16px)",
                WebkitBackdropFilter: "blur(16px)",
                borderBottom: "1px solid var(--border)",
            }}
            initial={{ y: -60, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        >
            <div className="flex items-center gap-1">
                {NAV_ITEMS.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            className="relative px-4 py-1.5 rounded-md text-[11px] tracking-widest uppercase transition-colors duration-200"
                            style={{
                                fontFamily: "var(--font-jetbrains), monospace",
                                color: isActive
                                    ? "var(--cyan)"
                                    : "var(--text-tertiary)",
                            }}
                        >
                            {isActive && (
                                <motion.span
                                    className="absolute inset-0 rounded-md"
                                    style={{
                                        background: "var(--cyan-ghost)",
                                        border: "1px solid var(--border-cyan)",
                                    }}
                                    layoutId="navbar-active"
                                    transition={{
                                        type: "spring",
                                        stiffness: 380,
                                        damping: 30,
                                    }}
                                />
                            )}
                            <span className="relative z-10 hover:text-[var(--cyan)] transition-colors">
                                {item.label}
                            </span>
                        </Link>
                    );
                })}
            </div>
        </motion.nav>
    );
}
