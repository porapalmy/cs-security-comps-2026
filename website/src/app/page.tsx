import Scanner from "@/components/Scanner";

export default function Home() {
    return (
        <main className="min-h-screen flex flex-col items-center justify-center p-4 md:p-24 relative">
            <div className="scanline" />
            {/* Vignette effect */}
            <div className="absolute inset-0 bg-radial-gradient from-transparent to-slate-950 pointer-events-none" />

            <div className="z-10 w-full max-w-5xl items-center justify-between font-mono text-sm lg:flex mb-16 flex-col gap-6">
                <div className="flex flex-col items-center gap-2">
                    {/* <div className="text-emerald-500/50 text-xs tracking-[0.2em] uppercase">pre-beta</div> */}
                    <h1 className="text-4xl md:text-7xl font-bold text-white tracking-tighter">
                        <span className="text-emerald-500 mr-4">&gt;</span>
                        YARA_MALWARE_SCANNER
                        <span className="animate-pulse text-emerald-500">_</span>
                    </h1>
                </div>
                
            </div>

            <Scanner />

            <footer className="absolute bottom-6 text-slate-600 text-xs font-mono uppercase tracking-widest">
                Made for Jeff Ondich's 2026 CS Security Comps
            </footer>
        </main>
    );
}
