import Scanner from "@/components/Scanner";

export default function Home() {
    return (
        <main className="min-h-screen flex flex-col items-center justify-center p-4 md:p-24 relative overflow-hidden">
            {/* Background blobs */}
            <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl -z-10 animate-pulse" />
            <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-indigo-500/20 rounded-full blur-3xl -z-10 animate-pulse delay-1000" />

            <div className="z-10 w-full max-w-5xl items-center justify-between font-mono text-sm lg:flex mb-12 flex-col gap-4">
                <h1 className="text-4xl md:text-6xl font-bold bg-clip-text text-transparent bg-gradient-to-b from-white to-gray-400 text-center">
                    Malware Scanner
                </h1>
                <p className="text-gray-400 text-center max-w-2xl text-lg">
                    Advanced static analysis using YARA rules. Detect threats in files and URLs instantly.
                </p>
            </div>

            <Scanner />

            <footer className="absolute bottom-4 text-gray-500 text-xs">
                Powered by YARA & Next.js
            </footer>
        </main>
    );
}
