import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";

const DOCS_MAP: Record<string, string> = {
    simplified: "HOW-IT-WORKS-SIMPLIFIED.md",
    detailed: "HOW-IT-WORKS.md",
    whitepaper: "HOW-IT-WORKS-WHITEPAPER.md",
};

export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const doc = searchParams.get("doc");

    if (!doc || !DOCS_MAP[doc]) {
        return NextResponse.json(
            { error: "Invalid doc parameter. Use: simplified, detailed, or whitepaper" },
            { status: 400 }
        );
    }

    try {
        const filePath = path.join(process.cwd(), DOCS_MAP[doc]);
        const content = fs.readFileSync(filePath, "utf-8");
        return NextResponse.json({ content });
    } catch {
        return NextResponse.json(
            { error: "Documentation file not found" },
            { status: 404 }
        );
    }
}
