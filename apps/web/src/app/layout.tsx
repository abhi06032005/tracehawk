import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "TraceHawk — Local Browser Security Inspection Platform",
  description: "Record, inspect, and analyze local browser sessions for security vulnerabilities passively and transparently.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex h-screen overflow-hidden bg-slate-50 text-slate-900" suppressHydrationWarning>
        <Sidebar />
        <main className="min-w-0 flex-1 flex flex-col h-screen overflow-y-auto bg-slate-50">
          {children}
        </main>
      </body>
    </html>
  );
}
