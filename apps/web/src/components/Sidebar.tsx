"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import {
  ShieldAlert,
  LayoutDashboard,
  FolderGit2,
  Radio,
  Network,
  Bug,
  Sparkles,
  FileText,
  Settings,
  Activity,
  Bot,
  TerminalSquare,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { label: "Pentest Copilot", href: "/copilot", icon: Bot },
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Projects", href: "/projects", icon: FolderGit2 },
  { label: "Sessions", href: "/sessions", icon: Radio },
  { label: "Network Traffic", href: "/traffic", icon: Network },
  { label: "Security Findings", href: "/findings", icon: Bug },
  { label: "DeepHat AI Audit", href: "/audit", icon: Sparkles },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [status, setStatus] = useState('Checking recorder');
  useEffect(() => {
    let disposed = false;
    const check = () => api.getHealth().then(h => { if (!disposed) setStatus(h.services.database === 'connected' ? 'Recorder connected' : 'Database unavailable'); }).catch(() => { if (!disposed) setStatus('Recorder offline'); });
    void check(); const timer = setInterval(check, 10000);
    return () => { disposed = true; clearInterval(timer); };
  }, []);

  return (
    <aside className="w-16 lg:w-60 border-r border-slate-200 bg-white flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-3 lg:px-5 border-b border-slate-200 gap-3">
        <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-sm">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
        </div>
        <div className="hidden lg:block">
          <span className="font-semibold text-slate-900 tracking-tight text-base">TraceHawk</span>
          <span className="block text-[11px] text-slate-500 font-mono">v1.0 • Local Inspector</span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="hidden lg:block px-3 mb-2 text-[11px] font-semibold tracking-wider text-slate-600 uppercase">
          Navigation
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              title={item.label}
              className={cn(
                "flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors",
                isActive
                  ? "bg-slate-100 text-slate-900 font-semibold"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              )}
            >
              <Icon
                className={cn(
                  "w-4 h-4",
                  isActive ? "text-slate-900" : "text-slate-400"
                )}
              />
              <span className="hidden lg:inline">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Engine Status Footer */}
      <div className="hidden lg:block p-4 border-t border-slate-200 bg-slate-50/50">
        <div className="flex items-center justify-between text-xs text-slate-600">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${status === 'Recorder connected' ? 'bg-emerald-500' : 'bg-amber-500'}`} />
            <span className="font-medium text-slate-700">{status}</span>
          </div>
        </div>
        <p className="text-[11px] text-slate-600 mt-1">
          <Link href="/#record" className="text-indigo-700 underline">Open Chrome & Record</Link>
        </p>
      </div>
    </aside>
  );
}
