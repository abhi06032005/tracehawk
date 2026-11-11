"use client";

import React, { useState } from "react";
import { X, Play, Shield, Globe, Terminal, Sparkles, CheckCircle2 } from "lucide-react";

interface NewMissionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLaunch: (data: {
    targetUrl: string;
    name?: string;
    mode: "autonomous" | "quick" | "api" | "recon";
    activeTests: boolean;
    maxSteps: number;
  }) => Promise<void>;
  busy: boolean;
}

export function NewMissionModal({ isOpen, onClose, onLaunch, busy }: NewMissionModalProps) {
  const [targetUrl, setTargetUrl] = useState("https://abhijeetnayak.vercel.app");
  const [name, setName] = useState("");
  const [mode, setMode] = useState<"autonomous" | "quick" | "api" | "recon">("autonomous");
  const [activeTests, setActiveTests] = useState(false);
  const [maxSteps, setMaxSteps] = useState(15);
  const [error, setError] = useState("");

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      new URL(targetUrl);
    } catch {
      setError("Please enter a valid HTTP or HTTPS target URL");
      return;
    }

    try {
      await onLaunch({
        targetUrl,
        name: name.trim() || undefined,
        mode,
        activeTests,
        maxSteps,
      });
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to launch copilot mission");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-xl rounded-2xl border border-slate-700 bg-slate-900 p-6 text-slate-100 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600/20 text-indigo-400">
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight text-white">New Pentest Mission</h2>
              <p className="text-xs text-slate-400">Autonomous black-box security assessment with AI Copilot</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          {/* Target URL */}
          <div>
            <label className="block text-xs font-medium text-slate-300">
              Target Web Application URL <span className="text-rose-400">*</span>
            </label>
            <div className="relative mt-1">
              <Globe className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="url"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full rounded-xl border border-slate-700 bg-slate-800/80 py-2.5 pl-9 pr-3 text-sm text-white placeholder-slate-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              />
            </div>
            <p className="mt-1 text-[11px] text-slate-500">
              Crawler will map endpoints and explore pages within this host origin.
            </p>
          </div>

          {/* Assessment Mode */}
          <div>
            <label className="block text-xs font-medium text-slate-300">Assessment Mode</label>
            <div className="mt-1.5 grid grid-cols-2 gap-2">
              {[
                {
                  id: "autonomous",
                  title: "Autonomous Full Pentest",
                  desc: "Comprehensive crawl, ZAP/Nuclei scanning & multi-turn exploit loop",
                },
                {
                  id: "quick",
                  title: "Quick Surface Audit",
                  desc: "Rapid top-level endpoint mapping & passive header/CORS checks",
                },
                {
                  id: "api",
                  title: "API Vulnerability Test",
                  desc: "Focus on JSON endpoints, parameter schemas & auth tokens",
                },
                {
                  id: "recon",
                  title: "Recon & Fingerprint",
                  desc: "Tech stack discovery & server response classification",
                },
              ].map((m) => (
                <button
                  type="button"
                  key={m.id}
                  onClick={() => setMode(m.id as any)}
                  className={`flex flex-col rounded-xl border p-3 text-left transition ${
                    mode === m.id
                      ? "border-indigo-500 bg-indigo-500/10 text-white"
                      : "border-slate-800 bg-slate-800/40 text-slate-400 hover:border-slate-700 hover:bg-slate-800"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold">{m.title}</span>
                    {mode === m.id && <CheckCircle2 className="h-3.5 w-3.5 text-indigo-400" />}
                  </div>
                  <span className="mt-1 text-[10px] text-slate-400">{m.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Probing Options */}
          <div className="rounded-xl border border-slate-800 bg-slate-800/40 p-3.5">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-medium text-slate-200">Active Exploit Probing</span>
                <p className="text-[11px] text-slate-400">
                  Allows bounded non-destructive probes (rate-limit checks, parameter reflection).
                </p>
              </div>
              <input
                type="checkbox"
                checked={activeTests}
                onChange={(e) => setActiveTests(e.target.checked)}
                className="h-4 w-4 rounded border-slate-700 bg-slate-800 text-indigo-600 focus:ring-indigo-500"
              />
            </div>
          </div>

          {/* Max Turns */}
          <div className="flex items-center justify-between border-t border-slate-800 pt-3 text-xs text-slate-400">
            <span>Model Reasoning Budget:</span>
            <select
              value={maxSteps}
              onChange={(e) => setMaxSteps(Number(e.target.value))}
              className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-slate-200 outline-none"
            >
              <option value={10}>10 Turns (Fast)</option>
              <option value={15}>15 Turns (Recommended)</option>
              <option value={20}>20 Turns (Deep)</option>
            </select>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-2 border-t border-slate-800 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={busy}
              className="rounded-xl border border-slate-700 bg-transparent px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2 text-xs font-medium text-white shadow-lg shadow-indigo-600/30 transition hover:bg-indigo-500 disabled:opacity-50"
            >
              {busy ? (
                <>Launching Mission...</>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-current" />
                  Launch Copilot Mission
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

