"use client";

import { useEffect, useState } from "react";
import { Settings, Shield, Cpu, Database, CheckCircle2, XCircle, Info, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";

export default function SettingsPage() {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.getHealth().then((res) => {
      setHealth(res);
      setLoading(false);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
  }, []);

  return (
    <div className="p-8 max-w-4xl mx-auto w-full space-y-8">
      {error && <div role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error} <button className="underline" onClick={() => window.location.reload()}>Retry</button></div>}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">Platform Settings & Environment</h1>
        <p className="text-sm text-slate-500 mt-1">
          Review system health, database connections, Playwright browser engine, and optional AI inference configurations.
        </p>
      </div>

      {/* Services Health */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-4">
        <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
          <Database className="w-4 h-4 text-slate-600" />
          Service Status & Core Engine
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[11px]">Database (PostgreSQL 17)</span>
            <div className="flex items-center gap-1.5 mt-1">
              <Info className="w-4 h-4 text-slate-500" />
              <span className="font-semibold text-slate-900">
                {health?.services?.database === "connected" ? "Connected (Port 5433)" : loading ? "Checking..." : "Unavailable"}
              </span>
            </div>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[11px]">Browser Engine</span>
            <div className="flex items-center gap-1.5 mt-1">
              <Info className="w-4 h-4 text-slate-500" />
              <span className="font-semibold text-slate-900">Chrome preferred; Chromium fallback</span>
            </div>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[11px]">Backend API</span>
            <div className="flex items-center gap-1.5 mt-1">
              <Info className="w-4 h-4 text-slate-500" />
              <span className="font-semibold text-slate-900">{loading ? "Checking..." : health ? "Connected" : "Unavailable"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* AI Provider Configuration (DeepHat / OpenAI Compatible) */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-slate-600" />
              AI Inference Provider (DeepHat / OpenAI Compatible)
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              Optional secondary analysis using DeepHat-V1-7B, local vLLM/Ollama, or OpenAI-compatible endpoints.
            </p>
          </div>

          <span
            className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${
              health?.services?.aiProvider?.enabled
                ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                : "bg-slate-100 text-slate-600 border-slate-200"
            }`}
          >
            {health?.services?.aiProvider?.enabled ? "Configured (not connection-tested)" : "AI disabled; passive checks available"}
          </span>
        </div>

        <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3 text-xs">
          <div className="flex items-center gap-2 text-slate-700">
            <Info className="w-4 h-4 text-blue-500 shrink-0" />
            <span>
              Core passive security analysis runs deterministically and does <strong>not</strong> require an AI API key or GPU.
            </span>
          </div>

          <div className="pt-2 border-t border-slate-200/60 font-mono text-[11px] space-y-1.5 text-slate-600">
            <div>AI_ENABLED = <span className="font-bold">{String(health?.services?.aiProvider?.enabled)}</span></div>
            <div>AI_MODEL = <span className="font-bold">{health?.services?.aiProvider?.model || "deephat-v1-7b"}</span></div>
            <div>AI_BASE_URL = <span className="font-bold">{health?.services?.aiProvider?.baseUrl || "Not configured"}</span></div>
          </div>
        </div>

        <div className="border border-slate-200 rounded-lg p-4 text-xs space-y-2">
          <h4 className="font-semibold text-slate-900">How to connect DeepHat later:</h4>
          <ol className="list-decimal list-inside space-y-1 text-slate-600 text-xs">
            <li>Start your inference server (e.g. vLLM or Ollama with DeepHat-V1-7B on port 8000).</li>
            <li>In <code className="bg-slate-100 px-1 py-0.5 rounded font-mono">apps/server/.env</code>, set:</li>
          </ol>
          <pre className="bg-slate-900 text-slate-100 p-2.5 rounded font-mono text-[11px]">
AI_ENABLED=true
AI_BASE_URL=http://127.0.0.1:8000
AI_MODEL=deephat-v1-7b
AI_API_KEY=
          </pre>
          <p className="text-[11px] text-slate-500">
            The platform will automatically ingest hypotheses without modifying the browser recorder or dashboard.
          </p>
        </div>
      </div>

      {/* Redaction & Scope Architecture */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-3">
        <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
          <Shield className="w-4 h-4 text-slate-600" />
          Privacy & Redaction Policies
        </h2>

        <p className="text-xs text-slate-600 leading-relaxed">
          TraceHawk enforces strict zero-leakage security boundaries:
        </p>

        <ul className="list-disc list-inside text-xs text-slate-600 space-y-1">
          <li><strong>Authorization Header Masking:</strong> Bearer tokens and Basic auth credentials are redacted before persistence.</li>
          <li><strong>Storage Sanitization:</strong> JWT tokens and session secrets stored in cookies, localStorage, and sessionStorage are masked to preserve verifiable structure without exposing plaintext credentials.</li>
          <li><strong>Scope Isolation:</strong> Unrelated third-party response bodies are dropped to prevent recording extraneous traffic.</li>
          <li><strong>Local Binding:</strong> Express backend binds strictly to <code className="font-mono bg-slate-100 px-1 py-0.5 rounded">127.0.0.1:4000</code>.</li>
        </ul>
      </div>
    </div>
  );
}
