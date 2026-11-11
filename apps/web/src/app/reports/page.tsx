"use client";

import { useEffect, useState } from "react";
import { FileText, Download, Printer, ShieldCheck, Bug, Radio, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";
import { Session, Finding } from "@/types";
import { getSeverityBadge } from "@/lib/utils";

export default function ReportsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>("");
  const [session, setSession] = useState<Session | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.getProjects().then((data) => {
      const all: Session[] = [];
      for (const p of data.projects) {
        if (p.sessions) {
          for (const s of p.sessions) {
            all.push({ ...s, project: p });
          }
        }
      }
      all.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
      setSessions(all);
      if (all.length > 0) {
        setSelectedSessionId(all[0].id);
      }
      setLoading(false);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
  }, []);

  useEffect(() => {
    if (!selectedSessionId) return;
    api.getSession(selectedSessionId).then((res) => {
      setSession(res.session);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
    api.getFindings(selectedSessionId).then((res) => {
      setFindings(res.findings);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [selectedSessionId]);

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;
  const lowCount = findings.filter((f) => f.severity === "LOW").length;

  return (
    <div className="p-8 max-w-5xl mx-auto w-full space-y-8">
      {error && <div role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error} <button className="underline" onClick={() => window.location.reload()}>Retry</button></div>}
      {/* Top Header & Session Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-6 print:hidden">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Security Reports</h1>
          <p className="text-sm text-slate-500 mt-1">
            Export sanitized compliance summaries, HAR archives, and detailed vulnerability reports.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedSessionId}
            onChange={(e) => setSelectedSessionId(e.target.value)}
            className="px-3 py-2 text-xs font-medium border border-slate-300 rounded-lg bg-white text-slate-900"
          >
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {s.project?.name} ({new Date(s.startedAt).toLocaleDateString()})
              </option>
            ))}
          </select>

          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors"
          >
            <Printer className="w-4 h-4" />
            Print / PDF
          </button>
        </div>
      </div>

      {session && (
        <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-xs space-y-8">
          {/* Executive Header */}
          <div className="flex items-start justify-between border-b border-slate-200 pb-6">
            <div>
              <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                TraceHawk Security Audit Report
              </span>
              <h2 className="text-2xl font-bold text-slate-900 mt-1">
                {session.project?.name || "Application Inspection"}
              </h2>
              <p className="text-xs font-mono text-slate-500 mt-1">
                Target URL: {session.project?.targetUrl}
              </p>
            </div>

            <div className="text-right text-xs text-slate-500 space-y-1">
              <div>Session ID: <span className="font-mono text-slate-700">{session.id.substring(0, 8)}...</span></div>
              <div>Audit Date: {new Date(session.startedAt).toLocaleDateString()}</div>
              <div>Status: <span className="font-semibold text-slate-900">{session.status}</span></div>
            </div>
          </div>

          {/* Export Action Buttons */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 print:hidden">
            <a
              href={api.getExportUrl(session.id, "json")}
              download
              className="flex items-center justify-center gap-2 p-3 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors text-xs font-semibold text-slate-800"
            >
              <Download className="w-4 h-4 text-slate-500" />
              Download Findings JSON
            </a>
            <a
              href={api.getExportUrl(session.id, "traffic")}
              download
              className="flex items-center justify-center gap-2 p-3 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors text-xs font-semibold text-slate-800"
            >
              <Download className="w-4 h-4 text-slate-500" />
              Download Sanitized Traffic
            </a>
            <a
              href={api.getExportUrl(session.id, "har")}
              download
              className="flex items-center justify-center gap-2 p-3 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors text-xs font-semibold text-slate-800"
            >
              <Download className="w-4 h-4 text-slate-500" />
              Export Sanitized HAR
            </a>
          </div>

          {/* Executive Summary Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-center">
              <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Critical</span>
              <div className="text-2xl font-bold text-rose-600 mt-1">{criticalCount}</div>
            </div>
            <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-center">
              <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">High</span>
              <div className="text-2xl font-bold text-amber-600 mt-1">{highCount}</div>
            </div>
            <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-center">
              <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Medium</span>
              <div className="text-2xl font-bold text-yellow-600 mt-1">{mediumCount}</div>
            </div>
            <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-center">
              <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Low</span>
              <div className="text-2xl font-bold text-sky-600 mt-1">{lowCount}</div>
            </div>
          </div>

          {/* Detailed Findings List */}
          <div className="space-y-4">
            <h3 className="font-bold text-base text-slate-900 border-b border-slate-200 pb-2">
              Detailed Vulnerability Findings ({findings.length})
            </h3>

            {findings.length === 0 ? (
              <p className="text-sm text-slate-500 py-4">No security findings recorded for this session.</p>
            ) : (
              findings.map((f, i) => (
                <div key={f.id} className="p-4 rounded-lg border border-slate-200 space-y-2 bg-slate-50/50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-slate-400">#{i + 1}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                      {f.cweId && (
                        <span className="text-[11px] font-mono text-slate-500 bg-white border border-slate-200 px-1.5 py-0.5 rounded">
                          {f.cweId}
                        </span>
                      )}
                      <h4 className="font-semibold text-sm text-slate-900">{f.title}</h4>
                    </div>
                  </div>

                  <p className="text-xs text-slate-700 leading-relaxed">{f.description}</p>

                  <div className="pt-2 text-xs space-y-1">
                    <div>
                      <span className="font-semibold text-rose-900">Attacker Impact: </span>
                      <span className="text-slate-700">{f.impact}</span>
                    </div>
                    <div>
                      <span className="font-semibold text-emerald-900">Remediation: </span>
                      <span className="text-slate-700">{f.remediation}</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
