"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Bug, ShieldAlert, Filter, Search, ArrowRight, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { Finding, Session } from "@/types";
import { getSeverityBadge } from "@/lib/utils";

export default function FindingsPage() {
  const [findings, setFindings] = useState<(Finding & { session?: Session })[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const loadAllFindings = async () => {
    try {
      const data = await api.getProjects();
      const all: (Finding & { session?: Session })[] = [];

      for (const p of data.projects) {
        if (p.sessions) {
          for (const s of p.sessions) {
            try {
              const fData = await api.getFindings(s.id);
              for (const f of fData.findings) {
                all.push({ ...f, session: { ...s, project: p } });
              }
            } catch { setError("Some session findings could not be loaded."); }
          }
        }
      }
      setFindings(all);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllFindings();
  }, []);

  const filtered = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (categoryFilter !== "ALL" && f.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      {error && <div role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error} <button className="underline" onClick={() => window.location.reload()}>Retry</button></div>}
      <div className="bg-white border-b border-slate-200 px-8 py-5 shrink-0">
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">Security Findings</h1>
        <p className="text-sm text-slate-500 mt-1">
          Evidence-linked passive security vulnerabilities and configuration anomalies detected across recorded sessions.
        </p>

        {/* Filter Toolbar */}
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-medium">Severity:</span>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded-md font-semibold text-xs transition-colors ${
                  severityFilter === sev
                    ? "bg-slate-900 text-white"
                    : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5 text-xs ml-4">
            <span className="text-slate-400 font-medium">Category:</span>
            {["ALL", "HEADERS", "COOKIES", "STORAGE", "CORS", "ERROR_LEAK"].map((cat) => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2.5 py-1 rounded-md font-medium text-xs transition-colors ${
                  categoryFilter === cat
                    ? "bg-slate-900 text-white"
                    : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="ml-auto text-xs text-slate-500">
            {filtered.length} matching observations
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        <div className="flex-1 overflow-y-auto p-8 space-y-3">
          {filtered.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-xl p-12 text-center text-slate-500">
              <Bug className="w-10 h-10 text-slate-300 mx-auto mb-2" />
              <h3 className="font-semibold text-slate-900">No Security Findings</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                No observations match your current filter. Record a session with your target and click &quot;Analyze Session&quot;.
              </p>
            </div>
          ) : (
            filtered.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              return (
                <div
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`bg-white border rounded-xl p-4 cursor-pointer transition-all ${
                    isSelected
                      ? "border-slate-900 ring-1 ring-slate-900 shadow-sm"
                      : "border-slate-200 hover:border-slate-300"
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${getSeverityBadge(
                            f.severity
                          )}`}
                        >
                          {f.severity}
                        </span>
                        {f.cweId && (
                          <span className="text-[11px] font-mono text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                            {f.cweId}
                          </span>
                        )}
                        <span className="font-semibold text-sm text-slate-900">{f.title}</span>
                      </div>
                      <p className="text-xs text-slate-600 line-clamp-2 mt-1">{f.description}</p>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-[11px] font-mono text-slate-400 block">
                        {f.session?.project?.name}
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {f.verificationStatus}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Finding Detail Sidebar */}
        {selectedFinding && (
          <div className="w-[520px] border-l border-slate-200 bg-white flex flex-col h-full overflow-hidden shadow-lg shrink-0">
            <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
              <div>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${getSeverityBadge(
                    selectedFinding.severity
                  )}`}
                >
                  {selectedFinding.severity}
                </span>
                <h3 className="font-bold text-sm text-slate-900 mt-1">{selectedFinding.title}</h3>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-slate-700 font-bold p-1"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1">
                  What Was Observed
                </h4>
                <p className="text-slate-700 leading-relaxed bg-slate-50 p-3 rounded-lg border border-slate-200">
                  {selectedFinding.description}
                </p>
              </div>

              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1">
                  Evidence
                </h4>
                <pre className="bg-slate-900 text-slate-100 p-3 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedFinding.evidence, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1">
                  Possible Attacker Impact
                </h4>
                <p className="text-rose-900 bg-rose-50/70 p-3 rounded-lg border border-rose-200 leading-relaxed">
                  {selectedFinding.impact}
                </p>
              </div>

              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1">
                  Recommended Remediation
                </h4>
                <p className="text-emerald-900 bg-emerald-50/70 p-3 rounded-lg border border-emerald-200 leading-relaxed">
                  {selectedFinding.remediation}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
