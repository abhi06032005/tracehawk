"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Radio, Play, Trash2, ArrowRight, Clock, Network, Bug } from "lucide-react";
import { api } from "@/lib/api";
import { Project, Session } from "@/types";
import { getStatusBadge } from "@/lib/utils";

export default function SessionsListPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadSessions = async () => {
    try {
      const data = await api.getProjects();
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
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this session?")) return;
    try {
      await api.deleteSession(id);
      await loadSessions();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto w-full space-y-6">
      {error && <div role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error} <button className="underline" onClick={() => window.location.reload()}>Retry</button></div>}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">Recorded Sessions</h1>
        <p className="text-sm text-slate-500 mt-1">
          Historical browser inspection sessions, network traces, and vulnerability analysis runs.
        </p>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs divide-y divide-slate-100">
        {sessions.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <Radio className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <h3 className="font-semibold text-slate-900">No Recorded Sessions Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
              Go to Projects, select a target application and click &quot;Launch Browser & Record&quot;.
            </p>
            <Link
              href="/projects"
              className="inline-block mt-4 px-4 py-2 bg-slate-900 text-white text-xs font-medium rounded-lg hover:bg-slate-800"
            >
              Go to Projects
            </Link>
          </div>
        ) : (
          sessions.map((s) => (
            <div
              key={s.id}
              className="p-5 flex items-center justify-between hover:bg-slate-50/80 transition-colors"
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2.5">
                  <span className="font-semibold text-base text-slate-900">
                    {s.project?.name || "Target App"}
                  </span>
                  <span
                    className={`text-xs px-2.5 py-0.5 rounded-full border font-semibold ${getStatusBadge(
                      s.status
                    )}`}
                  >
                    {s.status}
                  </span>
                </div>

                <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
                  <span>{s.project?.targetUrl}</span>
                  <span>•</span>
                  <span>{s.totalRequests} HTTP exchanges</span>
                  <span>•</span>
                  <span>{s.totalErrors} errors</span>
                  <span>•</span>
                  <span>Started {new Date(s.startedAt).toLocaleString()}</span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Link
                  href={`/sessions/${s.id}`}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 hover:border-slate-300 transition-colors shadow-2xs"
                >
                  Open Session
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>

                <button
                  onClick={() => handleDelete(s.id)}
                  className="p-1.5 text-slate-400 hover:text-rose-600 rounded-lg hover:bg-rose-50 transition-colors"
                  title="Delete session"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
