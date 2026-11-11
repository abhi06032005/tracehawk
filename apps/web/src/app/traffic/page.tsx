"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { Network, Search, Filter, RefreshCw, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { Session, HttpExchange } from "@/types";
import { formatDuration } from "@/lib/utils";

export default function TrafficPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>("");
  const [traffic, setTraffic] = useState<HttpExchange[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedExchange, setSelectedExchange] = useState<HttpExchange | null>(null);

  // Filters
  const [filterType, setFilterType] = useState<string>("ALL");
  const [searchUrl, setSearchUrl] = useState<string>("");
  const [filterStatus, setFilterStatus] = useState<string>("ALL");

  useEffect(() => {
    api.getProjects().then((data) => {
      const allSessions: Session[] = [];
      for (const p of data.projects) {
        if (p.sessions) {
          for (const s of p.sessions) {
            allSessions.push({ ...s, project: p });
          }
        }
      }
      allSessions.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
      setSessions(allSessions);
      if (allSessions.length > 0) {
        setSelectedSessionId(allSessions[0].id);
      }
      setLoading(false);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
  }, []);

  useEffect(() => {
    if (!selectedSessionId) return;
    api.getTraffic(selectedSessionId, { limit: 500 }).then((res) => {
      setTraffic(res.exchanges);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [selectedSessionId]);

  const filteredTraffic = useMemo(() => {
    return traffic.filter((item) => {
      if (filterType !== "ALL") {
        if (filterType === "XHR" && item.resourceType !== "fetch" && item.resourceType !== "xhr") return false;
        if (filterType === "DOC" && item.resourceType !== "document") return false;
        if (filterType === "JS" && item.resourceType !== "script") return false;
        if (filterType === "WS" && item.resourceType !== "websocket") return false;
      }
      if (filterStatus === "FAILED") {
        if (!item.statusCode || item.statusCode < 400) return false;
      }
      if (searchUrl.trim()) {
        if (!item.url.toLowerCase().includes(searchUrl.toLowerCase())) return false;
      }
      return true;
    });
  }, [traffic, filterType, filterStatus, searchUrl]);

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">Network Traffic Inspector</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Real captured HTTP requests, responses, sanitized bodies and timing information.
          </p>
        </div>

        {/* Session Selector */}
        <div className="flex items-center gap-2">
          <label className="text-xs font-medium text-slate-500">Inspection Session:</label>
          <select
            value={selectedSessionId}
            onChange={(e) => setSelectedSessionId(e.target.value)}
            className="px-3 py-1.5 text-xs font-medium border border-slate-200 rounded-lg bg-white text-slate-900 focus:outline-hidden focus:border-slate-900"
          >
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {s.project?.name || "Session"} • {new Date(s.startedAt).toLocaleTimeString()} ({s.totalRequests} reqs)
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="p-3 bg-white border-b border-slate-200 flex items-center gap-3 shrink-0">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search URL or path..."
            value={searchUrl}
            onChange={(e) => setSearchUrl(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-200 rounded-md font-mono focus:outline-hidden focus:border-slate-900"
          />
        </div>

        <div className="flex items-center gap-1 text-xs">
          {["ALL", "XHR", "DOC", "JS", "WS"].map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-2.5 py-1 rounded-md font-medium text-xs transition-colors ${
                filterType === type ? "bg-slate-900 text-white" : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              {type}
            </button>
          ))}

          <button
            onClick={() => setFilterStatus(filterStatus === "FAILED" ? "ALL" : "FAILED")}
            className={`ml-2 px-2.5 py-1 rounded-md font-medium text-xs transition-colors ${
              filterStatus === "FAILED"
                ? "bg-rose-100 text-rose-700 font-bold border border-rose-300"
                : "text-slate-600 hover:bg-slate-100"
            }`}
          >
            Failed Only
          </button>
        </div>

        <div className="ml-auto text-xs text-slate-400 font-mono">
          {filteredTraffic.length} / {traffic.length} requests
        </div>
      </div>

      {/* Table & Inspector Split */}
      <div className="flex-1 flex overflow-hidden">
        <div className="flex-1 overflow-y-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-medium sticky top-0 z-10 select-none">
              <tr>
                <th className="py-2.5 px-4 w-20">Method</th>
                <th className="py-2.5 px-4">URL / Path</th>
                <th className="py-2.5 px-4 w-20">Status</th>
                <th className="py-2.5 px-4 w-24">Type</th>
                <th className="py-2.5 px-4 w-20">Duration</th>
                <th className="py-2.5 px-4 w-28">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {filteredTraffic.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400 font-sans">
                    No requests captured for this session yet.
                  </td>
                </tr>
              ) : (
                filteredTraffic.map((ex) => {
                  const isSelected = selectedExchange?.id === ex.id;
                  const isError = ex.statusCode && ex.statusCode >= 400;

                  return (
                    <tr
                      key={ex.id}
                      onClick={() => setSelectedExchange(ex)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? "bg-blue-50/80 font-medium" : "hover:bg-slate-50"
                      } ${isError ? "text-rose-700 bg-rose-50/30" : "text-slate-800"}`}
                    >
                      <td className="py-2 px-4 font-bold">{ex.method}</td>
                      <td className="py-2 px-4 truncate max-w-md" title={ex.url}>
                        {ex.url}
                      </td>
                      <td className="py-2 px-4">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[11px] font-semibold ${
                            !ex.statusCode
                              ? "bg-slate-100 text-slate-500"
                              : ex.statusCode >= 500
                              ? "bg-rose-100 text-rose-700"
                              : ex.statusCode >= 400
                              ? "bg-amber-100 text-amber-700"
                              : "bg-emerald-50 text-emerald-700"
                          }`}
                        >
                          {ex.statusCode || "FAIL"}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-slate-500 font-sans text-[11px]">
                        {ex.resourceType || "other"}
                      </td>
                      <td className="py-2 px-4 text-slate-500">{formatDuration(ex.duration)}</td>
                      <td className="py-2 px-4 text-slate-400 font-sans text-[11px]">
                        {new Date(ex.timestamp).toLocaleTimeString()}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Request Slide-over */}
        {selectedExchange && (
          <div className="w-[500px] border-l border-slate-200 bg-white flex flex-col h-full overflow-hidden shadow-lg shrink-0">
            <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
              <div className="truncate">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-xs bg-slate-900 text-white px-1.5 py-0.5 rounded">
                    {selectedExchange.method}
                  </span>
                  <span className="font-mono text-xs font-semibold text-slate-900">
                    {selectedExchange.statusCode || "Failed"}
                  </span>
                </div>
                <p className="text-[11px] font-mono text-slate-500 truncate mt-1">
                  {selectedExchange.url}
                </p>
              </div>
              <button
                onClick={() => setSelectedExchange(null)}
                className="text-slate-400 hover:text-slate-700 font-bold p-1"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1.5">
                  General Info
                </h4>
                <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono space-y-1">
                  <div>
                    <span className="text-slate-400">URL:</span> {selectedExchange.url}
                  </div>
                  <div>
                    <span className="text-slate-400">Method:</span> {selectedExchange.method}
                  </div>
                  <div>
                    <span className="text-slate-400">Status:</span>{" "}
                    {selectedExchange.statusCode || selectedExchange.failureReason || "N/A"}
                  </div>
                  <div>
                    <span className="text-slate-400">Duration:</span>{" "}
                    {formatDuration(selectedExchange.duration)}
                  </div>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1.5">
                  Request Headers (Sanitized)
                </h4>
                <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono overflow-x-auto max-h-40">
                  {selectedExchange.requestHeaders &&
                  Object.keys(selectedExchange.requestHeaders).length > 0 ? (
                    Object.entries(selectedExchange.requestHeaders).map(([k, v]) => (
                      <div key={k} className="truncate">
                        <span className="text-slate-500">{k}:</span>{" "}
                        <span className="text-slate-900">
                          {Array.isArray(v) ? v.join(", ") : String(v)}
                        </span>
                      </div>
                    ))
                  ) : (
                    <span className="text-slate-400">None</span>
                  )}
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1.5">
                  Response Headers (Sanitized)
                </h4>
                <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono overflow-x-auto max-h-40">
                  {selectedExchange.responseHeaders &&
                  Object.keys(selectedExchange.responseHeaders).length > 0 ? (
                    Object.entries(selectedExchange.responseHeaders).map(([k, v]) => (
                      <div key={k} className="truncate">
                        <span className="text-slate-500">{k}:</span>{" "}
                        <span className="text-slate-900">
                          {Array.isArray(v) ? v.join(", ") : String(v)}
                        </span>
                      </div>
                    ))
                  ) : (
                    <span className="text-slate-400">None</span>
                  )}
                </div>
              </div>

              {selectedExchange.sanitizedRequestBody && (
                <div>
                  <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1.5">
                    Request Body
                  </h4>
                  <pre className="bg-slate-900 text-slate-100 p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto max-h-48 whitespace-pre-wrap">
                    {selectedExchange.sanitizedRequestBody}
                  </pre>
                </div>
              )}

              {selectedExchange.sanitizedResponseBody && (
                <div>
                  <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-1.5">
                    Response Body
                  </h4>
                  <pre className="bg-slate-900 text-slate-100 p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto max-h-60 whitespace-pre-wrap">
                    {selectedExchange.sanitizedResponseBody}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
