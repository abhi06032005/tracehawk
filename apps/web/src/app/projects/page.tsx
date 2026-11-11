"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { FolderGit2, Plus, Play, Radio, Globe, Shield, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { Project } from "@/types";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");
  const [allowedOrigins, setAllowedOrigins] = useState("http://localhost:3000, http://127.0.0.1:3000");
  const [launchingId, setLaunchingId] = useState<string | null>(null);

  const loadProjects = async () => {
    try {
      const data = await api.getProjects();
      setProjects(data.projects);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProjects();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !targetUrl.trim()) return;

    try {
      const origins = allowedOrigins
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      await api.createProject({
        name: name.trim(),
        targetUrl: targetUrl.trim(),
        allowedOrigins: origins,
      });

      setShowModal(false);
      setName("");
      await loadProjects();
    } catch (err: any) {
      alert(`Error creating project: ${err.message}`);
    }
  };

  const handleLaunch = async (projectId: string, targetUrl: string) => {
    try {
      setLaunchingId(projectId);
      const res = await api.launchSession({ projectId, targetUrl });
      window.location.href = `/sessions/${res.sessionId}`;
    } catch (err: any) {
      alert(`Launch error: ${err.message}`);
      setLaunchingId(null);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto w-full space-y-6">
      {error && <div role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error} <button className="underline" onClick={() => window.location.reload()}>Retry</button></div>}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Projects</h1>
          <p className="text-sm text-slate-500 mt-1">
            Manage target applications and authorized testing scopes.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors shadow-sm"
        >
          <Plus className="w-4 h-4" />
          Create Project
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {projects.length === 0 ? (
          <div className="col-span-full bg-white border border-slate-200 rounded-xl p-12 text-center text-slate-500">
            <FolderGit2 className="w-12 h-12 text-slate-300 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-900">No Projects Configured</h3>
            <p className="text-sm text-slate-500 max-w-sm mx-auto mt-1">
              Add your application (e.g. OWASP Juice Shop on http://localhost:3000) to start recording browser security traffic.
            </p>
            <button
              onClick={() => setShowModal(true)}
              className="mt-4 px-4 py-2 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800"
            >
              Create Project
            </button>
          </div>
        ) : (
          projects.map((project) => (
            <div
              key={project.id}
              className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <h3 className="font-semibold text-base text-slate-900">{project.name}</h3>
                  <span className="text-[11px] font-mono text-slate-600 bg-slate-100 px-2 py-0.5 rounded">
                    {project.sessions?.length || 0} Sessions
                  </span>
                </div>

                <div className="space-y-1.5 text-xs text-slate-600">
                  <div className="flex items-center gap-1.5 font-mono text-slate-700 truncate">
                    <Globe className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span>{project.targetUrl}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-500">
                    <Shield className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span className="truncate">
                      Scope: {project.allowedOrigins?.join(", ") || "Strict origin"}
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-100 flex items-center justify-between gap-3">
                <Link
                  href={`/sessions?project=${project.id}`}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors"
                >
                  <Radio className="w-3.5 h-3.5" />
                  View Sessions
                </Link>

                <button
                  onClick={() => handleLaunch(project.id, project.targetUrl)}
                  disabled={launchingId === project.id}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-slate-900 text-white rounded-lg hover:bg-slate-800 disabled:opacity-50 transition-colors"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  {launchingId === project.id ? "Launching..." : "Launch Browser & Record"}
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl border border-slate-200 shadow-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-semibold text-slate-900">New Project Target</h3>

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Project Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="OWASP Juice Shop"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-slate-900"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Target Application URL
                </label>
                <input
                  type="url"
                  required
                  placeholder="http://localhost:3000"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono text-xs focus:outline-hidden focus:ring-2 focus:ring-slate-900"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Allowed Origins (Comma-separated)
                </label>
                <input
                  type="text"
                  placeholder="http://localhost:3000, http://127.0.0.1:3000"
                  value={allowedOrigins}
                  onChange={(e) => setAllowedOrigins(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono text-xs focus:outline-hidden focus:ring-2 focus:ring-slate-900"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Only HTTP requests belonging to these origins will have full bodies captured.
                </p>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium bg-slate-900 text-white rounded-lg hover:bg-slate-800"
                >
                  Save Project
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
