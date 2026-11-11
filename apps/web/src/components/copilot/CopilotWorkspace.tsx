"use client";

import React, { useState, useEffect, useRef } from "react";
import Markdown from "react-markdown";
import {
  Shield,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Play,
  Square,
  Download,
  Copy,
  Check,
  Sparkles,
  Layers,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Cpu,
  Send,
  HelpCircle,
  Network,
  ListTodo,
  FileCode,
  Flame,
} from "lucide-react";
import { api } from "@/lib/api";

interface CopilotWorkspaceProps {
  mission: any;
  investigation: any;
  checklistData: any;
  graphData: any;
  config: any;
  onRefresh: () => Promise<void>;
  onStop: () => Promise<void>;
  onNewMissionClick: () => void;
  busy: boolean;
}

export function CopilotWorkspace({
  mission,
  investigation,
  checklistData,
  graphData,
  config,
  onRefresh,
  onStop,
  onNewMissionClick,
  busy,
}: CopilotWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<"copilot" | "terminal" | "checklist" | "graph">("copilot");
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [pocData, setPocData] = useState<any>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedPython, setCopiedPython] = useState(false);

  // Chat state
  const [chatInput, setChatInput] = useState("");
  const [chatSending, setChatSending] = useState(false);
  const [chatError, setChatError] = useState("");

  // Terminal state
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    `[${new Date().toLocaleTimeString()}] TraceHawk Pentest Copilot initialized.`,
    `[${new Date().toLocaleTimeString()}] Connected to AI Provider: ${config?.model || 'Gemini Flash-Lite'}`,
    `[${new Date().toLocaleTimeString()}] Ready. Type 'help' or launch an autonomous pentest mission.`,
  ]);
  const [cmdInput, setCmdInput] = useState("");
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const findings = investigation?.hypotheses || [];
  const selectedFinding = findings.find((f: any) => f.id === selectedFindingId) || findings[0];
  const steps = investigation?.steps || [];
  const isRunning = investigation?.status === "RUNNING" || investigation?.status === "AWAITING_APPROVAL";
  const approvalStep = steps.find((s: any) => s.approvalStatus === "PENDING");
  const conversation = steps.filter((s: any) => s.phase.startsWith("CHAT_"));

  // Fetch PoC whenever selected finding changes
  useEffect(() => {
    if (selectedFinding?.id) {
      api.getCopilotPoC(selectedFinding.id).then(setPocData).catch(() => setPocData(null));
    } else {
      setPocData(null);
    }
  }, [selectedFinding?.id]);

  // Scroll chat
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [conversation.length, isRunning]);

  // Scroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalLogs]);

  // Append new step logs to terminal
  useEffect(() => {
    if (steps.length > 0) {
      const recent = steps.slice(-5);
      const newEntries = recent.map(
        (s: any) =>
          `[${new Date(s.createdAt || Date.now()).toLocaleTimeString()}] [${s.phase}] ${s.thought || s.toolName || "Step completed"}`
      );
      setTerminalLogs((prev) => Array.from(new Set([...prev, ...newEntries])));
    }
  }, [steps.length]);

  const handleSendChat = async (text = chatInput) => {
    if (!text.trim() || !investigation?.id || chatSending) return;
    setChatSending(true);
    setChatError("");
    try {
      await api.askReport(investigation.id, text.trim(), selectedFinding?.id);
      setChatInput("");
      await onRefresh();
    } catch (err: any) {
      setChatError(err.message || "Failed to send query to Copilot");
    } finally {
      setChatSending(false);
    }
  };

  const handleTerminalCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cmdInput.trim()) return;
    const input = cmdInput.trim();
    setCmdInput("");

    if (input.toLowerCase() === "clear") {
      setTerminalLogs([]);
      return;
    }

    setTerminalLogs((prev) => [...prev, `$ ${input}`]);
    try {
      const res = await api.executeCopilotCommand(input, mission?.targetUrl);
      setTerminalLogs((prev) => [...prev, res.output]);
    } catch (err: any) {
      setTerminalLogs((prev) => [...prev, `[ERROR] ${err.message}`]);
    }
  };

  const copyToClipboard = (text: string, type: "curl" | "python") => {
    navigator.clipboard.writeText(text);
    if (type === "curl") {
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 2000);
    } else {
      setCopiedPython(true);
      setTimeout(() => setCopiedPython(false), 2000);
    }
  };

  const handleDownloadReport = () => {
    if (!investigation) return;
    const reportData = {
      title: "TraceHawk Pentest Copilot Security Assessment Report",
      generatedAt: new Date().toISOString(),
      targetUrl: mission?.targetUrl,
      model: investigation.model,
      status: investigation.status,
      summary: investigation.riskSummary,
      findings: investigation.hypotheses,
      steps: investigation.steps,
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pentest-copilot-report-${investigation.id}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-slate-950 font-sans text-slate-100">
      {/* Top Header / Mission Control */}
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-slate-800 bg-slate-900/90 px-4 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-white shadow-md shadow-indigo-600/30">
            <Sparkles className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white tracking-tight">Pentest Copilot</span>
              <span className="rounded bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-medium text-indigo-400 border border-indigo-500/20">
                Autonomous
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Target: <span className="font-mono text-slate-200">{mission?.targetUrl || "None selected"}</span>
            </p>
          </div>
        </div>

        {/* Center / Status */}
        <div className="hidden items-center gap-3 md:flex">
          <div className="flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-950 px-3 py-1 text-xs">
            <span
              className={`h-2 w-2 rounded-full ${
                isRunning ? "animate-pulse bg-emerald-400" : "bg-slate-400"
              }`}
            />
            <span className="font-medium text-slate-300">
              {isRunning ? "AGENT ACTIVE (Reasoning Loop)" : investigation?.status || "READY"}
            </span>
          </div>

          <div className="flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-950 px-3 py-1 text-xs text-slate-400">
            <Cpu className="h-3.5 w-3.5 text-indigo-400" />
            <span>{config?.model || "Gemini Flash-Lite"}</span>
          </div>
        </div>

        {/* Right Action Buttons */}
        <div className="flex items-center gap-2">
          {isRunning && (
            <button
              onClick={onStop}
              className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-500/20"
            >
              <Square className="h-3.5 w-3.5 fill-current" />
              Stop Agent
            </button>
          )}

          <button
            onClick={handleDownloadReport}
            disabled={!investigation}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-40"
          >
            <Download className="h-3.5 w-3.5" />
            VAPT Report
          </button>

          <button
            onClick={onNewMissionClick}
            disabled={busy}
            className="flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-md shadow-indigo-600/30 hover:bg-indigo-500 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            New Assessment
          </button>
        </div>
      </header>

      {/* Main Workspace Layout (Left: Tabs & Content, Right: Finding & PoC Inspector) */}
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[minmax(0,1fr)_420px]">
        {/* Left Column: Primary Tabbed Pane */}
        <div className="flex min-h-0 flex-col border-r border-slate-800 bg-slate-950">
          {/* Workspace Tabs Header */}
          <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/60 px-4 py-1.5">
            <div className="flex items-center gap-1">
              {[
                { id: "copilot", label: "AI Copilot", icon: Sparkles },
                { id: "terminal", label: "Live Terminal", icon: Terminal },
                { id: "checklist", label: "Pentest Checklist", icon: ListTodo },
                { id: "graph", label: "Exploit Graph", icon: Network },
              ].map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                      active
                        ? "bg-slate-800 text-white shadow-sm"
                        : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
                    }`}
                  >
                    <Icon className={`h-3.5 w-3.5 ${active ? "text-indigo-400" : "text-slate-500"}`} />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            <div className="text-[11px] text-slate-500">
              {findings.length} Vulnerabilities Found
            </div>
          </div>

          {/* TAB 1: AI COPILOT CHAT & STREAM */}
          {activeTab === "copilot" && (
            <div className="flex min-h-0 flex-1 flex-col">
              <div ref={chatScrollRef} className="flex-1 overflow-y-auto p-4 space-y-4">
                {/* Agent Welcome / Mission Intro */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
                  <div className="flex items-center gap-2 text-indigo-400">
                    <Sparkles className="h-4 w-4" />
                    <span className="text-xs font-semibold uppercase tracking-wider">Pentest Copilot Autonomous Agent</span>
                  </div>
                  <h3 className="mt-1 text-base font-semibold text-white">
                    {mission?.targetUrl ? `Auditing ${mission.targetUrl}` : "Ready to conduct security assessment."}
                  </h3>
                  <p className="mt-1 text-xs leading-relaxed text-slate-400">
                    I automatically map endpoints, test for vulnerabilities (IDOR, Clickjacking, Injection, Missing
                    Security Headers), execute verifiable checks, and produce reproducible cURL/Python PoCs.
                  </p>
                </div>

                {/* Human Approval Required Card */}
                {approvalStep && (
                  <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-200 shadow-lg">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-400" />
                      <span className="text-xs font-semibold">Human Consent Required (State-Changing Probe)</span>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
                      The AI agent is requesting authorization to execute an active security test:
                    </p>
                    <pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-black/40 p-2.5 font-mono text-[11px] text-amber-300">
                      {JSON.stringify(approvalStep.toolResult?.approvalRequest || approvalStep.toolArgs, null, 2)}
                    </pre>
                    <div className="mt-3 flex gap-2">
                      <button
                        onClick={() => api.approveAction(investigation.id, approvalStep.approvalId, true)}
                        className="rounded-lg bg-amber-500 px-3 py-1.5 text-xs font-semibold text-black hover:bg-amber-400"
                      >
                        Approve Action
                      </button>
                      <button
                        onClick={() => api.approveAction(investigation.id, approvalStep.approvalId, false)}
                        className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700"
                      >
                        Deny
                      </button>
                    </div>
                  </div>
                )}

                {/* Real-time Agent Thoughts & Steps */}
                {steps
                  .filter((s: any) => !s.phase.startsWith("CHAT_"))
                  .map((step: any) => (
                    <div
                      key={step.id}
                      className="rounded-xl border border-slate-800/80 bg-slate-900/30 p-3.5 transition hover:border-slate-700"
                    >
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span className="font-mono uppercase text-indigo-400 font-semibold">{step.phase}</span>
                        <span>{new Date(step.createdAt || Date.now()).toLocaleTimeString()}</span>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-300 font-sans">
                        {step.thought}
                      </p>
                      {step.toolResult && (
                        <details className="mt-2 border-t border-slate-800/60 pt-2">
                          <summary className="cursor-pointer text-[10px] text-slate-500 hover:text-slate-300">
                            Tool Result Evidence ({step.toolName || "Result"})
                          </summary>
                          <pre className="mt-1 max-h-40 overflow-auto rounded bg-black/50 p-2 font-mono text-[10px] text-slate-400">
                            {JSON.stringify(step.toolResult, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  ))}

                {/* Conversation History */}
                {conversation.map((msg: any) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${
                      msg.phase === "CHAT_USER" ? "items-end" : "items-start"
                    }`}
                  >
                    <div className="mb-1 text-[10px] text-slate-500">
                      {msg.phase === "CHAT_USER" ? "You" : "Pentest Copilot"}
                    </div>
                    <div
                      className={`max-w-xl rounded-2xl p-3.5 text-xs leading-relaxed ${
                        msg.phase === "CHAT_USER"
                          ? "bg-indigo-600 text-white"
                          : "border border-slate-800 bg-slate-900 text-slate-200"
                      }`}
                    >
                      <Markdown>{msg.thought}</Markdown>
                    </div>
                  </div>
                ))}

                {chatSending && (
                  <div className="flex items-center gap-2 text-xs text-indigo-400">
                    <Sparkles className="h-3.5 w-3.5 animate-spin" />
                    <span>Copilot is analyzing evidence and formulating response...</span>
                  </div>
                )}
              </div>

              {/* Chat Input & Quick Action Pills */}
              <div className="border-t border-slate-800 bg-slate-900/60 p-3">
                {/* Quick Prompts */}
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {[
                    "Explain the Clickjacking vulnerability",
                    "What should I test next?",
                    "Generate cURL exploit for finding #1",
                    "How to remediate highest risk issue?",
                  ].map((pill) => (
                    <button
                      key={pill}
                      onClick={() => handleSendChat(pill)}
                      disabled={chatSending || !investigation}
                      className="rounded-full border border-slate-800 bg-slate-950 px-2.5 py-1 text-[11px] text-slate-400 hover:border-slate-700 hover:text-slate-200 disabled:opacity-30"
                    >
                      {pill}
                    </button>
                  ))}
                </div>

                {chatError && <p className="mb-2 text-xs text-rose-400">{chatError}</p>}

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSendChat();
                  }}
                  className="relative flex items-center"
                >
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder={
                      isRunning
                        ? "Ask Copilot anything about the ongoing assessment..."
                        : "Ask about attack paths, verify an endpoint, or request remediation code..."
                    }
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 py-2.5 pl-3 pr-10 text-xs text-white placeholder-slate-500 outline-none focus:border-indigo-500"
                  />
                  <button
                    type="submit"
                    disabled={chatSending || !chatInput.trim()}
                    className="absolute right-2 rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white disabled:opacity-30"
                  >
                    <Send className="h-4 w-4" />
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* TAB 2: LIVE TERMINAL */}
          {activeTab === "terminal" && (
            <div className="flex min-h-0 flex-1 flex-col bg-black font-mono text-emerald-400">
              <div className="flex-1 overflow-y-auto p-4 space-y-1 text-xs">
                {terminalLogs.map((log, idx) => (
                  <div key={idx} className="whitespace-pre-wrap leading-relaxed">
                    {log}
                  </div>
                ))}
                <div ref={terminalEndRef} />
              </div>

              {/* Terminal Command Prompt */}
              <form
                onSubmit={handleTerminalCommand}
                className="flex items-center border-t border-slate-800 bg-slate-950/80 px-3 py-2 text-xs"
              >
                <span className="mr-2 text-emerald-500 font-bold">$</span>
                <input
                  type="text"
                  value={cmdInput}
                  onChange={(e) => setCmdInput(e.target.value)}
                  placeholder="Type 'help', 'recon <url>', 'check-headers <url>', or 'status'..."
                  className="flex-1 bg-transparent text-emerald-400 placeholder-slate-600 outline-none"
                />
              </form>
            </div>
          )}

          {/* TAB 3: DYNAMIC PENTEST CHECKLIST */}
          {activeTab === "checklist" && (
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-white">PTES / OWASP Pentesting Methodology</h3>
                  <p className="text-xs text-slate-400">
                    Live dynamic checklist automatically tracked and evaluated by the Copilot agent
                  </p>
                </div>
                <div className="text-xs font-semibold text-indigo-400">
                  {checklistData?.completedSteps || 0} / {checklistData?.totalSteps || 8} Phases
                </div>
              </div>

              <div className="space-y-3">
                {(checklistData?.checklist || []).map((item: any) => {
                  const isVuln = item.status === "VULNERABLE";
                  const isDone = item.status === "COMPLETED" || item.status === "PASSED";
                  const isProg = item.status === "IN_PROGRESS";

                  return (
                    <div
                      key={item.id}
                      className={`rounded-xl border p-4 transition ${
                        isVuln
                          ? "border-red-500/30 bg-red-500/5"
                          : isDone
                          ? "border-emerald-500/30 bg-emerald-500/5"
                          : isProg
                          ? "border-indigo-500/30 bg-indigo-500/5"
                          : "border-slate-800 bg-slate-900/30"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <span className="flex h-5 w-5 items-center justify-center rounded-full bg-slate-800 text-[10px] font-bold text-slate-300">
                            {item.phase}
                          </span>
                          <span className="text-xs font-semibold text-white">{item.title}</span>
                        </div>

                        <span
                          className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                            isVuln
                              ? "bg-red-500/20 text-red-400 border border-red-500/30"
                              : isDone
                              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                              : isProg
                              ? "bg-indigo-500/20 text-indigo-400 animate-pulse border border-indigo-500/30"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {item.status}
                        </span>
                      </div>

                      <p className="mt-2 text-xs leading-relaxed text-slate-400">
                        {item.description}
                      </p>

                      {item.findingsCount > 0 && (
                        <div className="mt-2 text-[11px] font-semibold text-rose-400">
                          ⚠️ {item.findingsCount} Potential Security Finding(s) Identified
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 4: EXPLOIT GRAPH */}
          {activeTab === "graph" && (
            <div className="flex-1 overflow-auto p-6">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">Exploit Graph & Attack Path Visualizer</h3>
                  <p className="text-xs text-slate-400">
                    Traces vulnerabilities from initial root target down to compromised endpoints
                  </p>
                </div>
              </div>

              {/* Exploit Graph Visual Cards */}
              <div className="flex flex-col gap-6">
                {/* Root Node */}
                <div className="flex justify-center">
                  <div className="rounded-xl border border-indigo-500 bg-indigo-500/10 px-5 py-3 text-center shadow-lg shadow-indigo-500/20">
                    <span className="text-[10px] uppercase tracking-wider text-indigo-400 font-bold">Target Entity</span>
                    <p className="font-mono text-xs font-semibold text-white">{graphData?.nodes?.[0]?.label || "Target Host"}</p>
                  </div>
                </div>

                <div className="flex justify-center">
                  <ArrowRight className="h-5 w-5 rotate-90 text-slate-600" />
                </div>

                {/* Endpoints Layer */}
                <div>
                  <span className="mb-2 block text-center text-[10px] uppercase tracking-wider text-slate-500 font-bold">
                    Discovered Attack Surface
                  </span>
                  <div className="flex flex-wrap justify-center gap-3">
                    {(graphData?.nodes || [])
                      .filter((n: any) => n.type === "endpoint")
                      .map((ep: any) => (
                        <div
                          key={ep.id}
                          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-300"
                        >
                          {ep.label}
                        </div>
                      ))}
                  </div>
                </div>

                <div className="flex justify-center">
                  <ArrowRight className="h-5 w-5 rotate-90 text-slate-600" />
                </div>

                {/* Exploited Vulnerabilities Layer */}
                <div>
                  <span className="mb-2 block text-center text-[10px] uppercase tracking-wider text-rose-500 font-bold">
                    Identified Vulnerabilities & Threat Paths
                  </span>
                  <div className="flex flex-wrap justify-center gap-3">
                    {findings.map((hyp: any) => (
                      <button
                        key={hyp.id}
                        onClick={() => setSelectedFindingId(hyp.id)}
                        className={`flex flex-col rounded-xl border p-3.5 text-left transition ${
                          selectedFinding?.id === hyp.id
                            ? "border-rose-500 bg-rose-500/10 shadow-lg shadow-rose-500/20"
                            : "border-slate-800 bg-slate-900/60 hover:border-slate-700"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                              hyp.risk === "CRITICAL" || hyp.risk === "HIGH"
                                ? "bg-red-500/20 text-red-400"
                                : "bg-amber-500/20 text-amber-400"
                            }`}
                          >
                            {hyp.risk}
                          </span>
                          <span className="text-xs font-semibold text-white">{hyp.title}</span>
                        </div>
                        <span className="mt-1 font-mono text-[10px] text-slate-400">{hyp.affectedEndpoint}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Finding & PoC Inspector */}
        <div className="flex min-h-0 flex-col bg-slate-900/50">
          {/* Finding Selector Header */}
          <div className="border-b border-slate-800 p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Vulnerabilities ({findings.length})
              </span>
              <span className="text-[11px] text-slate-400">Click to inspect PoC</span>
            </div>

            {/* Finding Pills List */}
            <div className="mt-2.5 flex max-h-36 flex-col gap-1.5 overflow-y-auto">
              {findings.map((f: any) => {
                const isSelected = selectedFinding?.id === f.id;
                return (
                  <button
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    className={`flex items-center justify-between rounded-lg border px-3 py-2 text-left text-xs transition ${
                      isSelected
                        ? "border-indigo-500 bg-indigo-500/10 text-white"
                        : "border-slate-800/80 bg-slate-950/40 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                    }`}
                  >
                    <span className="truncate font-medium">{f.title}</span>
                    <span
                      className={`ml-2 text-[10px] font-bold ${
                        f.risk === "CRITICAL" || f.risk === "HIGH" ? "text-red-400" : "text-amber-400"
                      }`}
                    >
                      {f.risk}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Finding Detail Pane */}
          {selectedFinding ? (
            <div className="flex-1 overflow-y-auto p-4 space-y-5 text-xs text-slate-300">
              {/* Header Info */}
              <div>
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                      selectedFinding.risk === "CRITICAL" || selectedFinding.risk === "HIGH"
                        ? "bg-red-500/20 text-red-400 border border-red-500/30"
                        : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    }`}
                  >
                    {selectedFinding.risk}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">{selectedFinding.cweCategory}</span>
                </div>
                <h3 className="mt-2 text-base font-semibold text-white">{selectedFinding.title}</h3>
                <p className="mt-1 break-all font-mono text-xs text-indigo-400">{selectedFinding.affectedEndpoint}</p>
              </div>

              {/* Attack Path */}
              <div>
                <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Attack Mechanism</h4>
                <p className="mt-1.5 leading-relaxed text-slate-400 font-sans">
                  {selectedFinding.attackMechanism || "Observed during security evaluation."}
                </p>
              </div>

              {/* What an attacker needs */}
              <div>
                <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Prerequisites</h4>
                <p className="mt-1.5 leading-relaxed text-slate-400 font-sans">
                  {selectedFinding.prerequisites || "Standard network access to web target."}
                </p>
              </div>

              {/* Potential Impact */}
              <div>
                <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Potential Impact</h4>
                <p className="mt-1.5 leading-relaxed text-slate-400 font-sans">
                  {selectedFinding.potentialImpact || "High risk of security boundary bypass."}
                </p>
              </div>

              {/* Deterministic Proof of Concept (cURL & Python) */}
              {pocData && (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                      <Terminal className="h-3.5 w-3.5" />
                      Deterministic cURL PoC
                    </span>
                    <button
                      onClick={() => copyToClipboard(pocData.curlCommand, "curl")}
                      className="flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700"
                    >
                      {copiedCurl ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      {copiedCurl ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="mt-2 max-h-36 overflow-auto font-mono text-[10px] text-slate-300 whitespace-pre-wrap">
                    {pocData.curlCommand}
                  </pre>

                  <div className="mt-3 flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-xs font-semibold text-indigo-400 flex items-center gap-1.5">
                      <FileCode className="h-3.5 w-3.5" />
                      Python Reproduction Script
                    </span>
                    <button
                      onClick={() => copyToClipboard(pocData.pythonScript, "python")}
                      className="flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700"
                    >
                      {copiedPython ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      {copiedPython ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="mt-2 max-h-36 overflow-auto font-mono text-[10px] text-slate-300 whitespace-pre-wrap">
                    {pocData.pythonScript}
                  </pre>
                </div>
              )}

              {/* Step-by-Step Remediation */}
              <div className="rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-3.5">
                <h4 className="text-xs font-semibold text-indigo-300 uppercase tracking-wider">How to Fix</h4>
                <div className="mt-1.5 leading-relaxed text-slate-300">
                  <Markdown>{selectedFinding.suggestedRemediation || "Apply security header and origin restriction."}</Markdown>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-1 items-center justify-center p-6 text-center text-xs text-slate-500">
              No finding selected. Launch a pentest mission to discover and inspect vulnerabilities.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

