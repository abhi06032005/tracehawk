import { Project, Session, HttpExchange, BrowserEvent, Finding } from "@/types";

const API_BASE = "/api";

export async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  let res: Response;
  try { res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-TraceHawk-Control": "1",
      ...options?.headers,
    },
    cache: 'no-store',
    signal: options?.signal || AbortSignal.timeout(60000),
  }); } catch { throw new Error('Cannot reach TraceHawk. Check that the local server is running, then retry.'); }

  if (!res.ok) {
    let errorMsg = `HTTP ${res.status} ${res.statusText}`;
    try {
      const errData = await res.json();
      if (errData.error) errorMsg = errData.error;
      if (errData.details) errorMsg += `: ${errData.details}`;
    } catch {}
    throw new Error(errorMsg);
  }
  try { return await res.json(); } catch { throw new Error('The local server returned an unexpected response. Retry or check Settings.'); }
}

export const api = {
  askReport: (id:string,question:string,findingId?:string)=>fetchJson<{questionId:string}>(`${API_BASE}/investigations/${id}/chat`,{method:'POST',body:JSON.stringify({question,findingId})}),
  stopReportReply: (id:string)=>fetchJson(`${API_BASE}/investigations/${id}/chat/stop`,{method:'POST'}),
  pairExtension: (projectId: string) => fetchJson<{code:string;expiresInSeconds:number}>(`${API_BASE}/extension/pair`, {method:'POST',body:JSON.stringify({projectId})}),
  launchExtensionSession: (data: { projectId: string; targetUrl?: string }) =>
    fetchJson<{ sessionId: string; message: string; code?: string }>(`${API_BASE}/extension/launch`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  getExtensionStatus: () => fetchJson<{ connected: boolean; lastSeen: number }>(`${API_BASE}/extension/status`),
  getHealth: () => fetchJson<{ status: string; services: any }>(`${API_BASE}/health`),

  getProjects: () => fetchJson<{ projects: Project[] }>(`${API_BASE}/projects`),

  createProject: (data: { name: string; targetUrl: string; allowedOrigins?: string[] }) =>
    fetchJson<{ project: Project }>(`${API_BASE}/projects`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getProject: (id: string) => fetchJson<{ project: Project }>(`${API_BASE}/projects/${id}`),

  launchSession: (data: { projectId: string; targetUrl?: string }) =>
    fetchJson<{ message: string; sessionId: string; targetUrl: string; status: string }>(
      `${API_BASE}/sessions`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),

  clearBrowserProfile: () =>
    fetchJson<{ success: boolean; message: string }>(`${API_BASE}/browser/clear-profile`, {
      method: "POST",
    }),

  getSession: (id: string) => fetchJson<{ session: Session }>(`${API_BASE}/sessions/${id}`),
  focusBrowser: (id: string) => fetchJson<{ message: string }>(`${API_BASE}/sessions/${id}/focus`, { method: 'POST' }),
  getStorage: (id: string) => fetchJson<{ observations: import('@/types').StorageObservation[] }>(`${API_BASE}/sessions/${id}/storage`),
  getTokens: (id: string) => fetchJson<{ observations: BrowserEvent[] }>(`${API_BASE}/sessions/${id}/tokens`),
  revealToken: (id: string, tokenId: string) => fetchJson<{ value: string }>(`${API_BASE}/sessions/${id}/tokens/${tokenId}/reveal`, { method: 'POST' }),

  pauseSession: (id: string) =>
    fetchJson<{ message: string; status: string }>(`${API_BASE}/sessions/${id}/pause`, {
      method: "POST",
    }),

  resumeSession: (id: string) =>
    fetchJson<{ message: string; status: string }>(`${API_BASE}/sessions/${id}/resume`, {
      method: "POST",
    }),

  stopSession: (id: string) =>
    fetchJson<{ message: string; session: Session }>(`${API_BASE}/sessions/${id}/stop`, {
      method: "POST",
    }),

  deleteSession: (id: string) =>
    fetchJson<{ message: string }>(`${API_BASE}/sessions/${id}`, {
      method: "DELETE",
    }),

  getTraffic: (
    id: string,
    params?: {
      method?: string;
      resourceType?: string;
      statusCode?: string;
      search?: string;
      limit?: number;
      offset?: number;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.method) searchParams.set("method", params.method);
    if (params?.resourceType) searchParams.set("resourceType", params.resourceType);
    if (params?.statusCode) searchParams.set("statusCode", params.statusCode);
    if (params?.search) searchParams.set("search", params.search);
    if (params?.limit) searchParams.set("limit", String(params.limit));
    if (params?.offset) searchParams.set("offset", String(params.offset));

    const qs = searchParams.toString();
    return fetchJson<{ exchanges: HttpExchange[]; total: number }>(
      `${API_BASE}/sessions/${id}/traffic${qs ? `?${qs}` : ""}`
    );
  },

  getEvents: (id: string, type?: string) => {
    const qs = type ? `?type=${encodeURIComponent(type)}` : "";
    return fetchJson<{ events: BrowserEvent[] }>(`${API_BASE}/sessions/${id}/events${qs}`);
  },

  analyzeSession: (id: string) =>
    fetchJson<{ message: string; summary: any; deepHatAnalysis?: string }>(`${API_BASE}/sessions/${id}/analyze`, {
      method: "POST",
    }),

  startInvestigation: (sessionId: string, options: { authorized: true; activeTests: boolean; maxSteps: number; maxTimeSeconds: number; requestBudget: number }) =>
    fetchJson<{ message: string; investigationId: string; status: string }>(
      `${API_BASE}/sessions/${sessionId}/investigate`,
      {
        method: "POST",
        body: JSON.stringify(options),
      }
    ),

  getAiConfig: () => fetchJson<{ enabled: boolean; model: string; scenarios: { id: string; endpoint: string }[]; zapConfigured: boolean }>(`${API_BASE}/ai/config`),
  approveAction: (id: string, approvalId: string, approved: boolean) => fetchJson(`${API_BASE}/investigations/${id}/approvals/${approvalId}`, { method: 'POST', body: JSON.stringify({ approved }) }),

  getInvestigations: (sessionId: string) =>
    fetchJson<{ investigations: any[] }>(`${API_BASE}/sessions/${sessionId}/investigations`),

  getInvestigation: (investigationId: string) =>
    fetchJson<{ investigation: any }>(`${API_BASE}/investigations/${investigationId}`),

  stopInvestigation: (investigationId: string) =>
    fetchJson<{ message: string }>(`${API_BASE}/investigations/${investigationId}/stop`, {
      method: "POST",
    }),

  getFindings: (id: string, params?: { category?: string; severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.category) searchParams.set("category", params.category);
    if (params?.severity) searchParams.set("severity", params.severity);
    const qs = searchParams.toString();
    return fetchJson<{ findings: Finding[] }>(
      `${API_BASE}/sessions/${id}/findings${qs ? `?${qs}` : ""}`
    );
  },

  // BugBase Pentest Copilot APIs
  launchCopilotMission: (data: { targetUrl: string; name?: string; mode?: 'autonomous' | 'quick' | 'api' | 'recon'; activeTests?: boolean; authProfile?: string; maxSteps?: number }) =>
    fetchJson<{ success: boolean; message: string; sessionId: string; projectId: string; targetUrl: string; mode: string }>(
      `${API_BASE}/copilot/launch`,
      { method: 'POST', body: JSON.stringify(data) }
    ),

  getCopilotMissions: () =>
    fetchJson<{ missions: Array<{ sessionId: string; investigationId: string | null; targetUrl: string; projectName: string; status: string; startedAt: string; totalRequests: number; totalErrors: number; findingsCount: number; criticalCount: number; highCount: number; mediumCount: number; lowCount: number }> }>(
      `${API_BASE}/copilot/missions`
    ),

  getCopilotChecklist: (investigationId: string) =>
    fetchJson<{ investigationId: string; status: string; completedSteps: number; totalSteps: number; checklist: Array<{ id: string; phase: number; title: string; category: string; description: string; status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'PASSED' | 'VULNERABLE'; findingsCount: number }> }>(
      `${API_BASE}/copilot/checklist/${investigationId}`
    ),

  getCopilotGraph: (investigationId: string) =>
    fetchJson<{ investigationId: string; nodes: Array<{ id: string; label: string; type: 'target' | 'endpoint' | 'threat' | 'finding'; risk?: string; details?: string }>; edges: Array<{ source: string; target: string; label?: string }> }>(
      `${API_BASE}/copilot/graph/${investigationId}`
    ),

  getCopilotPoC: (hypothesisId: string) =>
    fetchJson<{ hypothesisId: string; title: string; risk: string; cwe: string; endpoint: string; method: string; curlCommand: string; pythonScript: string; remediation: string }>(
      `${API_BASE}/copilot/poc/${hypothesisId}`
    ),

  executeCopilotCommand: (command: string, targetUrl?: string) =>
    fetchJson<{ output: string }>(
      `${API_BASE}/copilot/command`,
      { method: 'POST', body: JSON.stringify({ command, targetUrl }) }
    ),

  getExportUrl: (sessionId: string, format: "json" | "traffic" | "har") =>
    `${API_BASE}/sessions/${sessionId}/export?format=${format}`,
};
