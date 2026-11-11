export interface Project {
  id: string;
  name: string;
  targetUrl: string;
  allowedOrigins: string[];
  createdAt: string;
  sessions?: Session[];
}

export interface Session {
  id: string;
  projectId: string;
  project?: Project;
  status: "RECORDING" | "PAUSED" | "STOPPED" | "ANALYZED";
  startedAt: string;
  endedAt?: string | null;
  totalRequests: number;
  totalErrors: number;
  isLiveActive?: boolean;
  browserName?: string | null;
  findings?: Finding[];
  investigations?: Investigation[];
  _count?: {
    httpExchanges: number;
    browserEvents: number;
    storageObservations: number;
    findings: number;
    investigations: number;
  };
}

export interface HttpExchange {
  id: string;
  sessionId: string;
  timestamp: string;
  method: string;
  url: string;
  statusCode: number | null;
  requestHeaders?: Record<string, string | string[]>;
  responseHeaders?: Record<string, string | string[]>;
  sanitizedRequestBody?: string | null;
  sanitizedResponseBody?: string | null;
  contentType?: string | null;
  duration?: number | null;
  resourceType?: string | null;
  failureReason?: string | null;
  pageUrl?: string | null;
}

export interface BrowserEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  type: string;
  message: string;
  pageUrl?: string | null;
  metadata?: Record<string, any>;
}

export interface StorageObservation {
  id: string;
  sessionId: string;
  origin: string;
  storageType: "COOKIE" | "LOCAL_STORAGE" | "SESSION_STORAGE" | "INDEXED_DB";
  key: string;
  sanitizedValue?: string | null;
  timestamp: string;
}

export interface Finding {
  id: string;
  sessionId: string;
  title: string;
  category: "HEADERS" | "COOKIES" | "STORAGE" | "INFORMATION_DISCLOSURE" | "CORS" | "ERROR_LEAK" | "AUTH" | "MIXED_CONTENT";
  cweId?: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "CERTAIN" | "HIGH" | "MEDIUM" | "LOW";
  verificationStatus: "CONFIRMED_CONFIG" | "POTENTIAL_VULNERABILITY" | "INFORMATIONAL";
  description: string;
  evidence: any;
  impact: string;
  remediation: string;
  createdAt: string;
}

export interface InvestigationStep {
  id: string;
  investigationId: string;
  stepNumber: number;
  phase: "OBSERVE" | "ANALYZE" | "PLAN" | "VERIFY" | "EVALUATE" | "ERROR" | "CHAT_USER" | "CHAT_ASSISTANT" | "CHAT_ERROR";
  thought: string;
  toolName?: string | null;
  toolArgs?: any;
  toolResult?: any;
  decision?: any;
  evaluation?: any;
  approvalId?: string;
  approvalStatus?: string;
  timestamp: string;
}

export interface AiHypothesis {
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  claimType: string;
  id: string;
  investigationId: string;
  title: string;
  affectedEndpoint: string;
  cweCategory?: string | null;
  attackMechanism?: string | null;
  prerequisites?: string | null;
  potentialImpact?: string | null;
  suggestedRemediation?: string | null;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  verificationStatus: "HYPOTHESIS" | "NEEDS_VERIFICATION" | "VERIFIED" | "REJECTED";
  supportingEvidenceIds: string[];
  verificationNotes?: string | null;
  createdAt: string;
}

export interface Investigation {
  id: string;
  sessionId: string;
  session?: Session;
  status: "PENDING" | "RUNNING" | "AWAITING_APPROVAL" | "LIMIT_REACHED" | "COMPLETED" | "CANCELLED" | "FAILED";
  requestsUsed: number;
  requestBudget: number;
  allowedOrigins: string[];
  currentStep: number;
  maxSteps: number;
  model?: string | null;
  riskSummary?: string | null;
  startedAt: string;
  completedAt?: string | null;
  errorMessage?: string | null;
  steps?: InvestigationStep[];
  hypotheses?: AiHypothesis[];
}

export interface LiveTelemetryUpdate {
  type: "telemetry";
  sessionId: string;
  status: string;
  totalRequests: number;
  totalErrors: number;
  recentEndpoint?: {
    method: string;
    url: string;
    statusCode: number | null;
    duration: number | null;
    timestamp: string;
  };
  currentPageUrl?: string;
  activeTabsCount: number;
}
