import { EnrichedSBOM } from "./sbom";

export interface ScanRequest {
  projectRef: string;
  refType: "git" | "zip" | "image";
  ref: string;
}

export interface ScanResponse {
  jobId: string;
}

export interface EnrichResponse extends EnrichedSBOM {}

export interface AskRequest {
  projectId: string;
  question: string;
}

export interface KeyFinding {
  nodeId: string;
  reason: string;
}

export interface RemediationStep {
  title: string;
  impact: "HIGH" | "MEDIUM" | "LOW";
  actions: string[];
  affectedPackages: string[];
  estimatedBreakage: "LOW" | "MEDIUM" | "HIGH";
}

export interface Citation {
  type: "package" | "vuln" | "advisory";
  id: string;
}

export interface AgentAnswer {
  question: string;
  answerMarkdown: string;
  keyFindings: KeyFinding[];
  remediationPlan: RemediationStep[];
  citations: Citation[];
}

export interface ReportRequest {
  projectId: string;
  format?: "pdf" | "markdown";
}