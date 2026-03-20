export interface PromptRequest {
  prompt: string;
  userId: string;
  requestId?: string;
  sessionId?: string;
  clientIp?: string;
}

export interface AgentResponse {
  riskScore: number;
  hasPii: boolean;
  xaiExplanation: string;
  requiresSandboxing: boolean;
  detectedThreats?: ThreatType[];
  confidenceScore?: number;
}

export enum ThreatType {
  PROMPT_INJECTION = 'PROMPT_INJECTION',
  PII_EXFILTRATION = 'PII_EXFILTRATION',
  JAILBREAK = 'JAILBREAK',
  OBFUSCATION = 'OBFUSCATION',
  SENSITIVE_DATA = 'SENSITIVE_DATA',
  UNKNOWN = 'UNKNOWN',
}

export enum SecurityDecision {
  ALLOW = 'ALLOW',
  BLOCK = 'BLOCK',
  SANDBOX = 'SANDBOX',
}

export interface EvaluationResult {
  requestId: string;
  blocked: boolean;
  decision: SecurityDecision;
  riskScore: number;
  xaiExplanation: string;
  detectedThreats: ThreatType[];
  sandboxJobId?: string;
  evaluationMs?: number;
}

export interface AuditEvent {
  requestId: string;
  userId: string;
  clientIp?: string;
  prompt: string;
  decision: SecurityDecision;
  riskScore: number;
  detectedThreats: ThreatType[];
  xaiExplanation: string;
  sandboxJobId?: string;
  timestamp: string;
}