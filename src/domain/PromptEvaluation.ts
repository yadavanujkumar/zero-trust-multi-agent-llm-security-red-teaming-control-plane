export interface PromptRequest {
  prompt: string;
  userId: string;
}

export interface AgentResponse {
  riskScore: number;
  hasPii: boolean;
  xaiExplanation: string;
  requiresSandboxing: boolean;
}

export interface EvaluationResult {
  blocked: boolean;
  riskScore: number;
  xaiExplanation: string;
}