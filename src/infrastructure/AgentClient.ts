import axios from 'axios';
import { AgentResponse } from '../domain/PromptEvaluation';

export class AgentClient {
  constructor(private readonly baseUrl: string) {}

  async analyze(prompt: string): Promise<AgentResponse> {
    try {
      const res = await axios.post(`${this.baseUrl}/analyze`, { prompt });
      return {
        riskScore: res.data.risk_score,
        hasPii: res.data.has_pii,
        xaiExplanation: res.data.xai_explanation,
        requiresSandboxing: res.data.requires_sandboxing
      };
    } catch (error) {
      console.error('Agent service failed, defaulting to fail-safe block', error);
      return { riskScore: 1.0, hasPii: false, xaiExplanation: 'Agent service unreachable', requiresSandboxing: false };
    }
  }
}