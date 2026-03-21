import axios, { AxiosError } from 'axios';
import { AgentResponse, ThreatType } from '../domain/PromptEvaluation';
import { logger } from './Logger';
import { agentServiceErrors } from './MetricsCollector';

const RETRY_DELAYS_MS = [250, 750, 1500];
const REQUEST_TIMEOUT_MS = 10_000;

export class AgentClient {
  constructor(private readonly baseUrl: string) {}

  async analyze(prompt: string, requestId?: string): Promise<AgentResponse> {
    for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
      try {
        const res = await axios.post(
          `${this.baseUrl}/analyze`,
          { prompt },
          {
            timeout: REQUEST_TIMEOUT_MS,
            headers: {
              'Content-Type': 'application/json',
              ...(requestId ? { 'X-Request-ID': requestId } : {}),
            },
          },
        );
        return {
          riskScore: res.data.risk_score,
          hasPii: res.data.has_pii,
          xaiExplanation: res.data.xai_explanation,
          requiresSandboxing: res.data.requires_sandboxing,
          detectedThreats: (res.data.detected_threats as ThreatType[]) ?? [],
          confidenceScore: res.data.confidence_score ?? 1.0,
        };
      } catch (err) {
        const isLastAttempt = attempt === RETRY_DELAYS_MS.length;
        const axiosErr = err as AxiosError;
        logger.warn('Agent service call failed', {
          requestId,
          attempt: attempt + 1,
          maxAttempts: RETRY_DELAYS_MS.length + 1,
          status: axiosErr.response?.status,
          message: axiosErr.message,
        });

        if (!isLastAttempt) {
          await new Promise(r => setTimeout(r, RETRY_DELAYS_MS[attempt]));
          continue;
        }

        agentServiceErrors.inc();
        logger.error('Agent service unreachable after all retries — engaging fail-safe block', {
          requestId,
        });
        return {
          riskScore: 1.0,
          hasPii: false,
          xaiExplanation: 'Agent service unreachable — fail-safe block applied',
          requiresSandboxing: false,
          detectedThreats: [ThreatType.UNKNOWN],
          confidenceScore: 0,
        };
      }
    }
    // TypeScript requires a return path here; unreachable in practice
    /* istanbul ignore next */
    return {
      riskScore: 1.0,
      hasPii: false,
      xaiExplanation: 'Unexpected code path',
      requiresSandboxing: false,
      detectedThreats: [ThreatType.UNKNOWN],
      confidenceScore: 0,
    };
  }
}
