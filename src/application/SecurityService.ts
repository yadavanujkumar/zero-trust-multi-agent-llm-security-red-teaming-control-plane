import { PromptRequest, AgentResponse, EvaluationResult } from '../domain/PromptEvaluation';
import { SlackNotifier } from '../infrastructure/SlackNotifier';
import { K8sSandbox } from '../infrastructure/K8sSandbox';
import { AgentClient } from '../infrastructure/AgentClient';

/**
 * Orchestrates the Zero-Trust Evaluation Logic
 */
export class SecurityService {
  constructor(
    private readonly agentClient: AgentClient,
    private readonly slackNotifier: SlackNotifier,
    private readonly k8sSandbox: K8sSandbox
  ) {}

  public async evaluatePrompt(request: PromptRequest): Promise<EvaluationResult> {
    // 1. Multi-Agent Analysis
    const agentAnalysis: AgentResponse = await this.agentClient.analyze(request.prompt);

    // 2. Determine Sandboxing Needs
    if (agentAnalysis.requiresSandboxing || (agentAnalysis.riskScore > 0.5 && agentAnalysis.riskScore <= 0.8)) {
      await this.k8sSandbox.detonate(request.prompt);
    }

    // 3. Evaluate Block Condition
    const blocked = agentAnalysis.riskScore > 0.8 || agentAnalysis.hasPii;

    // 4. Alerting via Slack/Teams
    if (blocked) {
      await this.slackNotifier.sendAlert({
        userId: request.userId,
        riskScore: agentAnalysis.riskScore,
        explanation: agentAnalysis.xaiExplanation
      });
    }

    return {
      blocked,
      riskScore: agentAnalysis.riskScore,
      xaiExplanation: agentAnalysis.xaiExplanation
    };
  }
}