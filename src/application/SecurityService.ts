import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import {
  PromptRequest,
  AgentResponse,
  EvaluationResult,
  AuditEvent,
  SecurityDecision,
} from '../domain/PromptEvaluation';
import { SlackNotifier } from '../infrastructure/SlackNotifier';
import { K8sSandbox } from '../infrastructure/K8sSandbox';
import { AgentClient } from '../infrastructure/AgentClient';
import { RedisCache } from '../infrastructure/RedisCache';
import { logger } from '../infrastructure/Logger';
import {
  blockedPromptsTotal,
  promptEvaluationDuration,
  riskScoreHistogram,
} from '../infrastructure/MetricsCollector';

const CACHE_TTL_SECONDS = parseInt(process.env.PROMPT_CACHE_TTL || '60', 10);
const AUDIT_LOG_KEY = 'audit:security-events';

/**
 * Orchestrates the Zero-Trust Evaluation Pipeline.
 *
 * Decision matrix:
 *   risk > 0.8 OR hasPii  → BLOCK + Slack alert
 *   0.5 < risk ≤ 0.8      → SANDBOX (K8s job) + allow
 *   risk ≤ 0.5            → ALLOW
 */
export class SecurityService {
  constructor(
    private readonly agentClient: AgentClient,
    private readonly slackNotifier: SlackNotifier,
    private readonly k8sSandbox: K8sSandbox,
    private readonly cache?: RedisCache,
  ) {}

  public async evaluatePrompt(request: PromptRequest): Promise<EvaluationResult> {
    const requestId = request.requestId ?? uuidv4();
    const startTime = Date.now();
    const timer = promptEvaluationDuration.startTimer();

    logger.info('Evaluating prompt', {
      requestId,
      userId: request.userId,
      promptLength: request.prompt.length,
    });

    // 1. Cache lookup — deduplicate identical prompts within TTL window
    let agentAnalysis: AgentResponse | null = null;
    if (this.cache) {
      const cacheKey = `prompt:${crypto.createHash('sha256').update(request.prompt).digest('hex')}`;
      agentAnalysis = await this.cache.get<AgentResponse>(cacheKey);
      if (agentAnalysis) {
        logger.info('Cache hit — reusing agent analysis', { requestId, cacheKey });
      } else {
        // 2. Multi-Agent Analysis
        agentAnalysis = await this.agentClient.analyze(request.prompt, requestId);
        await this.cache.set(cacheKey, agentAnalysis, CACHE_TTL_SECONDS);
      }
    } else {
      agentAnalysis = await this.agentClient.analyze(request.prompt, requestId);
    }

    riskScoreHistogram.observe(agentAnalysis.riskScore);

    // 3. Determine decision
    const blocked = agentAnalysis.riskScore > 0.8 || agentAnalysis.hasPii;
    const needsSandbox =
      !blocked &&
      (agentAnalysis.requiresSandboxing ||
        (agentAnalysis.riskScore > 0.5 && agentAnalysis.riskScore <= 0.8));

    const decision: SecurityDecision = blocked
      ? SecurityDecision.BLOCK
      : needsSandbox
        ? SecurityDecision.SANDBOX
        : SecurityDecision.ALLOW;

    let sandboxJobId: string | undefined;

    // 4. Spawn sandbox job for medium-risk payloads
    if (needsSandbox) {
      sandboxJobId = await this.k8sSandbox.detonate(request.prompt, requestId);
      logger.info('Sandbox job spawned', { requestId, sandboxJobId });
    }

    // 5. Alert via Slack for blocked prompts
    if (blocked) {
      blockedPromptsTotal.inc({ reason: agentAnalysis.hasPii ? 'pii' : 'high_risk' });
      await this.slackNotifier.sendAlert({
        requestId,
        userId: request.userId,
        riskScore: agentAnalysis.riskScore,
        explanation: agentAnalysis.xaiExplanation,
        detectedThreats: agentAnalysis.detectedThreats ?? [],
        clientIp: request.clientIp,
        sandboxJobId,
      });
    }

    // 6. Persist audit event
    const auditEvent: AuditEvent = {
      requestId,
      userId: request.userId,
      clientIp: request.clientIp,
      prompt: request.prompt.slice(0, 500), // truncate for audit log storage
      decision,
      riskScore: agentAnalysis.riskScore,
      detectedThreats: agentAnalysis.detectedThreats ?? [],
      xaiExplanation: agentAnalysis.xaiExplanation,
      sandboxJobId,
      timestamp: new Date().toISOString(),
    };
    if (this.cache) {
      await this.cache.rpush(AUDIT_LOG_KEY, auditEvent);
    }

    const evaluationMs = Date.now() - startTime;
    timer();

    logger.info('Prompt evaluation complete', {
      requestId,
      decision,
      riskScore: agentAnalysis.riskScore,
      evaluationMs,
    });

    return {
      requestId,
      blocked,
      decision,
      riskScore: agentAnalysis.riskScore,
      xaiExplanation: agentAnalysis.xaiExplanation,
      detectedThreats: agentAnalysis.detectedThreats ?? [],
      sandboxJobId,
      evaluationMs,
    };
  }
}
