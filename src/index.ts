import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { SecurityService } from './application/SecurityService';
import { SlackNotifier } from './infrastructure/SlackNotifier';
import { K8sSandbox } from './infrastructure/K8sSandbox';
import { AgentClient } from './infrastructure/AgentClient';
import { RedisCache } from './infrastructure/RedisCache';
import { logger } from './infrastructure/Logger';
import { register, httpRequestsTotal } from './infrastructure/MetricsCollector';
import { SecurityDecision } from './domain/PromptEvaluation';

// ── Input validation schema ────────────────────────────────────────────────
const InterceptSchema = z.object({
  prompt: z.string().min(1).max(16_000),
  user_id: z.string().max(256).optional(),
  session_id: z.string().max(256).optional(),
});

// ── App bootstrap ──────────────────────────────────────────────────────────
const app = express();

// Security headers
app.use(helmet());
app.use(express.json({ limit: '64kb' }));

// Correlation ID middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  req.headers['x-request-id'] = req.headers['x-request-id'] ?? uuidv4();
  next();
});

// HTTP metrics middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  res.on('finish', () => {
    httpRequestsTotal.inc({
      method: req.method,
      route: req.route?.path ?? req.path,
      status_code: res.statusCode,
    });
  });
  next();
});

// Rate limiting — 100 req/min per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please retry later' },
});
app.use('/api/', limiter);

// ── Services ───────────────────────────────────────────────────────────────
const cache = new RedisCache(process.env.REDIS_URL || 'redis://localhost:6379');
const slackNotifier = new SlackNotifier(process.env.SLACK_BOT_TOKEN || '');
const k8sSandbox = new K8sSandbox();
const agentClient = new AgentClient(
  process.env.AGENT_SERVICE_URL || 'http://localhost:8000',
);
const securityService = new SecurityService(agentClient, slackNotifier, k8sSandbox, cache);

// ── Routes ─────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/intercept
 * Evaluates an LLM prompt against all security policies.
 */
app.post('/api/v1/intercept', async (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;

  const parsed = InterceptSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid request body', details: parsed.error.issues });
  }

  const { prompt, user_id, session_id } = parsed.data;

  try {
    const evaluation = await securityService.evaluatePrompt({
      prompt,
      userId: user_id ?? 'anonymous',
      requestId,
      sessionId: session_id,
      clientIp: req.ip,
    });

    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Risk-Score', evaluation.riskScore.toFixed(4));
    res.setHeader('X-Security-Decision', evaluation.decision);

    if (evaluation.blocked) {
      return res.status(403).json({
        error: 'Security policy violation — prompt blocked',
        requestId,
        decision: SecurityDecision.BLOCK,
        riskScore: evaluation.riskScore,
        reason: evaluation.xaiExplanation,
        detectedThreats: evaluation.detectedThreats,
      });
    }

    return res.status(200).json({
      status: 'allowed',
      requestId,
      decision: evaluation.decision,
      riskScore: evaluation.riskScore,
      ...(evaluation.sandboxJobId ? { sandboxJobId: evaluation.sandboxJobId } : {}),
      evaluationMs: evaluation.evaluationMs,
    });
  } catch (err) {
    logger.error('Unhandled interception error', { requestId, error: (err as Error).message });
    return res.status(500).json({ error: 'Internal Control Plane Error', requestId });
  }
});

/** GET /health — liveness probe */
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

/** GET /ready — readiness probe (checks Redis) */
app.get('/ready', (_req: Request, res: Response) => {
  const redisOk = cache.isReady();
  const status = redisOk ? 200 : 503;
  res.status(status).json({
    status: redisOk ? 'ready' : 'not_ready',
    dependencies: { redis: redisOk ? 'ok' : 'unavailable' },
  });
});

/** GET /metrics — Prometheus scrape endpoint */
app.get('/metrics', async (_req: Request, res: Response) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ── Global error handler ───────────────────────────────────────────────────
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  const requestId = req.headers['x-request-id'] as string;
  logger.error('Unhandled Express error', { requestId, error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal Server Error', requestId });
});

// ── Server lifecycle ───────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);
const server = app.listen(PORT, () => {
  logger.info(`Control Plane API listening`, { port: PORT, env: process.env.NODE_ENV ?? 'development' });
});

const shutdown = async (signal: string) => {
  logger.info(`${signal} received — shutting down gracefully`);
  server.close(async () => {
    await cache.disconnect();
    logger.info('Server closed');
    process.exit(0);
  });
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10_000).unref();
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export { app };
