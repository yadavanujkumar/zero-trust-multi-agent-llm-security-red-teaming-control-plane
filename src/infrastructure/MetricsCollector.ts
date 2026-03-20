import promClient from 'prom-client';

const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

export const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

export const promptEvaluationDuration = new promClient.Histogram({
  name: 'prompt_evaluation_duration_seconds',
  help: 'Time taken to evaluate a prompt (seconds)',
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register],
});

export const riskScoreHistogram = new promClient.Histogram({
  name: 'prompt_risk_score',
  help: 'Distribution of risk scores for evaluated prompts',
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
  registers: [register],
});

export const blockedPromptsTotal = new promClient.Counter({
  name: 'blocked_prompts_total',
  help: 'Total number of blocked prompts',
  labelNames: ['reason'],
  registers: [register],
});

export const sandboxJobsTotal = new promClient.Counter({
  name: 'sandbox_jobs_total',
  help: 'Total number of K8s sandbox jobs spawned',
  registers: [register],
});

export const agentServiceErrors = new promClient.Counter({
  name: 'agent_service_errors_total',
  help: 'Total number of agent service call failures',
  registers: [register],
});

export { register };
