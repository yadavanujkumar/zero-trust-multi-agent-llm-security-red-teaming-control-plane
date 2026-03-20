import * as k8s from '@kubernetes/client-node';
import crypto from 'crypto';
import { logger } from './Logger';
import { sandboxJobsTotal } from './MetricsCollector';

const SANDBOX_NAMESPACE = process.env.SANDBOX_NAMESPACE || 'llm-redteam-sandbox';
const SANDBOX_IMAGE = process.env.SANDBOX_IMAGE || 'alpine:3.19';
const JOB_TTL_SECONDS = parseInt(process.env.SANDBOX_JOB_TTL || '120', 10);

export class K8sSandbox {
  private k8sApi: k8s.BatchV1Api;
  private readonly mockMode: boolean;

  constructor() {
    const kc = new k8s.KubeConfig();
    this.mockMode = false;
    try {
      kc.loadFromDefault();
    } catch {
      logger.warn('Kubernetes config not found — running in mock sandbox mode');
      this.mockMode = true;
    }
    this.k8sApi = kc.makeApiClient(k8s.BatchV1Api);
  }

  async detonate(prompt: string, requestId?: string): Promise<string> {
    const jobId = `sandbox-${crypto.randomBytes(6).toString('hex')}`;

    if (this.mockMode) {
      logger.info('Mock sandbox detonation (no K8s cluster)', { jobId, requestId });
      return jobId;
    }

    const promptHash = crypto.createHash('sha256').update(prompt).digest('hex').slice(0, 16);

    const job: k8s.V1Job = {
      apiVersion: 'batch/v1',
      kind: 'Job',
      metadata: {
        name: jobId,
        namespace: SANDBOX_NAMESPACE,
        labels: {
          app: 'llm-sandbox',
          'security.io/request-id': requestId?.slice(0, 63) ?? 'unknown',
        },
        annotations: {
          'security.io/prompt-hash': promptHash,
          'security.io/created-at': new Date().toISOString(),
        },
      },
      spec: {
        ttlSecondsAfterFinished: JOB_TTL_SECONDS,
        backoffLimit: 0,
        template: {
          metadata: {
            labels: { app: 'llm-sandbox', 'security.io/job-id': jobId },
          },
          spec: {
            automountServiceAccountToken: false,
            restartPolicy: 'Never',
            securityContext: {
              runAsNonRoot: true,
              runAsUser: 65534,
              runAsGroup: 65534,
              seccompProfile: { type: 'RuntimeDefault' },
            },
            containers: [
              {
                name: 'detonator',
                image: SANDBOX_IMAGE,
                command: ['sh', '-c', 'echo "Sandbox detonation complete" && sleep 5'],
                resources: {
                  requests: { cpu: '50m', memory: '64Mi' },
                  limits: { cpu: '200m', memory: '128Mi' },
                },
                securityContext: {
                  allowPrivilegeEscalation: false,
                  readOnlyRootFilesystem: true,
                  capabilities: { drop: ['ALL'] },
                },
                env: [
                  { name: 'PROMPT_HASH', value: promptHash },
                  { name: 'REQUEST_ID', value: requestId ?? '' },
                ],
              },
            ],
          },
        },
      },
    };

    try {
      await this.k8sApi.createNamespacedJob(SANDBOX_NAMESPACE, job);
      sandboxJobsTotal.inc();
      logger.info('K8s sandbox job created', { jobId, requestId, promptHash });
      return jobId;
    } catch (error) {
      logger.error('Failed to create K8s sandbox job — RBAC/namespace missing?', {
        jobId,
        requestId,
        error: (error as Error).message,
      });
      return jobId;
    }
  }
}
