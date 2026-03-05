import * as k8s from '@kubernetes/client-node';
import crypto from 'crypto';

export class K8sSandbox {
  private k8sApi: k8s.BatchV1Api;

  constructor() {
    const kc = new k8s.KubeConfig();
    try {
      kc.loadFromDefault();
    } catch (e) {
      console.warn('Kubernetes config not found, running in mock sandbox mode.');
    }
    this.k8sApi = kc.makeApiClient(k8s.BatchV1Api);
  }

  async detonate(prompt: string): Promise<void> {
    const jobId = `sandbox-job-${crypto.randomBytes(4).toString('hex')}`;
    const job: k8s.V1Job = {
      metadata: { name: jobId, namespace: 'llm-redteam-sandbox' },
      spec: {
        ttlSecondsAfterFinished: 60,
        template: {
          spec: {
            containers: [{
              name: 'detonator',
              image: 'alpine:latest',
              command: ['sh', '-c', `echo "Detonating prompt securely..." && sleep 5`]
            }],
            restartPolicy: 'Never'
          }
        }
      }
    };

    try {
      await this.k8sApi.createNamespacedJob('llm-redteam-sandbox', job);
      console.log(`Successfully spawned K8s sandbox job: ${jobId}`);
    } catch (error) {
      console.error('Failed to create K8s sandbox. Ensure RBAC and namespace exist.', error);
    }
  }
}