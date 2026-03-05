import { WebClient } from '@slack/web-api';

export class SlackNotifier {
  private client: WebClient;

  constructor(token: string) {
    this.client = new WebClient(token);
  }

  async sendAlert(data: { userId: string; riskScore: number; explanation: string }): Promise<void> {
    try {
      // In production, configure channel dynamically or via env
      const channel = '#security-alerts';
      await this.client.chat.postMessage({
        channel,
        text: `*Security Alert: High Risk LLM Prompt Intercepted*
*User:* ${data.userId}
*Risk Score:* ${data.riskScore}
*XAI Explanation:* ${data.explanation}

[1-Click Remediation Options Available in Dashboard]`,
      });
    } catch (error) {
      console.error('Failed to dispatch Slack alert', error);
    }
  }
}