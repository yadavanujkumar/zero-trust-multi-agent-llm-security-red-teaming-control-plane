import { WebClient } from '@slack/web-api';
import { logger } from './Logger';
import { ThreatType } from '../domain/PromptEvaluation';

export interface AlertPayload {
  requestId: string;
  userId: string;
  riskScore: number;
  explanation: string;
  detectedThreats?: ThreatType[];
  clientIp?: string;
  sandboxJobId?: string;
}

export class SlackNotifier {
  private client: WebClient;
  private readonly channel: string;

  constructor(token: string) {
    this.client = new WebClient(token, { retryConfig: { retries: 3 } });
    this.channel = process.env.SLACK_CHANNEL || '#security-alerts';
  }

  async sendAlert(data: AlertPayload): Promise<void> {
    const riskPercent = (data.riskScore * 100).toFixed(1);
    const riskEmoji = data.riskScore >= 0.9 ? ':red_circle:' : ':large_yellow_circle:';
    const threats = data.detectedThreats?.join(', ') || 'Unknown';
    const dashboardUrl = process.env.DASHBOARD_URL || 'https://security.internal/dashboard';

    try {
      await this.client.chat.postMessage({
        channel: this.channel,
        text: `${riskEmoji} *Security Alert: High-Risk LLM Prompt Intercepted* — User: ${data.userId}`,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `${riskEmoji} Security Alert: Prompt Blocked`,
              emoji: true,
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Request ID:*\n\`${data.requestId}\`` },
              { type: 'mrkdwn', text: `*User ID:*\n${data.userId}` },
              { type: 'mrkdwn', text: `*Risk Score:*\n${riskPercent}%` },
              { type: 'mrkdwn', text: `*Detected Threats:*\n${threats}` },
              ...(data.clientIp
                ? [{ type: 'mrkdwn' as const, text: `*Client IP:*\n${data.clientIp}` }]
                : []),
              ...(data.sandboxJobId
                ? [{ type: 'mrkdwn' as const, text: `*Sandbox Job:*\n\`${data.sandboxJobId}\`` }]
                : []),
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*XAI Explanation:*\n>${data.explanation}`,
            },
          },
          { type: 'divider' },
          {
            type: 'actions',
            elements: [
              {
                type: 'button',
                text: { type: 'plain_text', text: '🔍 View in Dashboard', emoji: true },
                url: `${dashboardUrl}?requestId=${data.requestId}`,
                style: 'primary',
              },
              {
                type: 'button',
                text: { type: 'plain_text', text: '🚫 Revoke User Session', emoji: true },
                url: `${dashboardUrl}/revoke?userId=${data.userId}`,
                style: 'danger',
              },
            ],
          },
        ],
      });
      logger.info('Slack security alert dispatched', { requestId: data.requestId, userId: data.userId });
    } catch (error) {
      logger.error('Failed to dispatch Slack alert', {
        requestId: data.requestId,
        error: (error as Error).message,
      });
    }
  }
}
