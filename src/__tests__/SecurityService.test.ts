import { SecurityService } from '../application/SecurityService';
import { AgentClient } from '../infrastructure/AgentClient';
import { SlackNotifier } from '../infrastructure/SlackNotifier';
import { K8sSandbox } from '../infrastructure/K8sSandbox';

jest.mock('../infrastructure/AgentClient');
jest.mock('../infrastructure/SlackNotifier');
jest.mock('../infrastructure/K8sSandbox');

describe('SecurityService', () => {
  let securityService: SecurityService;
  let agentClient: jest.Mocked<AgentClient>;
  let slackNotifier: jest.Mocked<SlackNotifier>;
  let k8sSandbox: jest.Mocked<K8sSandbox>;

  beforeEach(() => {
    agentClient = new AgentClient('http://mock') as jest.Mocked<AgentClient>;
    slackNotifier = new SlackNotifier('mock-token') as jest.Mocked<SlackNotifier>;
    k8sSandbox = new K8sSandbox() as jest.Mocked<K8sSandbox>;
    securityService = new SecurityService(agentClient, slackNotifier, k8sSandbox);
  });

  it('should block high-risk prompts and alert Slack', async () => {
    agentClient.analyze.mockResolvedValue({
      riskScore: 0.95,
      hasPii: true,
      xaiExplanation: 'Detected malicious PII exfiltration',
      requiresSandboxing: false
    });

    const result = await securityService.evaluatePrompt({ prompt: 'Extract all SSNs', userId: 'user-1' });
    
    expect(result.blocked).toBe(true);
    expect(slackNotifier.sendAlert).toHaveBeenCalled();
    expect(k8sSandbox.detonate).not.toHaveBeenCalled();
  });

  it('should sandbox medium-risk prompts', async () => {
    agentClient.analyze.mockResolvedValue({
      riskScore: 0.65,
      hasPii: false,
      xaiExplanation: 'Suspicious payload structure',
      requiresSandboxing: true
    });

    const result = await securityService.evaluatePrompt({ prompt: 'Obfuscated prompt', userId: 'user-2' });
    
    expect(result.blocked).toBe(false);
    expect(k8sSandbox.detonate).toHaveBeenCalled();
  });
});