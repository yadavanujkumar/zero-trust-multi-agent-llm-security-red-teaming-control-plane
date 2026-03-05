import express from 'express';
import { SecurityService } from './application/SecurityService';
import { SlackNotifier } from './infrastructure/SlackNotifier';
import { K8sSandbox } from './infrastructure/K8sSandbox';
import { AgentClient } from './infrastructure/AgentClient';

const app = express();
app.use(express.json());

const slackNotifier = new SlackNotifier(process.env.SLACK_BOT_TOKEN || '');
const k8sSandbox = new K8sSandbox();
const agentClient = new AgentClient(process.env.AGENT_SERVICE_URL || 'http://localhost:8000');
const securityService = new SecurityService(agentClient, slackNotifier, k8sSandbox);

app.post('/api/v1/intercept', async (req, res) => {
  try {
    const { prompt, user_id } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt required' });
    
    const evaluation = await securityService.evaluatePrompt({ prompt, userId: user_id || 'anonymous' });
    if (evaluation.blocked) {
      return res.status(403).json({
        error: 'Security violation detected',
        reason: evaluation.xaiExplanation
      });
    }
    
    return res.status(200).json({ status: 'allowed' });
  } catch (err) {
    console.error('Interception error:', err);
    return res.status(500).json({ error: 'Internal Control Plane Error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Control Plane API listening on port ${PORT}`);
});