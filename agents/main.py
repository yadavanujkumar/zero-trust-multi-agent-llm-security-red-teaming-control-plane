from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI(title="LLM Security Agents XAI")

class AnalyzeRequest(BaseModel):
    prompt: str

class AnalyzeResponse(BaseModel):
    risk_score: float
    has_pii: bool
    xai_explanation: str
    requires_sandboxing: bool

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(req: AnalyzeRequest):
    """
    Multi-Agent architecture endpoint.
    In a full deployment, this leverages LangChain/AutoGen to run 
    adversarial detection, intent analysis, and PII scanning.
    """
    prompt_lower = req.prompt.lower()
    
    # Mock: Basic heuristics for boilerplate
    risk_score = 0.1
    has_pii = False
    xai_explanation = "Prompt appears benign."
    requires_sandboxing = False
    
    # Mock PII Detection (SSN/Credit Card patterns)
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', prompt_lower):
        has_pii = True
        risk_score = 0.9
        xai_explanation = "High confidence PII (SSN) detected in payload."
        
    # Mock Jailbreak/Injection Detection
    if "ignore previous instructions" in prompt_lower or "system prompt" in prompt_lower:
        risk_score = 0.95
        xai_explanation = "Detected explicit prompt injection attempt ('Ignore previous instructions')."
        
    # Mock Complex Obfuscation needing Sandbox
    if "base64" in prompt_lower or len(req.prompt) > 2000:
        risk_score = max(risk_score, 0.6)
        requires_sandboxing = True
        xai_explanation = "Payload requires behavioral sandboxing due to length or encoded segments."
        
    return AnalyzeResponse(
        risk_score=risk_score,
        has_pii=has_pii,
        xai_explanation=xai_explanation,
        requires_sandboxing=requires_sandboxing
    )
