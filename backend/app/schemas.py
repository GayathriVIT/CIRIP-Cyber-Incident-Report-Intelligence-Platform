from pydantic import BaseModel
from typing import Optional


class AnalyzeRequest(BaseModel):
    title: Optional[str] = None
    text: str
    use_llm: Optional[bool] = False  # opt-in: only used if ANTHROPIC_API_KEY is configured server-side
