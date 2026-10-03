import os
from typing import Optional
from google import genai
from app.ai.schemas import GeminiTriage
from app.ai.prompt import build_triage_prompt

class GeminiTriageClient:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    async def triage(self, evidence_packet: dict) -> Optional[GeminiTriage]:
        if not self.client:
            return None

        prompt = build_triage_prompt(evidence_packet)

        try:
            interaction = self.client.interactions.create(
                model=self.model_name,
                input=prompt,
                response_format={
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": GeminiTriage.model_json_schema()
                }
            )
            return GeminiTriage.model_validate_json(interaction.output_text)
        except Exception as e:
            print(f"Gemini Triage Error (fallback path active): {e}")
            return None