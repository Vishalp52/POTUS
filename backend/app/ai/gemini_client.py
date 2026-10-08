"""Async Gemini adapter with a bounded deadline and safe fallback."""
import asyncio
import logging
import math
import os
from typing import Optional
import httpx
from google import genai
from google.genai import types
from app.ai.schemas import GeminiTriage, provider_schema
from app.ai.prompt import PROMPT_VERSION, SYSTEM_TRIAGE_PROMPT, build_triage_prompt
from app.ai.typologies import TypologyMatcher

log = logging.getLogger("potus.gemini")

class GeminiTriageClient:
    def __init__(self, *, client=None, timeout_seconds=None):
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        self.api_mode = os.getenv("GEMINI_API", "generate_content")
        if self.api_mode not in {"generate_content", "interactions"}:
            raise ValueError("GEMINI_API must be generate_content or interactions")
        self.timeout_seconds = float(timeout_seconds if timeout_seconds is not None else os.getenv("GEMINI_TIMEOUT_SECONDS", "12"))
        self.thinking_level = os.getenv("GEMINI_THINKING_LEVEL", "low").lower()
        if self.thinking_level not in {"default", "minimal", "low", "medium", "high"}:
            raise ValueError("GEMINI_THINKING_LEVEL must be default, minimal, low, medium, or high")
        self.max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "2048"))
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("GEMINI_TIMEOUT_SECONDS must be finite and positive")
        if not 256 <= self.max_output_tokens <= 8192:
            raise ValueError("GEMINI_MAX_OUTPUT_TOKENS must be between 256 and 8192")
        self.typologies = TypologyMatcher()
        self.client = client
        if self.client is None and self.api_key:
            self.client = genai.Client(api_key=self.api_key, http_options=types.HttpOptions(
                timeout=max(10_000, int(self.timeout_seconds * 1000)),
                retry_options=types.HttpRetryOptions(attempts=1)))

        if self.client is not None:
            # google-genai 2.28.0 coerces attempts=0 to 1 before the Interactions
            # bridge interprets it as retries. Disable retries on that generated
            # resource explicitly; the pinned-SDK HTTP tests verify one request.
            config = getattr(getattr(self.client.aio, "interactions", None), "sdk_configuration", None)
            if config is not None:
                config.retry_config.strategy = "none"

    def prepare_evidence(self, evidence):
        # Apply the same privacy boundary even when called outside the HTTP engine.
        from app.api.security import sanitize_for_gemini
        packet = sanitize_for_gemini(evidence)
        packet["matched_typologies"] = self.typologies.match(packet)
        packet["prompt_version"] = PROMPT_VERSION
        return packet

    async def triage(self, evidence_packet: dict) -> Optional[GeminiTriage]:
        if self.client is None:
            return None
        try:
            packet = self.prepare_evidence(evidence_packet)
            async with asyncio.timeout(self.timeout_seconds):
                if self.api_mode == "generate_content":
                    response = await self.client.aio.models.generate_content(
                        model=self.model_name,
                        contents=build_triage_prompt(packet),
                        config=types.GenerateContentConfig(
                            system_instruction=SYSTEM_TRIAGE_PROMPT,
                            response_mime_type="application/json",
                            response_json_schema=provider_schema(),
                            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                            temperature=0,
                            max_output_tokens=self.max_output_tokens,
                            thinking_config=None if self.thinking_level == "default" else
                                types.ThinkingConfig(thinking_level=self.thinking_level),
                        ),
                    )
                    candidates = response.candidates or []
                    if not candidates or str(candidates[0].finish_reason).split(".")[-1] != "STOP":
                        return None
                    output = response.text
                else:
                    interaction = await self.client.aio.interactions.create(
                        model=self.model_name,
                        system_instruction=SYSTEM_TRIAGE_PROMPT,
                        input=build_triage_prompt(packet),
                        response_format={"type": "text", "mime_type": "application/json",
                                         "schema": provider_schema()},
                        generation_config={"temperature": 0, "max_output_tokens": self.max_output_tokens,
                            **({"thinking_level": self.thinking_level} if self.thinking_level != "default" else {})},
                        store=False,
                        timeout=max(10.0, self.timeout_seconds),
                    )
                    if getattr(interaction, "status", "completed") != "completed":
                        return None
                    output = interaction.output_text
            if not isinstance(output, str) or len(output) > 16000:
                return None
            triage = GeminiTriage.model_validate_json(output)
            if triage.category == "POTENTIAL_ILLICIT_ACTIVITY" and not any(
                item["category"] == "POTENTIAL_ILLICIT_ACTIVITY" for item in packet["matched_typologies"]
            ):
                # Unsupported AI severity must not become a risk signal.
                log.warning("Gemini classification lacked a corroborated configured typology")
                return None
            return triage
        except TimeoutError:
            raise  # engine records timeout separately from validation/provider failures
        except httpx.TimeoutException as exc:
            raise TimeoutError("Gemini provider timed out") from exc
        except Exception as exc:
            # Never log provider bodies, evidence, credentials or generated text.
            code = getattr(exc, "code", None)
            log.warning("Gemini triage unavailable (%s; HTTP %s)", type(exc).__name__,
                        code if type(code) is int else "unknown")
            return None

    async def aclose(self):
        if self.client is not None:
            await self.client.aio.aclose()
            self.client.close()
            self.client = None
