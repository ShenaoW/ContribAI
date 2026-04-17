"""Minimal async LLM providers used by the AWI workflow."""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from awi_contribai.core.config import LLMConfig
from awi_contribai.core.exceptions import LLMError


class LLMProvider(ABC):
    def __init__(self, config: LLMConfig):
        self.config = config
        self.model = config.model
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Run a single-turn completion."""

    async def close(self):
        """Close provider resources."""


class OpenAIProvider(LLMProvider):
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise LLMError("Install openai to use provider=openai") from exc
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = AsyncOpenAI(**kwargs)

    async def complete(self, prompt: str, *, system: str | None = None, **kwargs) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", self.temperature),
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
        )
        return response.choices[0].message.content or ""

    async def close(self):
        await self._client.close()


class AnthropicProvider(LLMProvider):
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:
            raise LLMError("Install anthropic to use provider=anthropic") from exc
        self._client = AsyncAnthropic(api_key=config.api_key)

    async def complete(self, prompt: str, *, system: str | None = None, **kwargs) -> str:
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=kwargs.get("max_tokens", self.max_tokens),
            temperature=kwargs.get("temperature", self.temperature),
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if hasattr(block, "text"))

    async def close(self):
        await self._client.close()


class GeminiProvider(LLMProvider):
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        try:
            from google import genai
        except ImportError as exc:
            raise LLMError("Install google-genai to use provider=gemini") from exc
        if config.use_vertex:
            self._client = genai.Client(
                vertexai=True,
                project=config.vertex_project,
                location=config.vertex_location,
            )
        else:
            self._client = genai.Client(api_key=config.api_key)

    async def complete(self, prompt: str, *, system: str | None = None, **kwargs) -> str:
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system,
            temperature=kwargs.get("temperature", self.temperature),
            max_output_tokens=kwargs.get("max_tokens", self.max_tokens),
        )
        response = self._client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=config,
        )
        return response.text or ""


class OllamaProvider(LLMProvider):
    async def complete(self, prompt: str, *, system: str | None = None, **kwargs) -> str:
        base_url = (self.config.base_url or "http://localhost:11434").rstrip("/")
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(
                f"{base_url}/api/generate",
                json={"model": self.model, "prompt": full_prompt, "stream": False},
            )
            response.raise_for_status()
            return response.json().get("response", "")


def create_llm_provider(config: LLMConfig) -> LLMProvider:
    if config.provider == "openai":
        return OpenAIProvider(config)
    if config.provider == "anthropic":
        return AnthropicProvider(config)
    if config.provider == "gemini":
        return GeminiProvider(config)
    if config.provider == "ollama":
        return OllamaProvider(config)
    raise LLMError(f"Unsupported LLM provider: {config.provider}")
