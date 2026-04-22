from __future__ import annotations

import os
from typing import Any

from odb_autodba.utils.env_loader import load_project_dotenv


class OpenAIPlannerAssistant:
    def __init__(self, model: str | None = None) -> None:
        load_project_dotenv()
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.api_key = os.getenv("OPENAI_API_KEY")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            return "LLM output unavailable because OPENAI_API_KEY is not configured. Using deterministic Oracle planner fallback."
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            return f"LLM output unavailable due to error: {exc}. Using deterministic Oracle planner fallback."
