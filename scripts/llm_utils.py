from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from openai import OpenAI

from src.config_utils import load_config


def load_prompt(prompt_path: str | Path) -> str:
    path = Path(prompt_path)
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {path}")
    return path.read_text(encoding="utf-8").strip()


def build_client() -> tuple[OpenAI, Dict[str, Any]]:
    cfg = load_config()
    llm_cfg = cfg["llm"]

    api_key_env = llm_cfg["api_key_env"]
    api_key = os.getenv(api_key_env)
    if not api_key:
        raise RuntimeError(
            f"Environment variable {api_key_env} is not set. "
            f"Please export your OpenAI API key first."
        )

    api_base = llm_cfg.get("api_base", "") or None
    client = OpenAI(api_key=api_key, base_url=api_base)
    return client, cfg


def call_llm(system_prompt: str, user_prompt: str) -> str:
    client, cfg = build_client()
    llm_cfg = cfg["llm"]

    resp = client.chat.completions.create(
        model=llm_cfg["model"],
        temperature=float(llm_cfg.get("temperature", 0.2)),
        max_tokens=int(llm_cfg.get("max_tokens", 2048)),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return resp.choices[0].message.content or ""


def call_llm_json(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    text = call_llm(system_prompt, user_prompt).strip()


    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass


    if "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if part.startswith("json"):
                part = part[4:].strip()
            try:
                return json.loads(part)
            except json.JSONDecodeError:
                continue

    raise ValueError(f"LLM did not return valid JSON:\n{text}")