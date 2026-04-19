from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

from src.config_utils import load_config
from src.llm_utils import load_prompt, call_llm_json


def _safe_list_str(x: Any) -> List[str]:
    if isinstance(x, list):
        return [str(i) for i in x]
    return []


def _safe_float(x: Any, default: float = 0.5) -> float:
    try:
        v = float(x)
        if v < 0:
            return 0.0
        if v > 1:
            return 1.0
        return v
    except Exception:
        return default


def _normalize_verdict(x: Any) -> str:
    x = str(x).strip().lower()
    if x in {"support", "uncertain", "unsupported"}:
        return x
    if "support" in x and "un" not in x:
        return "support"
    if "uncertain" in x or "partial" in x:
        return "uncertain"
    return "unsupported"


def build_assistant_user_prompt(
    community_record: Dict[str, Any],
    question: str,
) -> str:
    meta = community_record.get("metadata", {})
    anomaly = community_record.get("anomaly_contexts", {})
    boundary = community_record.get("boundary_cues", {})
    traces = community_record.get("archived_traces", [])

    payload = {
        "task": "Trace verification for one community during APT investigation",
        "question_from_lead": question,
        "community_metadata": {
            "global_id": meta.get("global_id"),
            "community_id": meta.get("community_id"),
            "pg_id": meta.get("pg_id"),
            "time_span": meta.get("time_span"),
        },
        "anomaly_contexts": {
            "suspicious_nodes": anomaly.get("suspicious_nodes", []),
            "node_scores": anomaly.get("node_scores", {}),
            "n_hop_neighbors": anomaly.get("n_hop_neighbors", {}),
            "candidate_attack_subchains": anomaly.get("candidate_attack_subchains", []),
            "anomaly_density": anomaly.get("anomaly_density"),
            "bridge_intensity": anomaly.get("bridge_intensity"),
        },
        "boundary_cues": {
            "matched_anchor_nodes": boundary.get("matched_anchor_nodes", []),
            "split_boundary_markers": boundary.get("split_boundary_markers", []),
        },
        "archived_traces": traces[:20],  # 首版控制长度，避免 token 过长
        "output_requirement": {
            "format": "json",
            "fields": [
                "verdict",
                "confidence",
                "evidence_snippets",
                "unsupported_parts",
            ],
            "verdict_candidates": ["support", "uncertain", "unsupported"],
        },
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)


def verify_trace_for_community(
    community_record: Dict[str, Any],
    question: str,
) -> Dict[str, Any]:
    """
    LLM-based Assistant Agent:
    - no long-term memory
    - reads only current community evidence + archived traces + lead question
    - returns a concise structured verification report
    """
    cfg = load_config()
    prompt_dir = Path(cfg["paths"]["prompt_dir"])
    system_prompt = load_prompt(prompt_dir / "assistant_system.txt")
    user_prompt = build_assistant_user_prompt(community_record, question)

    raw = call_llm_json(system_prompt=system_prompt, user_prompt=user_prompt)

    report = {
        "community_global_id": community_record["metadata"]["global_id"],
        "community_id": community_record["metadata"]["community_id"],
        "question": question,
        "verdict": _normalize_verdict(raw.get("verdict", "unsupported")),
        "confidence": _safe_float(raw.get("confidence", 0.5)),
        "evidence_snippets": _safe_list_str(raw.get("evidence_snippets", []))[:8],
        "unsupported_parts": _safe_list_str(raw.get("unsupported_parts", []))[:8],
    }

    return report