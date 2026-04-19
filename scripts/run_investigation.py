from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any, Set, Optional

from src.config_utils import load_config
from src.llm_utils import load_prompt, call_llm_json
from assistant_agent import verify_trace_for_community


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def build_record_map(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {r["metadata"]["global_id"]: r for r in records}


def build_outgoing_edges(edges: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges:
        s = e["source_community"]
        out.setdefault(s, []).append(e)
    return out


def extract_stage_hints(record: Dict[str, Any]) -> List[str]:
    suspicious_nodes = " ".join(record.get("anomaly_contexts", {}).get("suspicious_nodes", [])).lower()
    traces = " ".join(record.get("archived_traces", [])).lower()
    text = suspicious_nodes + " " + traces

    stages = []
    if any(k in text for k in ["firefox", "update.bin", "203.0.113.50"]):
        stages.append("C")
    if any(k in text for k in ["198.51.100.23", "dns_query", "syncsvc"]):
        stages.append("C&C")
    if any(k in text for k in ["passwd", "hostname", "route", "known_hosts", "scan_internal"]):
        stages.append("IR")
    if any(k in text for k in ["cron", "chmod", ".pid"]):
        stages.append("PE")
    if any(k in text for k in ["id_rsa", "host_targets", "10.10.20"]):
        stages.append("LM")
    if any(k in text for k in ["finance_q2", "hr_roster", "archive_01.tar", "45.77.10.8"]):
        stages.append("MP")

    return sorted(list(set(stages)))


def score_candidate(record: Dict[str, Any], edge: Dict[str, Any] | None) -> float:
    anomaly = record.get("anomaly_contexts", {})
    density = float(anomaly.get("anomaly_density", 0.0))
    suspicious_count = len(anomaly.get("suspicious_nodes", []))
    subchains = len(anomaly.get("candidate_attack_subchains", []))
    anchors = len(record.get("boundary_cues", {}).get("matched_anchor_nodes", []))
    bridge_intensity = anomaly.get("bridge_intensity", 0) or 0

    score = 0.0
    score += density * 5.0
    score += min(suspicious_count, 8) * 0.35
    score += min(subchains, 4) * 0.45
    score += min(anchors, 3) * 0.60
    score += min(bridge_intensity, 6) * 0.15

    if edge is not None:
        dep_types = edge.get("dependency_type", [])
        if "anchor_based" in dep_types:
            score += 1.0
        if "entity_alignment" in dep_types:
            score += 0.6
        if "temporal_continuation" in dep_types:
            score += 1.2

        score += min(len(edge.get("matched_anchor_nodes", [])), 3) * 0.5
        score += min(len(edge.get("aligned_entities", [])), 3) * 0.3
        score += min(len(edge.get("shared_context_entities", [])), 5) * 0.15

    return score


def retrieve_candidates(
    current_gid: str,
    outgoing_map: Dict[str, List[Dict[str, Any]]],
    record_map: Dict[str, Dict[str, Any]],
    seen: Set[str],
) -> List[Dict[str, Any]]:
    cands = []
    for e in outgoing_map.get(current_gid, []):
        tgt = e["target_community"]
        if tgt in seen:
            continue
        if tgt not in record_map:
            continue
        rec = record_map[tgt]
        cands.append(
            {
                "edge": e,
                "record": rec,
                "score": score_candidate(rec, e),
            }
        )

    cands.sort(key=lambda x: -x["score"])
    return cands[:5]


def infer_gap_between(backbone: List[str], record_map: Dict[str, Dict[str, Any]]) -> List[str]:
    all_stages = []
    for gid in backbone:
        all_stages.extend(extract_stage_hints(record_map[gid]))
    all_stages = sorted(list(set(all_stages)))

    expected_order = ["C", "C&C", "IR", "PE", "LM", "MP"]
    observed_idx = [expected_order.index(s) for s in all_stages if s in expected_order]

    gaps = []
    if observed_idx:
        min_i = min(observed_idx)
        max_i = max(observed_idx)
        for i in range(min_i, max_i + 1):
            if expected_order[i] not in all_stages:
                gaps.append(expected_order[i])

    if "C" not in all_stages:
        gaps.append("C")
    if "C&C" not in all_stages:
        gaps.append("C&C")

    return sorted(list(set(gaps)))


def maybe_find_bridge_candidates(
    backbone: List[str],
    edges: List[Dict[str, Any]],
    record_map: Dict[str, Dict[str, Any]],
    seen: Set[str],
) -> List[Dict[str, Any]]:
    backbone_set = set(backbone)
    candidates: Dict[str, float] = {}

    for e in edges:
        s = e["source_community"]
        t = e["target_community"]
        if s in backbone_set and t not in backbone_set and t not in seen:
            rec = record_map.get(t)
            if rec is None:
                continue
            anomaly = rec.get("anomaly_contexts", {})
            suspicious = len(anomaly.get("suspicious_nodes", []))
            density = float(anomaly.get("anomaly_density", 0.0))
            if suspicious >= 2 and density >= 0.10:
                candidates[t] = candidates.get(t, 0.0) + score_candidate(rec, e)

    ranked = sorted(candidates.items(), key=lambda x: -x[1])[:5]
    out = []
    for gid, score in ranked:
        rec = record_map[gid]
        out.append(
            {
                "global_id": gid,
                "score": score,
                "time_span": rec["metadata"]["time_span"],
                "suspicious_nodes": rec.get("anomaly_contexts", {}).get("suspicious_nodes", [])[:8],
                "candidate_attack_subchains": rec.get("anomaly_contexts", {}).get("candidate_attack_subchains", [])[:4],
            }
        )
    return out


def prune_final_backbone(final_backbone: List[str], record_map: Dict[str, Dict[str, Any]], retain_counter: Counter) -> List[str]:
    kept = []
    for gid in final_backbone:
        rec = record_map[gid]
        anomaly = rec.get("anomaly_contexts", {})
        suspicious = len(anomaly.get("suspicious_nodes", []))
        density = float(anomaly.get("anomaly_density", 0.0))
        subchains = len(anomaly.get("candidate_attack_subchains", []))

        if retain_counter[gid] >= 2:
            kept.append(gid)
        elif suspicious >= 4 and density >= 0.15 and subchains >= 1:
            kept.append(gid)

    if len(kept) < 8:
        ranked = sorted(
            final_backbone,
            key=lambda g: (
                -retain_counter[g],
                -len(record_map[g].get("anomaly_contexts", {}).get("suspicious_nodes", [])),
                -float(record_map[g].get("anomaly_contexts", {}).get("anomaly_density", 0.0)),
                g,
            ),
        )
        kept = ranked[: min(30, len(ranked))]

    ordered = []
    seen = set()
    for gid in final_backbone:
        if gid in kept and gid not in seen:
            ordered.append(gid)
            seen.add(gid)
    return ordered


def summarize_record_for_prompt(record: Dict[str, Any]) -> Dict[str, Any]:
    anomaly = record.get("anomaly_contexts", {})
    boundary = record.get("boundary_cues", {})

    return {
        "global_id": record["metadata"]["global_id"],
        "community_id": record["metadata"]["community_id"],
        "pg_id": record["metadata"]["pg_id"],
        "time_span": record["metadata"]["time_span"],
        "suspicious_nodes": anomaly.get("suspicious_nodes", [])[:10],
        "candidate_attack_subchains": anomaly.get("candidate_attack_subchains", [])[:5],
        "anomaly_density": anomaly.get("anomaly_density", 0.0),
        "bridge_intensity": anomaly.get("bridge_intensity", 0),
        "matched_anchor_nodes": boundary.get("matched_anchor_nodes", [])[:10],
        "split_boundary_markers": boundary.get("split_boundary_markers", [])[:10],
        "stage_hints": extract_stage_hints(record),
        "archived_traces_preview": record.get("archived_traces", [])[:6],
    }


def build_lead_user_prompt(
    current_record: Dict[str, Any],
    current_backbone: List[str],
    candidate_payloads: List[Dict[str, Any]],
    bridge_payloads: List[Dict[str, Any]],
    unresolved_gaps: List[str],
    step_index: int,
) -> str:
    packet = {
        "task": "Choose the next investigation action for one COI-centered APT investigation step.",
        "constraints": {
            "choose_exactly_one_action": True,
            "allowed_actions": ["retain", "discard", "bridge", "verify_trace", "terminate"],
            "use_only_provided_evidence": True,
            "do_not_invent_new_candidates": True,
        },
        "step_index": step_index,
        "current_record": summarize_record_for_prompt(current_record),
        "current_backbone": current_backbone,
        "current_unresolved_gaps": unresolved_gaps,
        "candidate_communities": candidate_payloads,
        "bridge_candidates": bridge_payloads,
        "output_schema": {
            "action": "one of retain/discard/bridge/verify_trace/terminate",
            "selected_candidate": "community global id or null",
            "reason": "short evidence-grounded reason",
            "unresolved_gap": "string or null",
            "confidence": "float between 0 and 1",
        },
    }
    return json.dumps(packet, indent=2, ensure_ascii=False)


def _normalize_action(x: Any) -> str:
    x = str(x).strip().lower()
    allowed = {"retain", "discard", "bridge", "verify_trace", "terminate"}
    if x in allowed:
        return x
    if "verify" in x:
        return "verify_trace"
    if "retain" in x or "keep" in x:
        return "retain"
    if "bridge" in x:
        return "bridge"
    if "terminate" in x or "stop" in x:
        return "terminate"
    return "discard"


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


def decide_action_with_llm(
    system_prompt: str,
    current_record: Dict[str, Any],
    current_backbone: List[str],
    candidates: List[Dict[str, Any]],
    bridge_candidates: List[Dict[str, Any]],
    unresolved_gaps: List[str],
    step_index: int,
) -> Dict[str, Any]:
    candidate_payloads = []
    for item in candidates:
        rec = item["record"]
        edge = item["edge"]
        candidate_payloads.append(
            {
                "global_id": rec["metadata"]["global_id"],
                "score": item["score"],
                "dependency_type": edge.get("dependency_type", []),
                "matched_anchor_nodes": edge.get("matched_anchor_nodes", []),
                "aligned_entities": edge.get("aligned_entities", []),
                "shared_context_entities": edge.get("shared_context_entities", []),
                "record_summary": summarize_record_for_prompt(rec),
            }
        )

    user_prompt = build_lead_user_prompt(
        current_record=current_record,
        current_backbone=current_backbone,
        candidate_payloads=candidate_payloads,
        bridge_payloads=bridge_candidates,
        unresolved_gaps=unresolved_gaps,
        step_index=step_index,
    )

    raw = call_llm_json(system_prompt=system_prompt, user_prompt=user_prompt)

    return {
        "action": _normalize_action(raw.get("action", "discard")),
        "selected_candidate": raw.get("selected_candidate"),
        "reason": str(raw.get("reason", "")),
        "unresolved_gap": None if raw.get("unresolved_gap") in [None, "", "null"] else str(raw.get("unresolved_gap")),
        "confidence": _safe_float(raw.get("confidence", 0.5)),
    }


def main() -> None:
    cfg = load_config()

    cdg_root = Path(cfg["paths"]["cdg_dir"])
    memory_path = Path(cfg["investigation"]["lead_memory_file"])
    out_dir = Path(cfg["paths"]["investigation_dir"])
    prompt_dir = Path(cfg["paths"]["prompt_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    lead_system_prompt = load_prompt(prompt_dir / "lead_system.txt")

    coi_ranked = load_json(cdg_root / "coi_ranked.json")
    edges = load_json(cdg_root / "cdg_edges.json")
    records = load_json(cdg_root / "cdg_records_updated.json")

    memory = load_json(memory_path)
    record_map = build_record_map(records)
    outgoing_map = build_outgoing_edges(edges)

    max_rounds = int(cfg["investigation"]["max_rounds"])

    coi_queue_all = [x["global_id"] for x in coi_ranked if x.get("is_coi", False)]
    coi_queue = coi_queue_all[:40]

    memory["coi_queue"] = coi_queue

    final_backbone: List[str] = []
    final_reasoning: List[Dict[str, Any]] = []
    final_verified_reports: List[Dict[str, Any]] = []
    retain_counter: Counter = Counter()

    print("[INFO] run_investigation.py starting...")
    print(f"[INFO] COIs available: {len(coi_queue_all)}")
    print(f"[INFO] COIs actually investigated: {len(coi_queue)}")
    print(f"[INFO] Max rounds per COI: {max_rounds}")

    max_backbone_len_per_coi = 5

    for coi_gid in coi_queue:
        if coi_gid not in record_map:
            continue

        current_backbone = [coi_gid]
        seen = set(current_backbone)
        memory["current_coi"] = coi_gid
        memory["status"] = "investigating"

        for t in range(max_rounds):
            if len(current_backbone) >= max_backbone_len_per_coi:
                final_reasoning.append(
                    {
                        "coi": coi_gid,
                        "step": t + 1,
                        "action": "terminate",
                        "selected": None,
                        "reason": "Reached max backbone length per COI.",
                    }
                )
                break

            current_gid = current_backbone[-1]
            current_record = record_map[current_gid]
            current_unresolved_gaps = infer_gap_between(current_backbone, record_map)

            candidates = retrieve_candidates(
                current_gid=current_gid,
                outgoing_map=outgoing_map,
                record_map=record_map,
                seen=seen,
            )
            bridge_candidates = maybe_find_bridge_candidates(current_backbone, edges, record_map, seen)

            if not candidates and not bridge_candidates:
                final_reasoning.append(
                    {
                        "coi": coi_gid,
                        "step": t + 1,
                        "action": "terminate",
                        "selected": None,
                        "reason": "No more supported candidates or bridge candidates.",
                    }
                )
                break

            lead_decision = decide_action_with_llm(
                system_prompt=lead_system_prompt,
                current_record=current_record,
                current_backbone=current_backbone,
                candidates=candidates,
                bridge_candidates=bridge_candidates,
                unresolved_gaps=current_unresolved_gaps,
                step_index=t + 1,
            )

            action = lead_decision["action"]
            selected_candidate = lead_decision["selected_candidate"]
            confidence = lead_decision["confidence"]
            reason = lead_decision["reason"] or "LLM decision without detailed reason."

            # safety fallback: if selected candidate invalid, choose top available candidate if needed
            valid_candidate_ids = {c["record"]["metadata"]["global_id"] for c in candidates}
            valid_bridge_ids = {b["global_id"] for b in bridge_candidates}

            if action in {"retain", "verify_trace"} and selected_candidate not in valid_candidate_ids:
                if candidates:
                    selected_candidate = candidates[0]["record"]["metadata"]["global_id"]
                else:
                    action = "terminate"

            if action == "bridge" and selected_candidate not in valid_bridge_ids:
                if bridge_candidates:
                    selected_candidate = bridge_candidates[0]["global_id"]
                else:
                    action = "terminate"

            if action == "retain":
                cand_item = next((c for c in candidates if c["record"]["metadata"]["global_id"] == selected_candidate), None)
                if cand_item is None:
                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "terminate",
                            "selected": None,
                            "reason": "LLM selected invalid retain target.",
                        }
                    )
                    break

                cand_gid = cand_item["record"]["metadata"]["global_id"]
                current_backbone.append(cand_gid)
                seen.add(cand_gid)
                retain_counter[cand_gid] += 1

                final_reasoning.append(
                    {
                        "coi": coi_gid,
                        "step": t + 1,
                        "action": "retain",
                        "selected": cand_gid,
                        "reason": reason,
                        "confidence": confidence,
                        "dependency_type": cand_item["edge"].get("dependency_type", []),
                    }
                )

            elif action == "verify_trace":
                cand_item = next((c for c in candidates if c["record"]["metadata"]["global_id"] == selected_candidate), None)
                if cand_item is None:
                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "terminate",
                            "selected": None,
                            "reason": "LLM selected invalid verify target.",
                        }
                    )
                    break

                cand_record = cand_item["record"]
                cand_gid = cand_record["metadata"]["global_id"]

                question = f"Does this community provide valid continuation for backbone after {current_gid}?"
                report = verify_trace_for_community(cand_record, question)
                final_verified_reports.append(report)

                if report["verdict"] == "support" and report["confidence"] >= 0.75:
                    current_backbone.append(cand_gid)
                    seen.add(cand_gid)
                    retain_counter[cand_gid] += 1
                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "verify_trace->retain",
                            "selected": cand_gid,
                            "reason": reason,
                            "confidence": confidence,
                            "assistant_report": report,
                        }
                    )
                else:
                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "discard",
                            "selected": cand_gid,
                            "reason": f"{reason} Assistant did not provide strong enough support.",
                            "confidence": confidence,
                            "assistant_report": report,
                        }
                    )
                    memory["discarded_communities"].append(cand_gid)
                    seen.add(cand_gid)

            elif action == "bridge":
                if selected_candidate is None:
                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "terminate",
                            "selected": None,
                            "reason": "LLM did not provide a valid bridge target.",
                        }
                    )
                    break

                bridge_gid = str(selected_candidate)
                current_backbone.append(bridge_gid)
                seen.add(bridge_gid)
                retain_counter[bridge_gid] += 1
                memory["bridged_communities"].append(bridge_gid)

                final_reasoning.append(
                    {
                        "coi": coi_gid,
                        "step": t + 1,
                        "action": "bridge",
                        "selected": bridge_gid,
                        "reason": reason,
                        "confidence": confidence,
                    }
                )

            elif action == "discard":
                if candidates:
                    fallback_gid = selected_candidate
                    if fallback_gid not in valid_candidate_ids:
                        fallback_gid = candidates[0]["record"]["metadata"]["global_id"]

                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "discard",
                            "selected": fallback_gid,
                            "reason": reason,
                            "confidence": confidence,
                        }
                    )
                    memory["discarded_communities"].append(fallback_gid)
                    seen.add(fallback_gid)
                else:
                    final_reasoning.append(
                        {
                            "coi": coi_gid,
                            "step": t + 1,
                            "action": "terminate",
                            "selected": None,
                            "reason": "LLM requested discard but no candidates remained.",
                        }
                    )
                    break

            else:  # terminate
                final_reasoning.append(
                    {
                        "coi": coi_gid,
                        "step": t + 1,
                        "action": "terminate",
                        "selected": None,
                        "reason": reason,
                        "confidence": confidence,
                    }
                )
                break

        for gid in current_backbone:
            if gid not in final_backbone:
                final_backbone.append(gid)
                retain_counter[gid] += 1

    pruned_backbone = prune_final_backbone(final_backbone, record_map, retain_counter)

    covered_attack_stages = []
    for gid in pruned_backbone:
        covered_attack_stages.extend(extract_stage_hints(record_map[gid]))
    covered_attack_stages = sorted(list(set(covered_attack_stages)))

    unresolved_gaps = infer_gap_between(pruned_backbone, record_map)

    needs_more_logs = False
    if len(unresolved_gaps) > 0:
        needs_more_logs = True
    if "C" not in covered_attack_stages or "C&C" not in covered_attack_stages:
        needs_more_logs = True
    if len(pruned_backbone) < 3:
        needs_more_logs = True

    memory["retained_backbone"] = pruned_backbone
    memory["verified_reports"] = final_verified_reports
    memory["covered_attack_stages"] = covered_attack_stages
    memory["unresolved_gaps"] = unresolved_gaps
    memory["reasoning_chain"] = final_reasoning
    memory["status"] = "finished"

    save_json(memory_path, memory)

    result = {
        "retained_backbone": pruned_backbone,
        "covered_attack_stages": covered_attack_stages,
        "unresolved_gaps": unresolved_gaps,
        "verified_reports": final_verified_reports,
        "reasoning_chain": final_reasoning,
        "needs_more_logs": needs_more_logs,
        "num_cois_investigated": len(coi_queue),
        "final_backbone_length": len(pruned_backbone),
    }

    result_path = out_dir / "investigation_result.json"
    save_json(result_path, result)

    print("[OK] Investigation finished.")
    print(f"Retained backbone length: {len(pruned_backbone)}")
    print(f"Covered stages: {covered_attack_stages}")
    print(f"Unresolved gaps: {unresolved_gaps}")
    print(f"Needs more logs: {needs_more_logs}")
    print(f"Saved memory: {memory_path}")
    print(f"Saved result: {result_path}")


if __name__ == "__main__":
    main()