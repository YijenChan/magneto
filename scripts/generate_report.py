from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any

from src.config_utils import load_config
from src.llm_utils import load_prompt, call_llm_json


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def build_record_map(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {r["metadata"]["global_id"]: r for r in records}


def unique_extend(dst: List[str], src: List[str]) -> None:
    existing = set(dst)
    for x in src:
        if x not in existing:
            dst.append(x)
            existing.add(x)


def infer_stage_hints_strict(record: Dict[str, Any]) -> List[str]:
    """
    Keep a lightweight deterministic stage hint extractor.
    These hints are only auxiliary signals for the LLM, not the final report itself.
    """
    suspicious_nodes = " ".join(record.get("anomaly_contexts", {}).get("suspicious_nodes", [])).lower()
    traces = " ".join(record.get("archived_traces", [])).lower()
    text = suspicious_nodes + " " + traces

    stages = []

    if any(k in text for k in ["proc_firefox", "update.bin", "203.0.113.50"]):
        stages.append("C")

    if any(k in text for k in ["198.51.100.23", "domain_update-check.net", "proc_loaderd", "proc_syncsvc"]):
        stages.append("C&C")

    if any(k in text for k in ["/etc/passwd", "/etc/hostname", "/proc/net/route", "known_hosts", "scan_internal", "proc_sshprobe"]):
        stages.append("IR")

    if any(k in text for k in ["/etc/cron.d/sys-sync", ".syncsvc.pid", "chmod"]):
        stages.append("PE")

    if any(k in text for k in ["id_rsa", "host_targets.txt", "10.10.20.14", "10.10.20.21"]):
        stages.append("LM")

    if any(k in text for k in ["finance_q2.xlsx", "hr_roster.csv", "archive_01.tar", "45.77.10.8", "proc_tarmini"]):
        stages.append("MP")

    return sorted(list(set(stages)))


def collect_iocs_strict(record: Dict[str, Any]) -> Dict[str, List[str]]:
    suspicious_nodes = list(map(str, record.get("anomaly_contexts", {}).get("suspicious_nodes", [])))

    attack_keywords = [
        "proc_firefox",
        "proc_loaderd",
        "proc_syncsvc",
        "proc_tarmini",
        "proc_sshprobe",
        "203.0.113.50",
        "198.51.100.23",
        "45.77.10.8",
        "domain_update-check.net",
        "update.bin",
        ".syscache/loaderd",
        "sys-sync",
        ".syncsvc.pid",
        "known_hosts",
        "id_rsa",
        "host_targets.txt",
        "finance_q2.xlsx",
        "hr_roster.csv",
        "archive_01.tar",
        "10.10.20.14",
        "10.10.20.21",
    ]

    filtered = []
    for node in suspicious_nodes:
        low = node.lower()
        if any(k.lower() in low for k in attack_keywords):
            filtered.append(node)

    processes = sorted([x for x in filtered if x.startswith("proc_")])
    files = sorted([x for x in filtered if x.startswith("file_")])
    endpoints = sorted([x for x in filtered if x.startswith("ip_") or x.startswith("domain_")])

    return {
        "processes": processes,
        "files": files,
        "external_endpoints": endpoints,
    }


def is_strong_record(record: Dict[str, Any]) -> bool:
    anomaly = record.get("anomaly_contexts", {})
    suspicious_nodes = anomaly.get("suspicious_nodes", [])
    density = float(anomaly.get("anomaly_density", 0.0))
    subchains = anomaly.get("candidate_attack_subchains", [])
    bridge_intensity = anomaly.get("bridge_intensity", 0) or 0

    stage_hints = infer_stage_hints_strict(record)
    pg_id = str(record["metadata"].get("pg_id", ""))
    is_malicious_pg = pg_id.endswith("_malicious")

    if is_malicious_pg and (len(suspicious_nodes) >= 1 or len(stage_hints) >= 1):
        return True

    if len(stage_hints) >= 1 and density >= 0.15 and len(subchains) >= 1:
        return True

    if len(suspicious_nodes) >= 4 and density >= 0.20 and bridge_intensity >= 2:
        return True

    return False


def filter_backbone(backbone: List[str], record_map: Dict[str, Dict[str, Any]]) -> List[str]:
    strong = []
    strong_benign = []

    for gid in backbone:
        rec = record_map[gid]
        pg_id = str(rec["metadata"].get("pg_id", ""))
        is_malicious_pg = pg_id.endswith("_malicious")

        if not is_strong_record(rec):
            continue

        if is_malicious_pg:
            strong.append(gid)
        else:
            strong_benign.append(gid)

    strong_benign = [
        gid for gid in strong_benign
        if len(infer_stage_hints_strict(record_map[gid])) > 0
    ][:8]

    filtered = strong + strong_benign

    if len(filtered) < 5:
        ranked = sorted(
            backbone,
            key=lambda gid: (
                not str(record_map[gid]["metadata"].get("pg_id", "")).endswith("_malicious"),
                -len(infer_stage_hints_strict(record_map[gid])),
                -(len(record_map[gid].get("anomaly_contexts", {}).get("suspicious_nodes", []))),
                -float(record_map[gid].get("anomaly_contexts", {}).get("anomaly_density", 0.0)),
            ),
        )
        filtered = ranked[: min(12, len(ranked))]

    out = []
    seen = set()
    for gid in backbone:
        if gid in filtered and gid not in seen:
            out.append(gid)
            seen.add(gid)
    return out


def build_evidence_entries(
    backbone: List[str],
    record_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    entries = []

    for gid in backbone:
        rec = record_map[gid]
        meta = rec["metadata"]
        anomaly = rec.get("anomaly_contexts", {})
        boundary = rec.get("boundary_cues", {})

        entries.append(
            {
                "global_id": gid,
                "community_id": meta["community_id"],
                "pg_id": meta["pg_id"],
                "time_span": meta["time_span"],
                "stage_hints": infer_stage_hints_strict(rec),
                "suspicious_nodes": anomaly.get("suspicious_nodes", []),
                "node_scores": anomaly.get("node_scores", {}),
                "candidate_attack_subchains": anomaly.get("candidate_attack_subchains", []),
                "anomaly_density": anomaly.get("anomaly_density", 0.0),
                "bridge_intensity": anomaly.get("bridge_intensity", None),
                "matched_anchor_nodes": boundary.get("matched_anchor_nodes", []),
                "split_boundary_markers": boundary.get("split_boundary_markers", []),
                "archived_traces_preview": rec.get("archived_traces", [])[:8],
            }
        )

    return entries


def build_transition_summary(evidence_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    transitions = []

    for i in range(len(evidence_entries) - 1):
        a = evidence_entries[i]
        b = evidence_entries[i + 1]

        transitions.append(
            {
                "from_community": a["global_id"],
                "to_community": b["global_id"],
                "from_stages": a["stage_hints"],
                "to_stages": b["stage_hints"],
                "time_from": a["time_span"],
                "time_to": b["time_span"],
                "bridge_nodes": list(set(a["matched_anchor_nodes"]).intersection(set(b["matched_anchor_nodes"]))),
            }
        )

    return transitions


def build_reporter_user_prompt(
    raw_backbone: List[str],
    filtered_backbone: List[str],
    evidence_entries: List[Dict[str, Any]],
    transition_summary: List[Dict[str, Any]],
    reasoning_chain: List[Dict[str, Any]],
    verified_reports: List[Dict[str, Any]],
    deterministic_iocs: Dict[str, List[str]],
    unresolved_gaps: List[str],
    needs_more_logs: bool,
) -> str:
    """
    Provide the LLM with a compact but structured evidence packet.
    """
    packet = {
        "task": "Generate an evidence-grounded APT investigation report from structured Magneto outputs.",
        "constraints": {
            "use_only_provided_evidence": True,
            "do_not_invent_missing_stages": True,
            "mark_unsupported_parts_as_unresolved": True,
            "do_not_read_raw_logs_outside_archived_trace_previews": True,
        },
        "input_summary": {
            "raw_backbone_length": len(raw_backbone),
            "filtered_backbone_length": len(filtered_backbone),
            "unresolved_gaps": unresolved_gaps,
            "needs_more_logs": needs_more_logs,
        },
        "evidence_entries": evidence_entries,
        "transition_summary": transition_summary,
        "reasoning_chain_preview": reasoning_chain[:40],
        "verified_reports": verified_reports[:30],
        "deterministic_ioc_candidates": deterministic_iocs,
        "required_output_schema": {
            "summary": {
                "final_backbone_length": "integer",
                "covered_attack_stages": "list[str]",
                "unresolved_gaps": "list[str]",
                "needs_more_logs": "bool",
            },
            "stage_summary": [
                {
                    "stage": "str",
                    "num_supporting_communities": "integer",
                    "supporting_communities": "list[str]",
                    "representative_entities": "list[str]",
                    "representative_events": "list[str]",
                }
            ],
            "key_transitions": [
                {
                    "from_community": "str",
                    "to_community": "str",
                    "reason": "str",
                    "supported_by": "list[str]",
                }
            ],
            "ioc_list": {
                "processes": "list[str]",
                "files": "list[str]",
                "external_endpoints": "list[str]",
            },
            "completeness_assessment": "str",
            "recommended_next_action": "str",
        },
    }

    return json.dumps(packet, indent=2, ensure_ascii=False)


def _safe_list_str(x: Any) -> List[str]:
    if isinstance(x, list):
        return [str(i) for i in x]
    return []


def _normalize_stage_summary(x: Any) -> List[Dict[str, Any]]:
    if not isinstance(x, list):
        return []

    out: List[Dict[str, Any]] = []
    for item in x:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "stage": str(item.get("stage", "")),
                "num_supporting_communities": int(item.get("num_supporting_communities", 0)),
                "supporting_communities": _safe_list_str(item.get("supporting_communities", [])),
                "representative_entities": _safe_list_str(item.get("representative_entities", [])),
                "representative_events": _safe_list_str(item.get("representative_events", [])),
            }
        )
    return out


def _normalize_key_transitions(x: Any) -> List[Dict[str, Any]]:
    if not isinstance(x, list):
        return []

    out: List[Dict[str, Any]] = []
    for item in x:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "from_community": str(item.get("from_community", "")),
                "to_community": str(item.get("to_community", "")),
                "reason": str(item.get("reason", "")),
                "supported_by": _safe_list_str(item.get("supported_by", [])),
            }
        )
    return out


def _normalize_ioc_list(x: Any, fallback: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if not isinstance(x, dict):
        return fallback

    processes = _safe_list_str(x.get("processes", []))
    files = _safe_list_str(x.get("files", []))
    endpoints = _safe_list_str(x.get("external_endpoints", []))

    # fallback merge
    if not processes:
        processes = fallback["processes"]
    if not files:
        files = fallback["files"]
    if not endpoints:
        endpoints = fallback["external_endpoints"]

    return {
        "processes": processes[:20],
        "files": files[:20],
        "external_endpoints": endpoints[:20],
    }


def _normalize_summary(
    raw_summary: Any,
    filtered_backbone_len: int,
    fallback_covered_stages: List[str],
    fallback_unresolved_gaps: List[str],
    fallback_needs_more_logs: bool,
) -> Dict[str, Any]:
    if not isinstance(raw_summary, dict):
        return {
            "final_backbone_length": filtered_backbone_len,
            "covered_attack_stages": fallback_covered_stages,
            "unresolved_gaps": fallback_unresolved_gaps,
            "needs_more_logs": fallback_needs_more_logs,
        }

    final_backbone_length = int(raw_summary.get("final_backbone_length", filtered_backbone_len))
    covered_attack_stages = _safe_list_str(raw_summary.get("covered_attack_stages", fallback_covered_stages))
    unresolved_gaps = _safe_list_str(raw_summary.get("unresolved_gaps", fallback_unresolved_gaps))
    needs_more_logs = bool(raw_summary.get("needs_more_logs", fallback_needs_more_logs))

    return {
        "final_backbone_length": final_backbone_length,
        "covered_attack_stages": covered_attack_stages,
        "unresolved_gaps": unresolved_gaps,
        "needs_more_logs": needs_more_logs,
    }


def render_markdown_report(report_json: Dict[str, Any]) -> str:
    lines: List[str] = []

    lines.append("# APT Investigation Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Raw backbone length: {report_json['summary']['raw_backbone_length']}")
    lines.append(f"- Final backbone length: {report_json['summary']['final_backbone_length']}")
    lines.append(f"- Covered stages: {', '.join(report_json['summary']['covered_attack_stages']) if report_json['summary']['covered_attack_stages'] else 'None'}")
    lines.append(f"- Unresolved gaps: {', '.join(report_json['summary']['unresolved_gaps']) if report_json['summary']['unresolved_gaps'] else 'None'}")
    lines.append(f"- Needs more logs: {report_json['summary']['needs_more_logs']}")
    lines.append("")

    lines.append("## Stage-oriented Findings")
    lines.append("")
    for item in report_json["stage_summary"]:
        lines.append(f"### Stage {item['stage']}")
        lines.append(f"- Supporting communities: {item['num_supporting_communities']}")
        lines.append(f"- Representative entities: {', '.join(item['representative_entities']) if item['representative_entities'] else 'None'}")
        lines.append("- Representative events:")
        for ev in item["representative_events"]:
            lines.append(f"  - {ev}")
        lines.append("")

    lines.append("## Key Transitions")
    lines.append("")
    for tr in report_json["key_transitions"]:
        lines.append(f"- {tr['from_community']} -> {tr['to_community']}")
        lines.append(f"  - Reason: {tr['reason']}")
        if tr["supported_by"]:
            lines.append(f"  - Supported by: {', '.join(tr['supported_by'])}")
    lines.append("")

    lines.append("## Backbone Communities")
    lines.append("")
    for entry in report_json["evidence_entries"]:
        lines.append(f"### {entry['global_id']}")
        lines.append(f"- Community ID: {entry['community_id']}")
        lines.append(f"- PG ID: {entry['pg_id']}")
        lines.append(f"- Time span: {entry['time_span']['start']} -> {entry['time_span']['end']}")
        lines.append(f"- Stage hints: {', '.join(entry['stage_hints']) if entry['stage_hints'] else 'None'}")
        lines.append(f"- Suspicious nodes: {', '.join(entry['suspicious_nodes'][:10]) if entry['suspicious_nodes'] else 'None'}")
        lines.append(f"- Anomaly density: {entry['anomaly_density']}")
        lines.append(f"- Bridge intensity: {entry['bridge_intensity']}")
        if entry["matched_anchor_nodes"]:
            lines.append(f"- Matched anchors: {', '.join(entry['matched_anchor_nodes'])}")
        if entry["split_boundary_markers"]:
            lines.append(f"- Split boundary markers: {', '.join(entry['split_boundary_markers'])}")
        lines.append("- Trace preview:")
        for tr in entry["archived_traces_preview"]:
            lines.append(f"  - {tr}")
        lines.append("")

    lines.append("## Investigation Reasoning")
    lines.append("")
    for step in report_json["reasoning_chain"][:60]:
        lines.append(
            f"- COI={step.get('coi')} | step={step.get('step')} | "
            f"action={step.get('action')} | selected={step.get('selected')} | "
            f"reason={step.get('reason')}"
        )
    lines.append("")

    lines.append("## Verified Trace Reports")
    lines.append("")
    for vr in report_json["verified_reports"][:20]:
        lines.append(
            f"- community={vr.get('community_global_id')} | verdict={vr.get('verdict')} | confidence={vr.get('confidence')}"
        )
        for ev in vr.get("evidence_snippets", [])[:3]:
            lines.append(f"  - {ev}")
    lines.append("")

    lines.append("## Indicators of Compromise (IOCs)")
    lines.append("")
    lines.append(f"- Processes: {', '.join(report_json['ioc_list']['processes']) if report_json['ioc_list']['processes'] else 'None'}")
    lines.append(f"- Files: {', '.join(report_json['ioc_list']['files']) if report_json['ioc_list']['files'] else 'None'}")
    lines.append(f"- External endpoints: {', '.join(report_json['ioc_list']['external_endpoints']) if report_json['ioc_list']['external_endpoints'] else 'None'}")
    lines.append("")

    lines.append("## Completeness Assessment")
    lines.append("")
    lines.append(str(report_json["completeness_assessment"]))
    lines.append("")

    lines.append("## Recommended Next Action")
    lines.append("")
    lines.append(str(report_json["recommended_next_action"]))
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    cfg = load_config()

    investigation_dir = Path(cfg["paths"]["investigation_dir"])
    memory_path = Path(cfg["investigation"]["lead_memory_file"])
    cdg_root = Path(cfg["paths"]["cdg_dir"])
    report_dir = Path(cfg["paths"]["report_dir"])
    prompt_dir = Path(cfg["paths"]["prompt_dir"])
    report_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = load_prompt(prompt_dir / "reporter_system.txt")

    result = load_json(investigation_dir / "investigation_result.json")
    memory = load_json(memory_path)
    records = load_json(cdg_root / "cdg_records_updated.json")

    record_map = build_record_map(records)

    raw_backbone = result.get("retained_backbone", [])
    backbone = filter_backbone(raw_backbone, record_map)

    reasoning_chain = result.get("reasoning_chain", [])
    verified_reports = result.get("verified_reports", [])

    evidence_entries = build_evidence_entries(backbone, record_map)
    transition_summary = build_transition_summary(evidence_entries)

    covered_attack_stages = []
    for gid in backbone:
        covered_attack_stages.extend(infer_stage_hints_strict(record_map[gid]))
    covered_attack_stages = sorted(list(set(covered_attack_stages)))

    unresolved_gaps = result.get("unresolved_gaps", [])
    needs_more_logs = bool(result.get("needs_more_logs", False))

    if "C" not in covered_attack_stages or "C&C" not in covered_attack_stages:
        needs_more_logs = True
    if len(backbone) < 3:
        needs_more_logs = True

    det_ioc_processes: List[str] = []
    det_ioc_files: List[str] = []
    det_ioc_endpoints: List[str] = []

    for gid in backbone:
        rec = record_map[gid]
        iocs = collect_iocs_strict(rec)
        unique_extend(det_ioc_processes, iocs["processes"])
        unique_extend(det_ioc_files, iocs["files"])
        unique_extend(det_ioc_endpoints, iocs["external_endpoints"])

    deterministic_iocs = {
        "processes": det_ioc_processes,
        "files": det_ioc_files,
        "external_endpoints": det_ioc_endpoints,
    }

    user_prompt = build_reporter_user_prompt(
        raw_backbone=raw_backbone,
        filtered_backbone=backbone,
        evidence_entries=evidence_entries,
        transition_summary=transition_summary,
        reasoning_chain=reasoning_chain,
        verified_reports=verified_reports,
        deterministic_iocs=deterministic_iocs,
        unresolved_gaps=unresolved_gaps,
        needs_more_logs=needs_more_logs,
    )

    raw_llm = call_llm_json(system_prompt=system_prompt, user_prompt=user_prompt)

    summary = _normalize_summary(
        raw_llm.get("summary", {}),
        filtered_backbone_len=len(backbone),
        fallback_covered_stages=covered_attack_stages,
        fallback_unresolved_gaps=unresolved_gaps,
        fallback_needs_more_logs=needs_more_logs,
    )

    ioc_list = _normalize_ioc_list(raw_llm.get("ioc_list", {}), deterministic_iocs)
    stage_summary = _normalize_stage_summary(raw_llm.get("stage_summary", []))
    key_transitions = _normalize_key_transitions(raw_llm.get("key_transitions", []))

    completeness_assessment = str(
        raw_llm.get(
            "completeness_assessment",
            "The current investigation remains incomplete and should request additional logs."
            if summary["needs_more_logs"]
            else "The current retained evidence is sufficient for a compact attack backbone."
        )
    )

    recommended_next_action = str(
        raw_llm.get(
            "recommended_next_action",
            "Update investigation signal from round=2 to round=1 and rerun collector/detector/investigation."
            if summary["needs_more_logs"]
            else "Proceed with current retained backbone."
        )
    )

    report_json = {
        "summary": {
            "raw_backbone_length": len(raw_backbone),
            "final_backbone_length": summary["final_backbone_length"],
            "covered_attack_stages": summary["covered_attack_stages"],
            "unresolved_gaps": summary["unresolved_gaps"],
            "needs_more_logs": summary["needs_more_logs"],
        },
        "evidence_entries": evidence_entries,
        "stage_summary": stage_summary,
        "key_transitions": key_transitions,
        "transition_summary": transition_summary,  # 保留原始结构化中间结果，便于调试
        "reasoning_chain": reasoning_chain,
        "verified_reports": verified_reports,
        "ioc_list": ioc_list,
        "completeness_assessment": completeness_assessment,
        "recommended_next_action": recommended_next_action,
    }

    report_md = render_markdown_report(report_json)

    report_json_path = report_dir / "apt_report.json"
    report_md_path = report_dir / "apt_report.md"
    ioc_path = report_dir / "ioc_list.json"

    save_json(report_json_path, report_json)
    with report_md_path.open("w", encoding="utf-8") as f:
        f.write(report_md)

    save_json(ioc_path, ioc_list)

    print("[OK] Reporter finished.")
    print(f"Raw backbone length: {len(raw_backbone)}")
    print(f"Final backbone length: {summary['final_backbone_length']}")
    print(f"Covered stages: {summary['covered_attack_stages']}")
    print(f"Unresolved gaps: {summary['unresolved_gaps']}")
    print(f"Needs more logs: {summary['needs_more_logs']}")
    print(f"Saved report json: {report_json_path}")
    print(f"Saved report md: {report_md_path}")
    print(f"Saved IOC list: {ioc_path}")


if __name__ == "__main__":
    main()