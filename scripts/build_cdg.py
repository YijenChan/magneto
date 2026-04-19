from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set

from src.config_utils import load_config


def list_detector_pg_dirs(detector_root: Path) -> List[Path]:
    dirs = []
    for p in detector_root.iterdir():
        if p.is_dir() and (p / "community_records.json").exists():
            dirs.append(p)
    dirs.sort(key=lambda x: x.name)
    return dirs


def parse_time_span(record: Dict[str, Any]) -> Tuple[str, str]:
    ts = record["metadata"]["time_span"]
    return ts["start"], ts["end"]


def record_global_id(pg_id: str, community_id: str) -> str:
    return f"{pg_id}::{community_id}"


def flatten_context_entities(record: Dict[str, Any]) -> Set[str]:
    out = set()

    anomaly = record.get("anomaly_contexts", {})
    suspicious_nodes = anomaly.get("suspicious_nodes", [])
    out.update(map(str, suspicious_nodes))

    n_hop = anomaly.get("n_hop_neighbors", {})
    for _, neighbors in n_hop.items():
        out.update(map(str, neighbors))

    boundary = record.get("boundary_cues", {})
    out.update(map(str, boundary.get("matched_anchor_nodes", [])))

    return out


def temporal_constraint_satisfied(src_record: Dict[str, Any], dst_record: Dict[str, Any]) -> bool:
    src_start, src_end = parse_time_span(src_record)
    dst_start, dst_end = parse_time_span(dst_record)
    return src_end <= dst_start


def basename_like(entity: str) -> str:
    s = str(entity)
    if "/" in s:
        return s.split("/")[-1]
    if "_" in s:
        return s.split("_")[-1]
    return s


def entity_alignment_pairs(src_record: Dict[str, Any], dst_record: Dict[str, Any]) -> List[List[str]]:
    src_entities = flatten_context_entities(src_record)
    dst_entities = flatten_context_entities(dst_record)

    pairs = []
    for a in src_entities:
        ba = basename_like(a)
        for b in dst_entities:
            bb = basename_like(b)
            if a == b:
                continue
            if ba and bb and ba == bb:
                pairs.append([str(a), str(b)])
            elif str(a) in str(b) or str(b) in str(a):
                pairs.append([str(a), str(b)])

    uniq = []
    seen = set()
    for x, y in pairs:
        key = (x, y)
        if key not in seen:
            seen.add(key)
            uniq.append([x, y])
    return uniq


def load_pg_boundary_marker_details(pg_root: Path, pg_id: str) -> List[Dict[str, Any]]:
    boundary_path = pg_root / pg_id / "boundary_markers.json"
    if not boundary_path.exists():
        return []

    with boundary_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        return []
    return data


def attach_boundary_marker_details(
    pg_root: Path,
    rec: Dict[str, Any],
) -> Dict[str, Any]:
    pg_id = rec["metadata"]["pg_id"]
    allowed_ids = set(rec.get("boundary_cues", {}).get("split_boundary_markers", []))
    details = load_pg_boundary_marker_details(pg_root, pg_id)

    if allowed_ids:
        details = [m for m in details if m.get("marker_id") in allowed_ids]

    rec["_boundary_marker_details"] = details
    return rec


def shared_anchor_nodes(src_record: Dict[str, Any], dst_record: Dict[str, Any]) -> List[str]:
    src_anchors = set(src_record.get("boundary_cues", {}).get("matched_anchor_nodes", []))
    dst_anchors = set(dst_record.get("boundary_cues", {}).get("matched_anchor_nodes", []))
    return sorted(list(src_anchors.intersection(dst_anchors)))


def shared_context_entities(src_record: Dict[str, Any], dst_record: Dict[str, Any]) -> List[str]:
    src_entities = flatten_context_entities(src_record)
    dst_entities = flatten_context_entities(dst_record)
    return sorted(list(src_entities.intersection(dst_entities)))


def anomaly_gate(record: Dict[str, Any]) -> bool:
    anomaly = record.get("anomaly_contexts", {})
    suspicious_nodes = anomaly.get("suspicious_nodes", [])
    density = float(anomaly.get("anomaly_density", 0.0))
    subchains = anomaly.get("candidate_attack_subchains", [])
    return len(suspicious_nodes) >= 1 or density >= 0.10 or len(subchains) >= 1


def temporal_continuation_matches(src_record: Dict[str, Any], dst_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stricter temporal continuation:
    add dependency only when two communities lie exactly on opposite sides of the same split boundary
    AND both communities touch the same bridge node(s).
    """
    if not temporal_constraint_satisfied(src_record, dst_record):
        return {
            "matched_split_markers": [],
            "matched_bridge_nodes": [],
        }

    src_markers = src_record.get("_boundary_marker_details", [])
    dst_markers = dst_record.get("_boundary_marker_details", [])

    src_context = flatten_context_entities(src_record)
    dst_context = flatten_context_entities(dst_record)

    src_pg_start, src_pg_end = parse_time_span(src_record)
    dst_pg_start, dst_pg_end = parse_time_span(dst_record)

    matched_ids = []
    matched_bridge_nodes = set()

    src_by_id = {m.get("marker_id"): m for m in src_markers if m.get("marker_id")}
    dst_by_id = {m.get("marker_id"): m for m in dst_markers if m.get("marker_id")}
    shared_ids = sorted(set(src_by_id.keys()).intersection(set(dst_by_id.keys())))

    # at least one side should carry non-trivial anomaly signal
    if not (anomaly_gate(src_record) or anomaly_gate(dst_record)):
        return {
            "matched_split_markers": [],
            "matched_bridge_nodes": [],
        }

    for mid in shared_ids:
        sm = src_by_id[mid]
        dm = dst_by_id[mid]

        src_side = sm.get("side")
        dst_side = dm.get("side")

        if not (src_side == "left" and dst_side == "right"):
            continue

        split_time = sm.get("split_time")
        if split_time is None or dm.get("split_time") != split_time:
            continue

        # both leaf PGs must directly touch the split boundary
        if str(src_pg_end) != str(split_time):
            continue
        if str(dst_pg_start) != str(split_time):
            continue

        src_bridge = set(map(str, sm.get("bridge_nodes", [])))
        dst_bridge = set(map(str, dm.get("bridge_nodes", [])))
        bridge_nodes = src_bridge.intersection(dst_bridge)

        if not bridge_nodes:
            continue

        # each side must actually touch bridge nodes
        src_hits = src_context.intersection(bridge_nodes)
        dst_hits = dst_context.intersection(bridge_nodes)

        if not src_hits:
            continue
        if not dst_hits:
            continue

        # strongest requirement: both sides touch the same bridge entity
        common_hits = src_hits.intersection(dst_hits)
        if not common_hits:
            continue

        matched_ids.append(mid)
        matched_bridge_nodes.update(common_hits)

    return {
        "matched_split_markers": sorted(list(set(matched_ids))),
        "matched_bridge_nodes": sorted(list(matched_bridge_nodes)),
    }


def classify_dependency(
    src_record: Dict[str, Any],
    dst_record: Dict[str, Any],
) -> Dict[str, Any] | None:
    if not temporal_constraint_satisfied(src_record, dst_record):
        return None

    temporal_info = temporal_continuation_matches(src_record, dst_record)
    split_matches = temporal_info["matched_split_markers"]
    temporal_bridge_nodes = temporal_info["matched_bridge_nodes"]

    anchor_matches = shared_anchor_nodes(src_record, dst_record)
    aligned_entities = entity_alignment_pairs(src_record, dst_record)
    shared_entities = shared_context_entities(src_record, dst_record)

    dep_types = []

    if split_matches:
        dep_types.append("temporal_continuation")
    if anchor_matches or shared_entities:
        dep_types.append("anchor_based")
    if aligned_entities:
        dep_types.append("entity_alignment")

    if not dep_types:
        return None

    return {
        "dependency_types": dep_types,
        "matched_split_markers": split_matches,
        "matched_anchor_nodes": sorted(list(set(anchor_matches).union(set(temporal_bridge_nodes)))),
        "aligned_entities": aligned_entities,
        "shared_context_entities": shared_entities,
    }


def main() -> None:
    cfg = load_config()

    detector_root = Path(cfg["paths"]["detector_dir"])
    cdg_root = Path(cfg["paths"]["cdg_dir"])
    pg_root = Path(cfg["paths"]["pg_dir"])
    cdg_root.mkdir(parents=True, exist_ok=True)

    pg_dirs = list_detector_pg_dirs(detector_root)
    if not pg_dirs:
        raise RuntimeError("No detector outputs found with community_records.json")

    all_records: List[Dict[str, Any]] = []
    nodes: List[Dict[str, Any]] = []

    for pg_dir in pg_dirs:
        pg_id = pg_dir.name
        record_path = pg_dir / "community_records.json"

        with record_path.open("r", encoding="utf-8") as f:
            records = json.load(f)

        for rec in records:
            community_id = rec["metadata"]["community_id"]
            gid = record_global_id(pg_id, community_id)

            rec["metadata"]["global_id"] = gid
            rec["metadata"]["pg_id"] = pg_id
            rec = attach_boundary_marker_details(pg_root, rec)

            all_records.append(rec)
            nodes.append(
                {
                    "global_id": gid,
                    "pg_id": pg_id,
                    "community_id": community_id,
                    "time_span": rec["metadata"]["time_span"],
                    "anomaly_density": rec["anomaly_contexts"].get("anomaly_density", 0.0),
                    "num_suspicious_nodes": len(rec["anomaly_contexts"].get("suspicious_nodes", [])),
                }
            )

    edges: List[Dict[str, Any]] = []

    for i in range(len(all_records)):
        for j in range(len(all_records)):
            if i == j:
                continue

            src = all_records[i]
            dst = all_records[j]

            dep = classify_dependency(src, dst)
            if dep is None:
                continue

            edge = {
                "source_community": src["metadata"]["global_id"],
                "target_community": dst["metadata"]["global_id"],
                "temporal_rule": "satisfied",
                "dependency_type": dep["dependency_types"],
                "matched_split_markers": dep["matched_split_markers"],
                "matched_anchor_nodes": dep["matched_anchor_nodes"],
                "aligned_entities": dep["aligned_entities"],
                "shared_context_entities": dep["shared_context_entities"],
            }
            edges.append(edge)

    outgoing_count: Dict[str, int] = {}
    incoming_count: Dict[str, int] = {}

    for e in edges:
        s = e["source_community"]
        t = e["target_community"]
        outgoing_count[s] = outgoing_count.get(s, 0) + 1
        incoming_count[t] = incoming_count.get(t, 0) + 1

    for rec in all_records:
        gid = rec["metadata"]["global_id"]
        bridge_intensity = outgoing_count.get(gid, 0) + incoming_count.get(gid, 0)
        rec["anomaly_contexts"]["bridge_intensity"] = bridge_intensity

        if "_boundary_marker_details" in rec:
            del rec["_boundary_marker_details"]

    nodes_out = cdg_root / "cdg_nodes.json"
    edges_out = cdg_root / "cdg_edges.json"
    records_out = cdg_root / "cdg_records_updated.json"
    summary_out = cdg_root / "cdg_summary.json"

    with nodes_out.open("w", encoding="utf-8") as f:
        json.dump(nodes, f, indent=2)

    with edges_out.open("w", encoding="utf-8") as f:
        json.dump(edges, f, indent=2)

    with records_out.open("w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)

    summary = {
        "num_pg_dirs": len(pg_dirs),
        "num_cdg_nodes": len(nodes),
        "num_cdg_edges": len(edges),
        "num_temporal_continuation_edges": sum(
            1 for e in edges if "temporal_continuation" in e["dependency_type"]
        ),
        "num_anchor_based_edges": sum(
            1 for e in edges if "anchor_based" in e["dependency_type"]
        ),
        "num_entity_alignment_edges": sum(
            1 for e in edges if "entity_alignment" in e["dependency_type"]
        ),
    }

    with summary_out.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("[OK] CDG construction finished.")
    print(f"PG dirs used: {len(pg_dirs)}")
    print(f"CDG nodes: {len(nodes)}")
    print(f"CDG edges: {len(edges)}")
    print(f"Temporal-continuation edges: {summary['num_temporal_continuation_edges']}")
    print(f"Anchor-based edges: {summary['num_anchor_based_edges']}")
    print(f"Entity-alignment edges: {summary['num_entity_alignment_edges']}")
    print(f"Saved nodes: {nodes_out}")
    print(f"Saved edges: {edges_out}")
    print(f"Saved updated records: {records_out}")
    print(f"Saved summary: {summary_out}")


if __name__ == "__main__":
    main()