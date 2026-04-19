from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Any

import pandas as pd

from src.config_utils import load_config


EPS = 1e-8


@dataclass
class TimeInterval:
    start: pd.Timestamp
    end: pd.Timestamp

    def to_str(self) -> str:
        return f"{self.start.strftime('%Y-%m-%d_%H-%M-%S')}_{self.end.strftime('%Y-%m-%d_%H-%M-%S')}"

    def duration_seconds(self) -> float:
        return float((self.end - self.start).total_seconds())


def infer_node_type(node_id: str) -> str:
    node_id = str(node_id)
    if node_id.startswith("proc_"):
        return "process"
    if node_id.startswith("file_"):
        return "file"
    if node_id.startswith("ip_"):
        return "network"
    if node_id.startswith("domain_"):
        return "network"
    return "unknown"


def ensure_required_columns(df: pd.DataFrame) -> None:
    required = {
        "event_id",
        "timestamp",
        "src",
        "rel",
        "dst",
        "stage",
        "label",
        "is_attack_related",
        "round",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")


def floor_to_interval(ts: pd.Timestamp, minutes: int) -> pd.Timestamp:
    return ts.floor(f"{minutes}min")


def build_default_intervals(df: pd.DataFrame, interval_minutes: int) -> List[TimeInterval]:
    min_ts = pd.to_datetime(df["timestamp"]).min()
    max_ts = pd.to_datetime(df["timestamp"]).max()

    start = floor_to_interval(min_ts, interval_minutes)
    intervals: List[TimeInterval] = []
    cur = start
    delta = pd.Timedelta(minutes=interval_minutes)

    while cur <= max_ts:
        intervals.append(TimeInterval(start=cur, end=cur + delta))
        cur = cur + delta

    return intervals


def filter_events_by_interval(df: pd.DataFrame, interval: TimeInterval) -> pd.DataFrame:
    mask = (df["timestamp"] >= interval.start) & (df["timestamp"] < interval.end)
    out = df.loc[mask].copy()
    out = out.sort_values(["timestamp", "event_id"]).reset_index(drop=True)
    return out


def compress_candidate_pg(events_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    if events_df.empty:
        return pd.DataFrame(), pd.DataFrame()

    node_ids = sorted(set(events_df["src"].astype(str)).union(set(events_df["dst"].astype(str))))
    node_rows = [{"node_id": nid, "node_type": infer_node_type(nid)} for nid in node_ids]
    nodes_df = pd.DataFrame(node_rows)

    edge_rows: List[Dict[str, Any]] = []
    grouped = events_df.groupby(["src", "rel", "dst"], dropna=False, sort=False)

    for (src, rel, dst), group in grouped:
        group = group.sort_values(["timestamp", "event_id"])
        labels = group["label"].astype(str).tolist()
        stages = group["stage"].astype(str).tolist()
        rounds = sorted(group["round"].astype(int).unique().tolist())

        edge_rows.append(
            {
                "src": str(src),
                "rel": str(rel),
                "dst": str(dst),
                "interaction_count": int(len(group)),
                "first_timestamp": str(group["timestamp"].iloc[0]),
                "last_timestamp": str(group["timestamp"].iloc[-1]),
                "event_ids": "|".join(group["event_id"].astype(str).tolist()),
                "stage_set": "|".join(sorted(set(stages))),
                "label_set": "|".join(sorted(set(labels))),
                "contains_malicious": bool((group["label"] == "malicious").any()),
                "round_set": "|".join(map(str, rounds)),
            }
        )

    edges_df = pd.DataFrame(edge_rows)
    edges_df = edges_df.sort_values(["first_timestamp", "src", "rel", "dst"]).reset_index(drop=True)

    return nodes_df, edges_df


def make_split_boundary_marker(
    parent_interval: TimeInterval,
    left_interval: TimeInterval,
    right_interval: TimeInterval,
    parent_events: pd.DataFrame,
) -> Dict[str, Any]:
    split_time = left_interval.end

    left_touch = parent_events[parent_events["timestamp"] < split_time]
    right_touch = parent_events[parent_events["timestamp"] >= split_time]

    left_nodes = set(left_touch["src"].astype(str)).union(set(left_touch["dst"].astype(str)))
    right_nodes = set(right_touch["src"].astype(str)).union(set(right_touch["dst"].astype(str)))
    bridge_nodes = sorted(left_nodes.intersection(right_nodes))

    marker_id = f"BND_{parent_interval.start.strftime('%Y%m%d%H%M%S')}_{split_time.strftime('%Y%m%d%H%M%S')}"

    return {
        "marker_id": marker_id,
        "parent_interval": {
            "start": str(parent_interval.start),
            "end": str(parent_interval.end),
        },
        "left_interval": {
            "start": str(left_interval.start),
            "end": str(left_interval.end),
        },
        "right_interval": {
            "start": str(right_interval.start),
            "end": str(right_interval.end),
        },
        "split_time": str(split_time),
        "bridge_nodes": bridge_nodes,
        "num_bridge_nodes": len(bridge_nodes),
    }


def update_marker_for_descendant(marker: Dict[str, Any], side: str, child_interval: TimeInterval) -> Dict[str, Any]:
    if side not in {"left", "right"}:
        raise ValueError(f"Invalid marker side: {side}")

    out = dict(marker)
    out["side"] = side
    out["child_interval"] = {
        "start": str(child_interval.start),
        "end": str(child_interval.end),
    }
    return out


def propagate_inherited_markers(
    inherited_markers: List[Dict[str, Any]],
    child_interval: TimeInterval,
) -> List[Dict[str, Any]]:
    """
    Update all inherited markers so that their child_interval reflects the CURRENT descendant interval.
    Keep the existing side unchanged.
    """
    propagated: List[Dict[str, Any]] = []

    for m in inherited_markers:
        side = m.get("side")
        if side not in {"left", "right"}:
            continue
        propagated.append(update_marker_for_descendant(m, side=side, child_interval=child_interval))

    return propagated


def deduplicate_markers(markers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    uniq: List[Dict[str, Any]] = []
    seen = set()

    for m in markers:
        key = (
            m.get("marker_id"),
            m.get("side"),
            m.get("child_interval", {}).get("start"),
            m.get("child_interval", {}).get("end"),
        )
        if key not in seen:
            seen.add(key)
            uniq.append(m)

    return uniq


def compute_node_features(
    events_df: pd.DataFrame,
    nodes_df: pd.DataFrame,
    relation_vocab: List[str],
) -> pd.DataFrame:
    if nodes_df.empty:
        return pd.DataFrame()

    ts_by_node: Dict[str, List[pd.Timestamp]] = {}
    rel_count_by_node: Dict[str, Dict[str, int]] = {
        nid: {r: 0 for r in relation_vocab} for nid in nodes_df["node_id"].astype(str)
    }

    for _, row in events_df.iterrows():
        src = str(row["src"])
        dst = str(row["dst"])
        rel = str(row["rel"])
        ts = row["timestamp"]

        ts_by_node.setdefault(src, []).append(ts)
        ts_by_node.setdefault(dst, []).append(ts)

        if src in rel_count_by_node and rel in rel_count_by_node[src]:
            rel_count_by_node[src][rel] += 1
        if dst in rel_count_by_node and rel in rel_count_by_node[dst]:
            rel_count_by_node[dst][rel] += 1

    rows: List[Dict[str, Any]] = []

    for _, row in nodes_df.iterrows():
        nid = str(row["node_id"])
        ntype = str(row["node_type"])

        type_process = 1.0 if ntype == "process" else 0.0
        type_file = 1.0 if ntype == "file" else 0.0
        type_network = 1.0 if ntype == "network" else 0.0
        type_unknown = 1.0 if ntype not in {"process", "file", "network"} else 0.0

        rel_counts = rel_count_by_node.get(nid, {r: 0 for r in relation_vocab})
        total_rel = sum(rel_counts.values())
        act_dist = {
            f"act_{rel}": (rel_counts[rel] / (total_rel + EPS)) for rel in relation_vocab
        }

        ts_list = sorted(ts_by_node.get(nid, []))
        if len(ts_list) >= 2:
            span = float((ts_list[-1] - ts_list[0]).total_seconds())
            gaps = [(ts_list[i] - ts_list[i - 1]).total_seconds() for i in range(1, len(ts_list))]
            mean_gap = float(sum(gaps) / len(gaps))
            max_gap = float(max(gaps))
        else:
            span = 0.0
            mean_gap = 0.0
            max_gap = 0.0

        out = {
            "node_id": nid,
            "node_type": ntype,
            "type_process": type_process,
            "type_file": type_file,
            "type_network": type_network,
            "type_unknown": type_unknown,
            "tmp_span": span,
            "tmp_mean_gap": mean_gap,
            "tmp_max_gap": max_gap,
        }
        out.update(act_dist)
        rows.append(out)

    feat_df = pd.DataFrame(rows)

    for col in ["tmp_span", "tmp_mean_gap", "tmp_max_gap"]:
        min_v = feat_df[col].min()
        max_v = feat_df[col].max()
        if max_v > min_v:
            feat_df[col] = (feat_df[col] - min_v) / (max_v - min_v + EPS)
        else:
            feat_df[col] = 0.0

    feat_df = feat_df.sort_values("node_id").reset_index(drop=True)
    return feat_df


def safe_label_name(is_malicious: bool) -> str:
    return "malicious" if is_malicious else "benign"


def save_pg_bundle(
    out_root: Path,
    interval: TimeInterval,
    events_df: pd.DataFrame,
    nodes_df: pd.DataFrame,
    edges_df: pd.DataFrame,
    feat_df: pd.DataFrame,
    boundary_markers: List[Dict[str, Any]],
    source_round: int,
    was_split: bool,
    split_depth: int,
    parent_interval: TimeInterval | None,
) -> None:
    is_malicious = bool((events_df["label"] == "malicious").any()) if not events_df.empty else False
    bundle_name = f"PG_{interval.to_str()}_{safe_label_name(is_malicious)}"
    bundle_dir = out_root / bundle_name
    bundle_dir.mkdir(parents=True, exist_ok=True)

    events_out = bundle_dir / "events.csv"
    nodes_out = bundle_dir / "nodes.csv"
    edges_out = bundle_dir / "edges.csv"
    feat_out = bundle_dir / "node_features.csv"
    meta_out = bundle_dir / "metadata.json"
    bnd_out = bundle_dir / "boundary_markers.json"

    events_df.to_csv(events_out, index=False, encoding="utf-8")
    nodes_df.to_csv(nodes_out, index=False, encoding="utf-8")
    edges_df.to_csv(edges_out, index=False, encoding="utf-8")
    feat_df.to_csv(feat_out, index=False, encoding="utf-8")

    metadata = {
        "pg_name": bundle_name,
        "time_span": {
            "start": str(interval.start),
            "end": str(interval.end),
        },
        "source_round": int(source_round),
        "is_benign": not is_malicious,
        "is_malicious": is_malicious,
        "num_raw_events": int(len(events_df)),
        "num_nodes": int(len(nodes_df)),
        "num_edges_compressed": int(len(edges_df)),
        "was_split": bool(was_split),
        "split_depth": int(split_depth),
        "parent_interval": None
        if parent_interval is None
        else {"start": str(parent_interval.start), "end": str(parent_interval.end)},
    }

    with meta_out.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    with bnd_out.open("w", encoding="utf-8") as f:
        json.dump(deduplicate_markers(boundary_markers), f, indent=2)

    print(
        f"[SAVE] {bundle_name} | "
        f"events={len(events_df)} nodes={len(nodes_df)} edges={len(edges_df)} "
        f"split={was_split} markers={len(boundary_markers)}"
    )


def recursive_construct_pg(
    all_events_df: pd.DataFrame,
    interval: TimeInterval,
    out_root: Path,
    node_budget: int,
    relation_vocab: List[str],
    source_round: int,
    split_depth: int = 0,
    parent_interval: TimeInterval | None = None,
    inherited_markers: List[Dict[str, Any]] | None = None,
) -> int:
    if inherited_markers is None:
        inherited_markers = []

    events_df = filter_events_by_interval(all_events_df, interval)

    if events_df.empty:
        return 0

    nodes_df, edges_df = compress_candidate_pg(events_df)

    if len(nodes_df) <= node_budget or interval.duration_seconds() <= 60:
        feat_df = compute_node_features(events_df, nodes_df, relation_vocab)
        save_pg_bundle(
            out_root=out_root,
            interval=interval,
            events_df=events_df,
            nodes_df=nodes_df,
            edges_df=edges_df,
            feat_df=feat_df,
            boundary_markers=inherited_markers,
            source_round=source_round,
            was_split=(split_depth > 0),
            split_depth=split_depth,
            parent_interval=parent_interval,
        )
        return 1

    mid = interval.start + (interval.end - interval.start) / 2
    left_interval = TimeInterval(start=interval.start, end=mid)
    right_interval = TimeInterval(start=mid, end=interval.end)

    marker = make_split_boundary_marker(interval, left_interval, right_interval, events_df)

    marker_dir = out_root / "_split_markers"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker_path = marker_dir / f"{marker['marker_id']}.json"
    with marker_path.open("w", encoding="utf-8") as f:
        json.dump(marker, f, indent=2)

    propagated_left = propagate_inherited_markers(inherited_markers, left_interval)
    propagated_right = propagate_inherited_markers(inherited_markers, right_interval)

    left_markers = deduplicate_markers(
        propagated_left + [update_marker_for_descendant(marker, side="left", child_interval=left_interval)]
    )
    right_markers = deduplicate_markers(
        propagated_right + [update_marker_for_descendant(marker, side="right", child_interval=right_interval)]
    )

    retained = 0
    retained += recursive_construct_pg(
        all_events_df=all_events_df,
        interval=left_interval,
        out_root=out_root,
        node_budget=node_budget,
        relation_vocab=relation_vocab,
        source_round=source_round,
        split_depth=split_depth + 1,
        parent_interval=interval,
        inherited_markers=left_markers,
    )
    retained += recursive_construct_pg(
        all_events_df=all_events_df,
        interval=right_interval,
        out_root=out_root,
        node_budget=node_budget,
        relation_vocab=relation_vocab,
        source_round=source_round,
        split_depth=split_depth + 1,
        parent_interval=interval,
        inherited_markers=right_markers,
    )

    print(
        f"[SPLIT] {interval.to_str()} -> "
        f"{left_interval.to_str()} | {right_interval.to_str()} "
        f"(nodes={len(nodes_df)} > budget={node_budget})"
    )
    return retained


def summarize_pg_results(pg_root: Path) -> None:
    meta_files = [p for p in pg_root.rglob("metadata.json") if p.is_file()]
    if not meta_files:
        print("[WARN] No PG metadata.json found.")
        return

    benign = 0
    malicious = 0
    total_nodes = 0
    total_edges = 0

    for mp in meta_files:
        with mp.open("r", encoding="utf-8") as f:
            meta = json.load(f)
        benign += int(bool(meta["is_benign"]))
        malicious += int(bool(meta["is_malicious"]))
        total_nodes += int(meta["num_nodes"])
        total_edges += int(meta["num_edges_compressed"])

    print("\n[SUMMARY] Collector PG construction finished.")
    print(f"Retained PGs: {len(meta_files)}")
    print(f"Benign PGs: {benign}")
    print(f"Malicious PGs: {malicious}")
    print(f"Average nodes per PG: {total_nodes / max(len(meta_files), 1):.2f}")
    print(f"Average edges per PG: {total_edges / max(len(meta_files), 1):.2f}")


def main() -> None:
    cfg = load_config()

    toy_dir = Path(cfg["paths"]["toy_data_dir"])
    pg_root = Path(cfg["paths"]["pg_dir"])
    pg_root.mkdir(parents=True, exist_ok=True)

    signal_path = Path(cfg["paths"]["config_dir"]) / "investigation_signal.json"
    with signal_path.open("r", encoding="utf-8") as f:
        signal = json.load(f)

    flag = int(signal["flag"])
    if flag not in [1, 2]:
        raise ValueError(f"Invalid investigation flag: {flag}")

    input_csv = toy_dir / f"toy_magneto_round{flag}.csv"
    if not input_csv.exists():
        raise FileNotFoundError(f"Input round CSV not found: {input_csv}")

    df = pd.read_csv(input_csv)
    ensure_required_columns(df)

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["src"] = df["src"].astype(str)
    df["rel"] = df["rel"].astype(str)
    df["dst"] = df["dst"].astype(str)
    df["stage"] = df["stage"].astype(str)
    df["label"] = df["label"].astype(str)
    df = df.sort_values(["timestamp", "event_id"]).reset_index(drop=True)

    interval_minutes = int(cfg["collector"]["default_interval_minutes"])
    node_budget = int(cfg["collector"]["node_budget"])

    relation_vocab = sorted(df["rel"].dropna().astype(str).unique().tolist())
    default_intervals = build_default_intervals(df, interval_minutes)

    print("[INFO] build_pg.py starting...")
    print(f"[INFO] Input file: {input_csv}")
    print(f"[INFO] Source round: {flag}")
    print(f"[INFO] Default interval (minutes): {interval_minutes}")
    print(f"[INFO] Node budget: {node_budget}")
    print(f"[INFO] Total events: {len(df)}")
    print(f"[INFO] Total default intervals: {len(default_intervals)}")
    print(f"[INFO] Relation vocab size: {len(relation_vocab)}")

    retained_total = 0
    for interval in default_intervals:
        retained_total += recursive_construct_pg(
            all_events_df=df,
            interval=interval,
            out_root=pg_root,
            node_budget=node_budget,
            relation_vocab=relation_vocab,
            source_round=flag,
            inherited_markers=[],
        )

    print(f"[INFO] Total retained PG bundles: {retained_total}")
    summarize_pg_results(pg_root)


if __name__ == "__main__":
    main()