from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any

from src.config_utils import load_config


def main() -> None:
    cfg = load_config()

    cdg_root = Path(cfg["paths"]["cdg_dir"])
    coi_ratio = float(cfg["cdg"]["coi_ratio"])

    nodes_path = cdg_root / "cdg_nodes.json"
    edges_path = cdg_root / "cdg_edges.json"
    out_path = cdg_root / "coi_ranked.json"

    with nodes_path.open("r", encoding="utf-8") as f:
        nodes = json.load(f)

    with edges_path.open("r", encoding="utf-8") as f:
        edges = json.load(f)

    in_deg: Dict[str, int] = {}
    out_deg: Dict[str, int] = {}

    for n in nodes:
        gid = n["global_id"]
        in_deg[gid] = 0
        out_deg[gid] = 0

    for e in edges:
        s = e["source_community"]
        t = e["target_community"]
        out_deg[s] = out_deg.get(s, 0) + 1
        in_deg[t] = in_deg.get(t, 0) + 1

    num_nodes = max(len(nodes), 1)
    ranked: List[Dict[str, Any]] = []

    for n in nodes:
        gid = n["global_id"]
        cent = (in_deg.get(gid, 0) + out_deg.get(gid, 0)) / max(2 * (num_nodes - 1), 1)

        record = {
            "global_id": gid,
            "pg_id": n["pg_id"],
            "community_id": n["community_id"],
            "time_span": n["time_span"],
            "anomaly_density": n.get("anomaly_density", 0.0),
            "num_suspicious_nodes": n.get("num_suspicious_nodes", 0),
            "in_degree": in_deg.get(gid, 0),
            "out_degree": out_deg.get(gid, 0),
            "centrality": cent,
        }
        ranked.append(record)

    ranked.sort(
        key=lambda x: (
            -x["centrality"],
            -x["anomaly_density"],
            -x["num_suspicious_nodes"],
            x["global_id"],
        )
    )

    top_k = max(1, int(len(ranked) * coi_ratio))
    for i, item in enumerate(ranked):
        item["is_coi"] = i < top_k
        item["coi_rank"] = i + 1 if i < top_k else None

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(ranked, f, indent=2)

    print("[OK] COI ranking finished.")
    print(f"Total nodes ranked: {len(ranked)}")
    print(f"Top-K ratio: {coi_ratio}")
    print(f"Selected COIs: {top_k}")
    print(f"Saved to: {out_path}")


if __name__ == "__main__":
    main()