from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Tuple, Any, Set

import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F

from src.config_utils import load_config

try:
    from torch_geometric.data import Data
    from torch_geometric.nn import GCNConv
except ImportError as e:
    raise ImportError("torch-geometric is required.") from e

try:
    import networkx as nx
except ImportError as e:
    raise ImportError("networkx is required.") from e


EPS = 1e-8


class GNNEncoder(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, emb_dim: int):
        super().__init__()
        self.conv1 = GCNConv(in_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, emb_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        z = self.conv2(h, edge_index)
        return z


def get_device(cfg: Dict[str, Any]) -> torch.device:
    runtime_cfg = cfg.get("runtime", {})
    device_cfg = str(runtime_cfg.get("device", "auto")).lower()
    prefer_gpu = bool(runtime_cfg.get("prefer_gpu", True))

    if device_cfg == "cpu":
        return torch.device("cpu")
    if device_cfg == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("Config requests CUDA but CUDA is not available.")
        return torch.device("cuda")
    if device_cfg == "auto":
        if prefer_gpu and torch.cuda.is_available():
            return torch.device("cuda")
        return torch.device("cpu")
    raise ValueError(f"Unsupported device config: {device_cfg}")


def list_pg_bundles(pg_root: Path) -> List[Path]:
    bundles = []
    for p in pg_root.iterdir():
        if p.is_dir() and p.name != "_split_markers" and (p / "metadata.json").exists():
            bundles.append(p)
    bundles.sort(key=lambda x: x.name)
    return bundles


def load_metadata(bundle_dir: Path) -> Dict[str, Any]:
    with (bundle_dir / "metadata.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def load_graph_bundle(bundle_dir: Path) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any], List[Dict[str, Any]]]:
    events_df = pd.read_csv(bundle_dir / "events.csv")
    nodes_df = pd.read_csv(bundle_dir / "nodes.csv")
    edges_df = pd.read_csv(bundle_dir / "edges.csv")
    feat_df = pd.read_csv(bundle_dir / "node_features.csv")
    meta = load_metadata(bundle_dir)

    boundary_path = bundle_dir / "boundary_markers.json"
    if boundary_path.exists():
        with boundary_path.open("r", encoding="utf-8") as f:
            boundary_markers = json.load(f)
    else:
        boundary_markers = []

    events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])
    return events_df, nodes_df, edges_df, feat_df, meta, boundary_markers


def build_node_index(nodes_df: pd.DataFrame) -> Dict[str, int]:
    return {str(nid): idx for idx, nid in enumerate(nodes_df["node_id"].astype(str).tolist())}


def build_edge_index(edges_df: pd.DataFrame, node_to_idx: Dict[str, int]) -> torch.Tensor:
    src_idx = []
    dst_idx = []
    for _, row in edges_df.iterrows():
        s = str(row["src"])
        d = str(row["dst"])
        if s in node_to_idx and d in node_to_idx:
            src_idx.append(node_to_idx[s])
            dst_idx.append(node_to_idx[d])
    if len(src_idx) == 0:
        idx = torch.arange(len(node_to_idx), dtype=torch.long)
        return torch.stack([idx, idx], dim=0)
    return torch.tensor([src_idx, dst_idx], dtype=torch.long)


def compute_local_refs(z: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
    num_nodes = z.shape[0]
    refs = torch.zeros_like(z)
    counts = torch.zeros((num_nodes, 1), dtype=z.dtype, device=z.device)

    src = edge_index[0]
    dst = edge_index[1]
    for s, d in zip(src.tolist(), dst.tolist()):
        if s == d:
            continue
        refs[s] += z[d]
        refs[d] += z[s]
        counts[s] += 1.0
        counts[d] += 1.0

    counts = torch.clamp(counts, min=1.0)
    refs = refs / counts
    return refs


def detect_communities_from_edges(node_ids: List[str], edges_df: pd.DataFrame) -> Dict[str, int]:
    g = nx.Graph()
    g.add_nodes_from(node_ids)
    for _, row in edges_df.iterrows():
        s = str(row["src"])
        d = str(row["dst"])
        if s != d:
            g.add_edge(s, d)

    try:
        import igraph as ig
        import leidenalg

        node_list = list(g.nodes())
        idx_map = {n: i for i, n in enumerate(node_list)}
        ig_graph = ig.Graph()
        ig_graph.add_vertices(len(node_list))
        ig_graph.add_edges([(idx_map[u], idx_map[v]) for u, v in g.edges()])

        part = leidenalg.find_partition(ig_graph, leidenalg.ModularityVertexPartition)
        assignment = {}
        for cid, cluster in enumerate(part):
            for idx in cluster:
                assignment[node_list[idx]] = cid

        next_cid = max(assignment.values(), default=-1) + 1
        for n in node_list:
            if n not in assignment:
                assignment[n] = next_cid
                next_cid += 1
        return assignment

    except Exception:
        communities = list(nx.algorithms.community.greedy_modularity_communities(g))
        assignment = {}
        for cid, comm in enumerate(communities):
            for n in comm:
                assignment[str(n)] = cid
        next_cid = len(communities)
        for n in node_ids:
            if n not in assignment:
                assignment[n] = next_cid
                next_cid += 1
        return assignment


def compute_proto_matrix(z: torch.Tensor, node_ids: List[str], assignment: Dict[str, int]) -> Tuple[Dict[int, torch.Tensor], torch.Tensor]:
    community_to_indices: Dict[int, List[int]] = {}
    for idx, nid in enumerate(node_ids):
        cid = assignment[nid]
        community_to_indices.setdefault(cid, []).append(idx)

    proto_dict: Dict[int, torch.Tensor] = {}
    proto_matrix = torch.zeros_like(z)

    for cid, idxs in community_to_indices.items():
        proto = z[idxs].mean(dim=0)
        proto_dict[cid] = proto
        for i in idxs:
            proto_matrix[i] = proto

    return proto_dict, proto_matrix


def normalize_scores(scores: pd.Series) -> pd.Series:
    min_v = scores.min()
    max_v = scores.max()
    if max_v > min_v:
        return (scores - min_v) / (max_v - min_v + EPS)
    return pd.Series([0.0] * len(scores), index=scores.index)


def build_undirected_adj(edges_df: pd.DataFrame) -> Dict[str, Set[str]]:
    adj: Dict[str, Set[str]] = {}
    for _, row in edges_df.iterrows():
        s = str(row["src"])
        d = str(row["dst"])
        adj.setdefault(s, set()).add(d)
        adj.setdefault(d, set()).add(s)
    return adj


def build_directed_adj(edges_df: pd.DataFrame) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    out_adj: Dict[str, List[str]] = {}
    in_adj: Dict[str, List[str]] = {}
    for _, row in edges_df.iterrows():
        s = str(row["src"])
        d = str(row["dst"])
        out_adj.setdefault(s, []).append(d)
        in_adj.setdefault(d, []).append(s)
        out_adj.setdefault(d, [])
        in_adj.setdefault(s, [])
    return out_adj, in_adj


def get_n_hop_neighbors(seed: str, undirected_adj: Dict[str, Set[str]], n_hop: int) -> List[str]:
    visited = {seed}
    q = deque([(seed, 0)])
    out = set()

    while q:
        cur, depth = q.popleft()
        if depth == n_hop:
            continue
        for nb in undirected_adj.get(cur, set()):
            if nb not in visited:
                visited.add(nb)
                out.add(nb)
                q.append((nb, depth + 1))
    return sorted(out)


def extract_anchor_nodes(boundary_markers: List[Dict[str, Any]]) -> List[str]:
    anchors = set()
    for marker in boundary_markers:
        for n in marker.get("bridge_nodes", []):
            anchors.add(str(n))
    return sorted(anchors)


def bounded_causal_traversal(
    seed: str,
    suspicious_set: Set[str],
    allowed_context_nodes: Set[str],
    out_adj: Dict[str, List[str]],
    in_adj: Dict[str, List[str]],
    max_length: int,
    budget: int,
) -> List[List[str]]:

    paths: List[List[str]] = []
    expanded = 0

    def expand(direction_adj: Dict[str, List[str]]) -> None:
        nonlocal expanded
        q = deque([[seed]])

        while q and expanded < budget:
            path = q.popleft()
            cur = path[-1]
            paths.append(path)

            if len(path) >= max_length:
                continue

            for nb in direction_adj.get(cur, []):
                if nb in path:
                    continue
                if nb in suspicious_set or nb in allowed_context_nodes:
                    q.append(path + [nb])
                    expanded += 1
                    if expanded >= budget:
                        break

    expand(out_adj)
    expand(in_adj)

    # deduplicate by tuple
    uniq = []
    seen = set()
    for p in paths:
        t = tuple(p)
        if len(t) >= 2 and t not in seen:
            seen.add(t)
            uniq.append(list(t))
    return uniq


def merge_overlapping_subchains(subchains: List[List[str]]) -> List[List[str]]:
    merged: List[Set[str]] = []

    for chain in subchains:
        cset = set(chain)
        found = False
        for existing in merged:
            if len(existing.intersection(cset)) >= max(1, min(len(existing), len(cset)) // 2):
                existing.update(cset)
                found = True
                break
        if not found:
            merged.append(set(cset))

    out = [sorted(list(s)) for s in merged]
    out.sort(key=lambda x: (len(x), x))
    return out


def build_archived_traces(events_df: pd.DataFrame) -> List[str]:
    traces = []
    sorted_df = events_df.sort_values(["timestamp", "event_id"])
    for _, row in sorted_df.iterrows():
        traces.append(
            f"[{pd.to_datetime(row['timestamp']).strftime('%H:%M:%S')}] "
            f"({row['src']}, {row['rel']}, {row['dst']})"
        )
    return traces


def main() -> None:
    cfg = load_config()
    device = get_device(cfg)

    pg_root = Path(cfg["paths"]["pg_dir"])
    detector_dir = Path(cfg["paths"]["detector_dir"])
    detector_dir.mkdir(parents=True, exist_ok=True)

    ckpt_path = detector_dir / "detector_checkpoint.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(f"Detector checkpoint not found: {ckpt_path}")

    checkpoint = torch.load(ckpt_path, map_location=device)
    feature_cols = checkpoint["feature_cols"]
    hidden_dim = int(checkpoint["hidden_dim"])
    emb_dim = int(checkpoint["emb_dim"])

    model = GNNEncoder(in_dim=len(feature_cols), hidden_dim=hidden_dim, emb_dim=emb_dim).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    delta = float(cfg["detector"]["threshold_delta"])
    n_hop = int(cfg["detector"]["n_hop"])
    max_length = int(cfg["detector"]["traversal_max_length"])
    budget = int(cfg["detector"]["traversal_budget"])

    bundles = list_pg_bundles(pg_root)
    print("[INFO] infer_suspicious_nodes.py starting...")
    print(f"[INFO] Device: {device}")
    print(f"[INFO] PG bundles to infer: {len(bundles)}")
    print(f"[INFO] Threshold delta: {delta}")

    for bundle_dir in bundles:
        pg_name = bundle_dir.name
        out_dir = detector_dir / pg_name
        out_dir.mkdir(parents=True, exist_ok=True)

        events_df, nodes_df, edges_df, feat_df, meta, boundary_markers = load_graph_bundle(bundle_dir)
        feat_df = feat_df.sort_values("node_id").reset_index(drop=True)

        node_ids = feat_df["node_id"].astype(str).tolist()
        node_to_idx = build_node_index(nodes_df)
        edge_index = build_edge_index(edges_df, node_to_idx)

        x = torch.tensor(feat_df[feature_cols].astype(float).values, dtype=torch.float32).to(device)
        edge_index = edge_index.to(device)

        with torch.no_grad():
            z = model(x, edge_index)
            local_refs = compute_local_refs(z, edge_index)
            assignment = detect_communities_from_edges(node_ids, edges_df)
            _, proto_matrix = compute_proto_matrix(z, node_ids, assignment)

            d_local = torch.sum((z - local_refs) ** 2, dim=1).cpu().numpy()
            d_comm = torch.sum((z - proto_matrix) ** 2, dim=1).cpu().numpy()
            s_raw = d_local + d_comm

        node_score_df = pd.DataFrame({
            "node_id": node_ids,
            "community_id": [assignment[nid] for nid in node_ids],
            "d_local": d_local,
            "d_comm": d_comm,
            "s_raw": s_raw,
        })
        node_score_df["s"] = normalize_scores(node_score_df["s_raw"])
        node_score_df["is_suspicious"] = node_score_df["s"] >= delta

        suspicious_nodes = set(node_score_df.loc[node_score_df["is_suspicious"], "node_id"].astype(str).tolist())

        undirected_adj = build_undirected_adj(edges_df)
        out_adj, in_adj = build_directed_adj(edges_df)
        anchor_nodes = set(extract_anchor_nodes(boundary_markers))

        # precompute 2-hop neighborhoods for suspicious nodes
        suspicious_nhop_map: Dict[str, List[str]] = {}
        allowed_context_nodes_global: Set[str] = set(anchor_nodes)

        for sn in suspicious_nodes:
            nhops = get_n_hop_neighbors(sn, undirected_adj, n_hop)
            suspicious_nhop_map[sn] = nhops
            allowed_context_nodes_global.update(nhops)

        # candidate subchains
        raw_subchains: List[List[str]] = []
        for sn in suspicious_nodes:
            raw_subchains.extend(
                bounded_causal_traversal(
                    seed=sn,
                    suspicious_set=suspicious_nodes,
                    allowed_context_nodes=allowed_context_nodes_global,
                    out_adj=out_adj,
                    in_adj=in_adj,
                    max_length=max_length,
                    budget=budget,
                )
            )
        merged_subchains = merge_overlapping_subchains(raw_subchains)

        # community-level evidence
        community_records = []
        archived_traces = build_archived_traces(events_df)

        for cid in sorted(set(assignment.values())):
            comm_nodes = [nid for nid in node_ids if assignment[nid] == cid]
            comm_score_df = node_score_df[node_score_df["community_id"] == cid].copy()
            comm_suspicious = comm_score_df[comm_score_df["is_suspicious"]]["node_id"].astype(str).tolist()

            n_hop_neighbors = {}
            for sn in comm_suspicious:
                n_hop_neighbors[sn] = suspicious_nhop_map.get(sn, [])

            community_subchains = []
            for chain in merged_subchains:
                if len(set(chain).intersection(set(comm_nodes))) > 0:
                    community_subchains.append(chain)

            anomaly_density = float(len(comm_suspicious) / max(len(comm_nodes), 1))

            node_scores = {
                row["node_id"]: {
                    "d_local": float(row["d_local"]),
                    "d_comm": float(row["d_comm"]),
                    "s": float(row["s"]),
                }
                for _, row in comm_score_df.iterrows()
                if bool(row["is_suspicious"])
            }

            record = {
                "metadata": {
                    "community_id": f"C{cid:03d}",
                    "pg_id": pg_name,
                    "time_span": meta["time_span"],
                },
                "anomaly_contexts": {
                    "suspicious_nodes": comm_suspicious,
                    "node_scores": node_scores,
                    "n_hop_neighbors": n_hop_neighbors,
                    "candidate_attack_subchains": community_subchains,
                    "anomaly_density": anomaly_density,
                    "bridge_intensity": None,
                },
                "boundary_cues": {
                    "matched_anchor_nodes": sorted(list(anchor_nodes.intersection(set(comm_nodes)))),
                    "split_boundary_markers": [m.get("marker_id") for m in boundary_markers],
                },
                "archived_traces": archived_traces,
            }
            community_records.append(record)

        suspicious_out = out_dir / "suspicious_nodes.csv"
        community_out = out_dir / "community_records.json"
        subchain_out = out_dir / "candidate_attack_subchains.json"
        summary_out = out_dir / "inference_summary.json"

        node_score_df.to_csv(suspicious_out, index=False, encoding="utf-8")

        with community_out.open("w", encoding="utf-8") as f:
            json.dump(community_records, f, indent=2)

        with subchain_out.open("w", encoding="utf-8") as f:
            json.dump(merged_subchains, f, indent=2)

        summary = {
            "pg_name": pg_name,
            "is_benign_pg": bool(meta.get("is_benign", False)),
            "is_malicious_pg": bool(meta.get("is_malicious", False)),
            "num_nodes": int(len(node_ids)),
            "num_edges": int(len(edges_df)),
            "num_communities": int(len(set(assignment.values()))),
            "num_suspicious_nodes": int(len(suspicious_nodes)),
            "num_candidate_subchains": int(len(merged_subchains)),
            "threshold_delta": delta,
        }
        with summary_out.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(
            f"[PG] {pg_name} | communities={summary['num_communities']} "
            f"suspicious_nodes={summary['num_suspicious_nodes']} "
            f"subchains={summary['num_candidate_subchains']}"
        )

    print("[OK] Detector inference finished.")


if __name__ == "__main__":
    main()