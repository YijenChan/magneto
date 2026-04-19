from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple, Any

import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F

from src.config_utils import load_config

try:
    from torch_geometric.data import Data
    from torch_geometric.nn import GCNConv
except ImportError as e:
    raise ImportError(
        "torch-geometric is required. Please install torch-geometric first."
    ) from e

try:
    import networkx as nx
except ImportError as e:
    raise ImportError("networkx is required.") from e


EPS = 1e-8


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
        if p.is_dir() and p.name != "_split_markers":
            if (p / "metadata.json").exists():
                bundles.append(p)
    bundles.sort(key=lambda x: x.name)
    return bundles


def load_metadata(bundle_dir: Path) -> Dict[str, Any]:
    with (bundle_dir / "metadata.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def select_benign_bundles(pg_root: Path) -> List[Path]:
    out = []
    for bundle in list_pg_bundles(pg_root):
        meta = load_metadata(bundle)
        if bool(meta.get("is_benign", False)):
            out.append(bundle)
    return out


def load_graph_bundle(bundle_dir: Path) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    nodes_df = pd.read_csv(bundle_dir / "nodes.csv")
    edges_df = pd.read_csv(bundle_dir / "edges.csv")
    feat_df = pd.read_csv(bundle_dir / "node_features.csv")
    meta = load_metadata(bundle_dir)

    if len(nodes_df) == 0:
        raise ValueError(f"Empty nodes.csv in {bundle_dir}")
    if len(feat_df) == 0:
        raise ValueError(f"Empty node_features.csv in {bundle_dir}")

    return nodes_df, edges_df, feat_df, meta


def feature_columns_from_df(feat_df: pd.DataFrame) -> List[str]:
    excluded = {"node_id", "node_type"}
    cols = [c for c in feat_df.columns if c not in excluded]
    return cols


def build_node_index(nodes_df: pd.DataFrame) -> Dict[str, int]:
    return {str(nid): idx for idx, nid in enumerate(nodes_df["node_id"].astype(str).tolist())}


def build_edge_index(edges_df: pd.DataFrame, node_to_idx: Dict[str, int]) -> torch.Tensor:
    src_idx = []
    dst_idx = []

    if len(edges_df) == 0:
        # isolated graph fallback: self-loop on each node is handled elsewhere
        return torch.empty((2, 0), dtype=torch.long)

    for _, row in edges_df.iterrows():
        s = str(row["src"])
        d = str(row["dst"])
        if s in node_to_idx and d in node_to_idx:
            src_idx.append(node_to_idx[s])
            dst_idx.append(node_to_idx[d])

    if len(src_idx) == 0:
        return torch.empty((2, 0), dtype=torch.long)

    return torch.tensor([src_idx, dst_idx], dtype=torch.long)


def ensure_nonempty_edges(edge_index: torch.Tensor, num_nodes: int) -> torch.Tensor:
    if edge_index.numel() > 0:
        return edge_index

    # fallback: self-loops
    idx = torch.arange(num_nodes, dtype=torch.long)
    return torch.stack([idx, idx], dim=0)


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


def pairwise_cosine_logits(q: torch.Tensor, k: torch.Tensor, temperature: float) -> torch.Tensor:
    q = F.normalize(q, dim=-1)
    k = F.normalize(k, dim=-1)
    return torch.matmul(q, k.T) / temperature


def info_nce_loss(queries: torch.Tensor, positives: torch.Tensor, temperature: float) -> torch.Tensor:
    logits = pairwise_cosine_logits(queries, positives, temperature)
    labels = torch.arange(queries.shape[0], device=queries.device)
    return F.cross_entropy(logits, labels)


def build_data_from_bundle(bundle_dir: Path, feature_cols: List[str]) -> Tuple[Data, List[str], pd.DataFrame]:
    nodes_df, edges_df, feat_df, _ = load_graph_bundle(bundle_dir)

    feat_df = feat_df.sort_values("node_id").reset_index(drop=True)
    node_ids = feat_df["node_id"].astype(str).tolist()
    node_to_idx = {nid: idx for idx, nid in enumerate(node_ids)}

    x = torch.tensor(feat_df[feature_cols].astype(float).values, dtype=torch.float32)
    edge_index = build_edge_index(edges_df, node_to_idx)
    edge_index = ensure_nonempty_edges(edge_index, len(node_ids))

    data = Data(x=x, edge_index=edge_index)
    return data, node_ids, edges_df


def main() -> None:
    cfg = load_config()
    device = get_device(cfg)

    pg_root = Path(cfg["paths"]["pg_dir"])
    detector_dir = Path(cfg["paths"]["detector_dir"])
    detector_dir.mkdir(parents=True, exist_ok=True)

    benign_bundles = select_benign_bundles(pg_root)
    if not benign_bundles:
        raise RuntimeError("No benign PG bundles found for detector training.")

    sample_nodes_df, sample_edges_df, sample_feat_df, _ = load_graph_bundle(benign_bundles[0])
    feature_cols = feature_columns_from_df(sample_feat_df)

    hidden_dim = int(cfg["detector"]["hidden_dim"])
    emb_dim = int(cfg["detector"]["emb_dim"])
    lr = float(cfg["detector"]["lr"])
    weight_decay = float(cfg["detector"]["weight_decay"])
    epochs = int(cfg["detector"]["epochs"])
    temperature = float(cfg["detector"]["temperature"])

    model = GNNEncoder(in_dim=len(feature_cols), hidden_dim=hidden_dim, emb_dim=emb_dim).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)

    print("[INFO] train_detector.py starting...")
    print(f"[INFO] Device: {device}")
    print(f"[INFO] Benign PG bundles: {len(benign_bundles)}")
    print(f"[INFO] Feature dim: {len(feature_cols)}")
    print(f"[INFO] Hidden dim: {hidden_dim}")
    print(f"[INFO] Emb dim: {emb_dim}")

    epoch_losses: List[float] = []

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        valid_graphs = 0

        for bundle_dir in benign_bundles:
            data, node_ids, edges_df = build_data_from_bundle(bundle_dir, feature_cols)

            x = data.x.to(device)
            edge_index = data.edge_index.to(device)

            optimizer.zero_grad()

            z = model(x, edge_index)
            a = compute_local_refs(z, edge_index)
            assignment = detect_communities_from_edges(node_ids, edges_df)
            _, proto_matrix = compute_proto_matrix(z, node_ids, assignment)

            loss_local = info_nce_loss(z, a, temperature)
            loss_comm = info_nce_loss(z, proto_matrix, temperature)
            loss = loss_local + loss_comm

            loss.backward()
            optimizer.step()

            total_loss += float(loss.item())
            valid_graphs += 1

        mean_loss = total_loss / max(valid_graphs, 1)
        epoch_losses.append(mean_loss)

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"[Epoch {epoch + 1:03d}] mean_loss={mean_loss:.6f}")

    ckpt_path = detector_dir / "detector_checkpoint.pt"
    summary_path = detector_dir / "train_detector_summary.json"

    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "feature_cols": feature_cols,
            "hidden_dim": hidden_dim,
            "emb_dim": emb_dim,
            "temperature": temperature,
        },
        ckpt_path,
    )

    summary = {
        "num_benign_pgs": len(benign_bundles),
        "feature_cols": feature_cols,
        "feature_dim": len(feature_cols),
        "hidden_dim": hidden_dim,
        "emb_dim": emb_dim,
        "epochs": epochs,
        "lr": lr,
        "weight_decay": weight_decay,
        "temperature": temperature,
        "final_mean_loss": epoch_losses[-1] if epoch_losses else None,
        "loss_curve": epoch_losses,
    }
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("[OK] Detector training finished.")
    print(f"Checkpoint saved to: {ckpt_path}")
    print(f"Summary saved to: {summary_path}")


if __name__ == "__main__":
    main()