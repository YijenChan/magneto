from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.config_utils import load_config


def load_flag(signal_path: Path) -> int:
    if not signal_path.exists():
        raise FileNotFoundError(f"Signal file not found: {signal_path}")

    with signal_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    flag = data.get("flag", None)
    if flag not in [1, 2]:
        raise ValueError(f"Invalid flag value: {flag}. Expected 1 or 2.")
    return int(flag)


def main() -> None:
    cfg = load_config()

    toy_dir = Path(cfg["paths"]["toy_data_dir"])
    input_csv = toy_dir / cfg["data"]["toy_dataset_name"]
    signal_path = Path(cfg["paths"]["config_dir"]) / "investigation_signal.json"

    if not input_csv.exists():
        raise FileNotFoundError(f"Toy dataset not found: {input_csv}")

    df = pd.read_csv(input_csv)
    required_cols = {
        "event_id", "timestamp", "src", "rel", "dst",
        "stage", "label", "is_attack_related", "round"
    }
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in dataset: {sorted(missing)}")

    flag = load_flag(signal_path)

    selected_df = df[df["round"] == flag].copy()
    selected_df = selected_df.sort_values(["timestamp", "event_id"]).reset_index(drop=True)

    output_csv = toy_dir / f"toy_magneto_round{flag}.csv"
    selected_df.to_csv(output_csv, index=False, encoding="utf-8")

    print("[OK] Round log selection finished.")
    print(f"Signal flag: {flag}")
    print(f"Input file: {input_csv}")
    print(f"Output file: {output_csv}")
    print(f"Selected rows: {len(selected_df)}")
    print(f"Attack rows: {(selected_df['label'] == 'malicious').sum()}")
    print(f"Benign rows: {(selected_df['label'] == 'benign').sum()}")
    print(f"Unique entities: {len(set(selected_df['src']).union(set(selected_df['dst'])))}")


if __name__ == "__main__":
    main()