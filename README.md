# Magneto

**Magneto** is a multi-agent framework for iterative APT investigation over system audit logs.  
It integrates provenance graph construction, benign-only anomaly detection, community dependency modeling, and LLM-guided investigation to reconstruct evidence-grounded attack backbones and generate analyst-readable APT reports.

## Highlights

- **Complexity-bounded provenance graph construction**
- **Benign-only dual-view graph contrastive learning**
- **Community Dependency Graph (CDG) for cross-community investigation**
- **Lead / Assistant / Reporter multi-agent investigation**
- **Iterative investigation with reusable evidence and report generation**

## Pipeline

Magneto follows the workflow below:

1. **Round-based log selection**  
   Select the currently exposed logs for the investigation round.

2. **Collector**  
   Construct complexity-bounded provenance graphs and initialize lightweight node features.

3. **Detector**  
   Train a benign-only detector and extract suspicious nodes, anomaly contexts, and candidate attack subchains.

4. **CDG Construction**  
   Organize detected communities into a Community Dependency Graph with temporal, anchor-based, and entity-alignment dependencies.

5. **Investigation Team**  
   Use Lead / Assistant / Reporter agents to refine attack backbones, verify traces, and generate APT reports.

## Repository Structure

```text
Magneto/
├── config/
├── data/
│   └── toy/
├── prompts/
├── results/
├── Scripts/
│   └── scripts/
└── src/
````

Main scripts:

* `select_round_logs.py`
* `build_pg.py`
* `train_detector.py`
* `infer_suspicious_nodes.py`
* `build_cdg.py`
* `rank_coi.py`
* `run_investigation.py`
* `generate_report.py`

## Input Format

Magneto expects parsed logs in a triplet-style CSV format.

Reference file:

```text id="7oizzu"
data/toy/toy_magneto_dataset.csv
```

Expected columns:

```text id="6pbzgn"
event_id,timestamp,src,rel,dst,stage,label,is_attack_related,round
```

If you want to run Magneto on **DARPA E3** or **DARPA E5**, first convert the original audit logs into the same format as the reference CSV above.

---

## Configuration

Main configuration file:

```text id="f8pyjj"
config/default.yaml
```

Before running Magneto, please configure:

* local paths
* runtime device
* detector hyperparameters
* CDG settings
* LLM settings
* prompt directory
* output directories

Set your API key through an environment variable, for example:

```bash id="vykzx7"
export OPENAI_API_KEY=your_key_here
```

## Quick Start

```bash id="pqj0mm"
python Scripts/scripts/select_round_logs.py
python Scripts/scripts/build_pg.py
python Scripts/scripts/train_detector.py
python Scripts/scripts/infer_suspicious_nodes.py
python Scripts/scripts/build_cdg.py
python Scripts/scripts/rank_coi.py
python Scripts/scripts/run_investigation.py
python Scripts/scripts/generate_report.py
```

## Outputs

Main outputs are stored in:

* `results/pg/`
* `results/detector/`
* `results/cdg/`
* `results/investigation/`
* `results/memory/`
* `results/reports/`

Typical final artifacts include:

* `results/investigation/investigation_result.json`
* `results/reports/apt_report.json`
* `results/reports/apt_report.md`
* `results/reports/ioc_list.json`

## LLM Agents

Magneto uses three role-specific prompts:

* `prompts/lead_system.txt`
* `prompts/assistant_system.txt`
* `prompts/reporter_system.txt`

Please configure your model and API credentials before running the LLM-guided investigation pipeline.

## Notes

* Path settings and API credentials must be configured by the user.
* DARPA E3/E5 logs should be parsed into the same schema as the reference file in `data/toy/`.
* Magneto supports iterative investigation through round-based log exposure and CDG-centered reasoning.
