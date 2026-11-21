#!/usr/bin/env bash
# Download the third-party benchmark material used by build_dataset.py into
# evals/external/. All sources are MIT licensed (license files are saved alongside).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p external/agentdojo external/injecagent external/llmail
AD=https://raw.githubusercontent.com/ethz-spylab/agentdojo/main
for f in baseline_attacks.py important_instructions_attacks.py; do
  curl -fsSL -o "external/agentdojo/$f" "$AD/src/agentdojo/attacks/$f"
done
curl -fsSL -o external/agentdojo/LICENSE "$AD/LICENSE"
IA=https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main
for f in user_cases.jsonl attacker_cases_ds.jsonl attacker_cases_dh.jsonl; do
  curl -fsSL -o "external/injecagent/$f" "$IA/data/$f"
done
curl -fsSL -o external/injecagent/LICENSE "$IA/LICENCE"
HF=https://huggingface.co/datasets/microsoft/llmail-inject-challenge/resolve/main
for f in scenarios.json objectives_descriptions.json levels_descriptions.json; do
  curl -fsSL -o "external/llmail/$f" "$HF/data/$f"
done
curl -fsSL -o external/llmail/labelled_phase2.json "$HF/data/labelled_unique_submissions_phase2.json"
curl -fsSL -o external/llmail/README.md "$HF/README.md"
echo "done. Now: python3 evals/build_dataset.py"
