#!/usr/bin/env python3
"""Run the detonation-chamber eval set and score it.

Usage:
  python3 evals/run_evals.py                         # all cases, trusting persona
  python3 evals/run_evals.py --persona default       # stock agent behaviour
  python3 evals/run_evals.py --model z-ai/glm-5.3-flash --jobs 6 --repeat 2
  python3 evals/run_evals.py --only m01,b03          # subset

Each case is written to a temp file and passed to `detonate --payload-file`.
Results go to evals/results/<timestamp>-<model>-<persona>/ as results.jsonl and
summary.md. Labels: "malicious" (should be flagged), "benign" and
"hard_benign" (should be Safe). Scoring is reported two ways:

  strict  — only a Malicious verdict counts as a detection
  lenient — Malicious or Suspicious counts as a detection

Standard library only.
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = ROOT / "target" / "release" / "detonate"


def run_case(case, args, rep):
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(case["payload"])
        payload_file = f.name
    cmd = [
        str(args.bin), "--payload-file", payload_file, "--output", "json",
        "--persona", args.persona, "--framing", args.framing,
        "--max-turns", str(args.max_turns), "--timeout", str(args.timeout),
    ]
    if args.model:
        cmd += ["--model", args.model]
    if args.thinking:
        cmd += ["--thinking", args.thinking]
    if args.no_traffic_review:
        cmd += ["--no-traffic-review"]
    if args.firecracker:
        cmd += ["--firecracker"]
    started = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout + 60, cwd=ROOT)
        stdout, stderr, code = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, code = "", "harness timeout", -1
    finally:
        os.unlink(payload_file)
    elapsed = time.time() - started

    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        report = {"verdict": "error", "confidence": 0, "metadata": {"error": (stderr or stdout)[-500:]}}

    meta = report.get("metadata") or {}
    if args.reports_dir:
        (args.reports_dir / f"{case['id']}-{rep}.json").write_text(json.dumps(report, indent=2))
    return {
        "id": case["id"],
        "rep": rep,
        "label": case["label"],
        "category": case["category"],
        "verdict": report.get("verdict", "error"),
        "confidence": report.get("confidence"),
        "exit_code": code,
        "signals": meta.get("signals", []),
        "turns": meta.get("turns"),
        "tool_calls": meta.get("tool_calls"),
        "terminated_reason": meta.get("terminated_reason"),
        "input_tokens": meta.get("input_tokens", 0),
        "output_tokens": meta.get("output_tokens", 0),
        "error": meta.get("error"),
        "elapsed_secs": round(elapsed, 1),
        "agent_output": next(
            (e["description"][len("Agent output: "):] for e in reversed(report.get("behavioral_timeline", []))
             if e.get("description", "").startswith("Agent output: ")),
            "",
        )[:400],
    }


def score(results):
    def is_mal(r):
        return r["label"] == "malicious"

    scored = [r for r in results if r["verdict"] != "error"]
    errors = [r for r in results if r["verdict"] == "error"]
    out = {"total": len(results), "errors": len(errors)}
    for mode, positive in (("strict", {"malicious"}), ("lenient", {"malicious", "suspicious"})):
        tp = sum(1 for r in scored if is_mal(r) and r["verdict"] in positive)
        fn = sum(1 for r in scored if is_mal(r) and r["verdict"] not in positive)
        fp = sum(1 for r in scored if not is_mal(r) and r["verdict"] in positive)
        tn = sum(1 for r in scored if not is_mal(r) and r["verdict"] not in positive)
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / (tp + fn) if tp + fn else float("nan")
        f1 = 2 * prec * rec / (prec + rec) if tp and (prec + rec) else 0.0
        out[mode] = dict(tp=tp, fn=fn, fp=fp, tn=tn, precision=prec, recall=rec, f1=f1,
                         fpr=fp / (fp + tn) if fp + tn else float("nan"))
    return out


def fmt_pct(x):
    return "n/a" if x != x else f"{x * 100:.0f}%"


def write_summary(results, args, outdir, wall):
    s = score(results)
    by_label = defaultdict(Counter)
    for r in results:
        by_label[r["label"]][r["verdict"]] += 1
    tokens_in = sum(r["input_tokens"] or 0 for r in results)
    tokens_out = sum(r["output_tokens"] or 0 for r in results)
    lat = sorted(r["elapsed_secs"] for r in results)
    med = lat[len(lat) // 2] if lat else 0

    lines = [
        f"# Eval run — {args.model or 'default model'} / persona={args.persona} / framing={args.framing}"
        f" / isolation={'firecracker' if args.firecracker else 'bwrap'}",
        "",
        f"- Date: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"- Cases: {s['total']} ({args.repeat} repeat(s)); harness errors / Error verdicts: {s['errors']}",
        f"- Wall time: {wall:.0f}s with {args.jobs} parallel jobs; median detonation {med:.0f}s",
        f"- Agent tokens: {tokens_in:,} in / {tokens_out:,} out",
        "",
        "| Mode | TP | FN | FP | TN | Precision | Recall | F1 | False-positive rate |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for mode in ("strict", "lenient"):
        m = s[mode]
        lines.append(
            f"| {mode} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} | {fmt_pct(m['precision'])} | "
            f"{fmt_pct(m['recall'])} | {m['f1']:.2f} | {fmt_pct(m['fpr'])} |"
        )
    lines += ["", "strict = only Malicious counts as detected; lenient = Malicious or Suspicious.", "",
              "## Verdicts by label", "", "| Label | safe | suspicious | malicious | error |", "|---|---|---|---|---|"]
    for label in ("malicious", "benign", "hard_benign"):
        c = by_label.get(label, Counter())
        lines.append(f"| {label} | {c['safe']} | {c['suspicious']} | {c['malicious']} | {c['error']} |")

    lines += ["", "## Per case", "", "| Case | Label | Category | Verdict | Turns | Tools | Top signal |",
              "|---|---|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (r["id"], r["rep"])):
        sig = (r["signals"][0] if r["signals"] else (r["error"] or "")).replace("|", "/")[:110]
        ok = (r["label"] == "malicious") == (r["verdict"] in ("malicious", "suspicious"))
        mark = "" if ok else " ❌"
        lines.append(f"| {r['id']}{'' if args.repeat == 1 else '#' + str(r['rep'])} | {r['label']} | {r['category']} | "
                     f"{r['verdict']}{mark} | {r['turns']} | {r['tool_calls']} | {sig} |")
    (outdir / "summary.md").write_text("\n".join(lines) + "\n")
    return s


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(Path(__file__).parent / "dataset.jsonl"))
    ap.add_argument("--bin", default=str(DEFAULT_BIN))
    ap.add_argument("--model", default=os.environ.get("DAAS_LLM_MODEL"))
    ap.add_argument("--persona", default="trusting", choices=["trusting", "default"])
    ap.add_argument("--framing", default="task", choices=["task", "direct"])
    ap.add_argument("--thinking")
    ap.add_argument("--max-turns", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--only", help="comma-separated case ids")
    ap.add_argument("--no-traffic-review", action="store_true")
    ap.add_argument("--firecracker", action="store_true", help="run each case in a Firecracker microVM")
    ap.add_argument("--out", default=str(Path(__file__).parent / "results"))
    args = ap.parse_args()

    if not Path(args.bin).exists():
        sys.exit(f"detonate binary not found at {args.bin}; run `cargo build --release` first")

    cases = [json.loads(l) for l in open(args.dataset) if l.strip()]
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in wanted]

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    model_tag = (args.model or "default").replace("/", "_")
    iso = "-fc" if args.firecracker else ""
    outdir = Path(args.out) / f"{stamp}-{model_tag}-{args.persona}-{args.framing}{iso}"
    outdir.mkdir(parents=True, exist_ok=True)
    args.reports_dir = outdir / "reports"
    args.reports_dir.mkdir(exist_ok=True)

    jobs = [(c, rep) for rep in range(1, args.repeat + 1) for c in cases]
    print(f"Running {len(jobs)} detonations ({args.jobs} parallel) → {outdir}", flush=True)
    results = []
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool, open(outdir / "results.jsonl", "w") as out:
        futs = {pool.submit(run_case, c, args, rep): (c, rep) for c, rep in jobs}
        for fut in cf.as_completed(futs):
            r = fut.result()
            results.append(r)
            out.write(json.dumps(r) + "\n")
            out.flush()
            print(f"  [{len(results):>3}/{len(jobs)}] {r['id']:<4} {r['label']:<11} → {r['verdict']:<10} "
                  f"({r['elapsed_secs']:.0f}s) {(r['signals'] or [''])[0][:70]}", flush=True)

    s = write_summary(results, args, outdir, time.time() - started)
    print()
    for mode in ("strict", "lenient"):
        m = s[mode]
        print(f"{mode:>8}: precision {fmt_pct(m['precision'])}  recall {fmt_pct(m['recall'])}  "
              f"F1 {m['f1']:.2f}  FPR {fmt_pct(m['fpr'])}  (TP {m['tp']} FN {m['fn']} FP {m['fp']} TN {m['tn']})")
    print(f"   errors: {s['errors']}")
    print(f"\nSummary: {outdir / 'summary.md'}")


if __name__ == "__main__":
    main()
