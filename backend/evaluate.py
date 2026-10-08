"""Evaluate stages 3-7 offline; --live optionally evaluates Gemini on bounded fixtures."""
import argparse
import asyncio
import json
import time
import math
from datetime import datetime, timezone
from pathlib import Path
from app.ai.gemini_client import GeminiTriageClient
from app.ai.prompt import PROMPT_VERSION
from app.api.engine import bundle_from_features
from app.api.engine import close_components, components
from app.features.schemas import BehaviorFeatures


def summarize_results(results):
    """Availability and fixture agreement are separate from detector accuracy."""
    accepted = [row for row in results if row["triage"] is not None]
    durations = sorted(row["elapsed_seconds"] for row in results)
    return {
        "accepted_fraction": len(accepted) / len(results) if results else 0,
        "fixture_match_count": sum(row["category_matches_fixture"] is True for row in accepted),
        "fixture_mismatch_ids": [row["id"] for row in accepted if not row["category_matches_fixture"]],
        "unavailable_ids": [row["id"] for row in results if row["triage"] is None],
        "latency_seconds": {str(q): durations[max(0, math.ceil(len(durations) * q / 100) - 1)]
                            for q in (50, 95, 100)} if durations else {},
    }

async def evaluate(args):
    rows = json.loads((Path(__file__).parent / "evaluation/triage_packets.json").read_text())
    if args.fixture_id:
        wanted = set(args.fixture_id)
        if wanted - {row['id'] for row in rows}:
            raise SystemExit('Unknown fixture ID; see evaluation/triage_packets.json.')
        rows = [row for row in rows if row['id'] in wanted]
    rows = rows[:args.limit]
    ai = GeminiTriageClient() if args.live else None
    if ai and ai.client is None:
        raise SystemExit("Set GEMINI_API_KEY in backend/.env for --live. Offline evaluation needs no key.")
    runtime = components()
    detector, rules, fusion = runtime.detector, runtime.rules, runtime.fusion
    results = []
    try:
        for index, row in enumerate(rows):
            started = time.monotonic()
            bundle = bundle_from_features(BehaviorFeatures(**row["features"]), "0x" + "0" * 40, "research-vault")
            bundle.simulated = True
            bundle.history_confidence = row["history_confidence"]
            anomaly = detector.score(bundle.vector)
            evidence = bundle.evidence_packet(anomaly)
            rule, reasons = rules.evaluate(evidence)
            triage, status = None, "offline_no_api"
            if ai:
                try:
                    # Deliberately tests every selected packet, including below-trigger cases.
                    triage = await ai.triage(evidence)
                    status = "ok" if triage else "fallback"
                except TimeoutError:
                    status = "timeout"
            risk, codes, review = fusion.compute_fused_risk(anomaly, rule, 0, triage, reasons)
            results.append({"id": row["id"], "simulated": True, "anomaly_score": anomaly,
                "rule_score": rule, "risk_score": risk, "requires_review": review,
                "reason_codes": [c.value for c in codes], "gemini_status": status,
                "triage": triage.model_dump() if triage else None,
                "category_matches_fixture": triage.category in row["expected_categories"] if triage else None,
                "elapsed_seconds": round(time.monotonic() - started, 3)})
            if ai:
                print(f"{row['id']}: {status}", flush=True)
                if index + 1 < len(rows):
                    await asyncio.sleep(max(0, args.interval - (time.monotonic() - started)))
    finally:
        if ai:
            await ai.aclose()
        await close_components()
    return {"mode": "live" if args.live else "offline", "prompt_version": PROMPT_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "model": ai.model_name if ai else None,
        "api": ai.api_mode if ai else None,
        "timeout_seconds": ai.timeout_seconds if ai else None,
        "thinking_level": ai.thinking_level if ai else None,
        "request_interval_seconds": args.interval if ai else None,
        "packet_count": len(results), "accepted_triage_count": sum(r["triage"] is not None for r in results),
        "summary": summarize_results(results),
        "limitations": "Synthetic review fixtures, not a production accuracy benchmark. Offline mode does not test Gemini semantics.",
        "results": results}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Send selected fixtures to Gemini (API charges may apply)")
    parser.add_argument("--limit", type=int, default=25, help="Maximum fixture/API calls; use 1 for smoke test")
    parser.add_argument("--output", default="evaluation/report.json")
    parser.add_argument("--fixture-id", action="append", help="Select a specific fixture; repeat to select several")
    parser.add_argument("--interval", type=float, default=3.1,
                        help="Minimum seconds between live request starts (default: 3.1; avoids burst quotas)")
    args = parser.parse_args()
    if not 1 <= args.limit <= 25:
        parser.error("--limit must be between 1 and 25")
    if not math.isfinite(args.interval) or args.interval < 0:
        parser.error("--interval must be finite and non-negative")
    report = asyncio.run(evaluate(args))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['packet_count']} packets; {report['accepted_triage_count']} accepted Gemini results; report: {path}")
    if args.live and report["accepted_triage_count"] != report["packet_count"]:
        raise SystemExit(1)  # Partial availability must not appear to pass the full live check.

if __name__ == "__main__":
    main()
