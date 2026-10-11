"""AgentBreak security regression CLI.

Supports running regression suites via the documented REST API:
  python -m agentbreak.cli regress --mode fixture --defense gateway
  python -m agentbreak.cli regress --mode live --defense gateway
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def _make_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    """Execute an HTTP request with JSON serialization."""
    data_bytes = None
    req_headers = dict(headers)
    if body is not None:
        data_bytes = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8")
            if "application/json" in content_type or raw.strip().startswith(("{", "[")):
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, {"raw": raw}
            return resp.status, {"text": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"error": {"code": "http_error", "message": raw}}


def run_regress(
    server_url: str,
    mode: str,
    defense: str,
    scenario_ids: list[str],
    timeout: float,
    poll_interval: float,
) -> int:
    """Execute regression suite via REST API and evaluate assertions.

    Exit code semantics:
      0: All required suite assertions pass.
      1: Verified security failure or clean benign regression failure.
      2: Setup / transport / inconclusive evaluation / timeout error.
    """
    token = os.environ.get("DEMO_ACCESS_TOKEN", "").strip()
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    base_url = server_url.rstrip("/")

    # 1. Health check
    health_url = f"{base_url}/api/health"
    try:
        status_code, health_data = _make_request("GET", health_url, headers=headers, timeout=5.0)
    except Exception as exc:
        print(f"Error: Unable to connect to AgentBreak service at {health_url}: {exc}", file=sys.stderr)
        return 2

    if status_code != 200 or health_data.get("status") != "ok":
        print(f"Error: Server health check failed (HTTP {status_code}): {health_data}", file=sys.stderr)
        return 2

    if mode == "live" and not health_data.get("live_ready"):
        print(
            "Error: Server reports live mode is not ready (missing credentials or ALLOW_LIVE_RUNS=false). "
            "Missing live credentials cannot execute live evaluation.",
            file=sys.stderr,
        )
        return 2

    # 2. Submit regression suite run
    runs_url = f"{base_url}/api/runs"
    payload = {
        "scenario_ids": scenario_ids,
        "operation": "suite",
        "defense": defense,
        "execution_mode": mode,
    }
    try:
        status_code, run_resp = _make_request("POST", runs_url, headers=headers, body=payload, timeout=10.0)
    except Exception as exc:
        print(f"Error: Failed to submit regression run: {exc}", file=sys.stderr)
        return 2

    if status_code != 202 or "run_id" not in run_resp:
        err_msg = run_resp.get("error", {}).get("message", str(run_resp))
        print(f"Error: Server rejected run creation (HTTP {status_code}): {err_msg}", file=sys.stderr)
        return 2

    run_id = run_resp["run_id"]
    print("Regression suite run started:")
    print(f"  Run ID:    {run_id}")
    print(f"  Mode:      {mode}")
    print(f"  Defense:   {defense}")
    print(f"  Scenarios: {', '.join(scenario_ids)}")
    print("Polling execution status...", flush=True)

    # 3. Poll until terminal state
    detail_url = f"{base_url}/api/runs/{run_id}"
    start_time = time.monotonic()
    deadline = start_time + timeout
    terminal_statuses = {"completed", "failed", "cancelled", "interrupted"}
    run_detail: dict[str, Any] | None = None

    while True:
        if time.monotonic() > deadline:
            print(f"Error: Regression run timed out after {timeout:.1f}s", file=sys.stderr)
            return 2

        try:
            status_code, data = _make_request("GET", detail_url, headers=headers, timeout=10.0)
            if status_code == 200:
                run_detail = data
                run_status = data.get("run", {}).get("status", "")
                progress = data.get("run", {}).get("progress", {})
                scheduled = progress.get("scheduled", 0)
                completed = progress.get("completed", 0)
                phase = progress.get("phase", "")
                elapsed = time.monotonic() - start_time
                print(
                    f"  [{elapsed:5.1f}s] status={run_status:<10} phase={phase:<8} completed={completed}/{scheduled}",
                    flush=True,
                )

                if run_status in terminal_statuses:
                    break
            else:
                print(f"Warning: Non-200 while polling run: HTTP {status_code}", file=sys.stderr)
        except Exception as exc:
            print(f"Warning: Transient error during polling: {exc}", file=sys.stderr)

        time.sleep(poll_interval)

    if run_detail is None:
        print("Error: Failed to retrieve run outcome details.", file=sys.stderr)
        return 2

    run_info = run_detail.get("run", {})
    final_status = run_info.get("status")
    if final_status != "completed":
        error_detail = run_info.get("error")
        print(f"Error: Run finished with non-completed status '{final_status}': {error_detail}", file=sys.stderr)
        return 2

    cases: list[dict[str, Any]] = run_detail.get("cases", [])
    if not cases:
        print("Error: Run completed with no case results.", file=sys.stderr)
        return 2

    # 4. Tally outcomes
    total_cases = len(cases)
    benign_cases = [c for c in cases if c.get("candidate_id") is None]
    attack_cases = [c for c in cases if c.get("candidate_id") is not None]

    inconclusive_cases = [
        c for c in cases
        if c.get("oracle_outcome") == "inconclusive" or c.get("status") in ("timed_out", "failed", "cancelled")
    ]
    benign_successes = [c for c in benign_cases if c.get("benign_success") is True]
    benign_failures = [c for c in benign_cases if c.get("benign_success") is not True]

    attack_successes = [c for c in attack_cases if c.get("oracle_outcome") == "success"]
    attack_held = [c for c in attack_cases if c.get("oracle_outcome") == "failure"]

    print("\n" + "=" * 60)
    print("AGENTBREAK REGRESSION SUITE RESULTS")
    print("=" * 60)
    print(f"Run ID:             {run_id}")
    print(f"Execution Mode:     {mode}")
    print(f"Defense Preset:     {defense}")
    print(f"Final Status:       {final_status}")
    print()
    print("Case Counts:")
    print(f"  Total Scheduled:  {total_cases}")
    print(f"  Inconclusive:     {len(inconclusive_cases)}")
    print()
    print("Clean / Benign Tasks:")
    print(f"  Total Benign:     {len(benign_cases)}")
    print(f"  Successful:       {len(benign_successes)}")
    print(f"  Failed:           {len(benign_failures)}")
    print()
    print("Attack Cases:")
    print(f"  Total Attacks:    {len(attack_cases)}")
    print(f"  Defense Held:     {len(attack_held)}")
    print(f"  Attacks Succeeded:{len(attack_successes)}")

    if attack_successes:
        print("\nVerified Violations:")
        for c in attack_successes:
            for v in c.get("violations", []):
                print(f"  - [{v.get('kind')}] Impact: {v.get('impact')} in trial {c.get('trial_id')}")

    print()
    print("Download Evidence Export:")
    print(f"  JSON:     {base_url}/api/runs/{run_id}/export?format=json")
    print(f"  Markdown: {base_url}/api/runs/{run_id}/export?format=markdown")
    print("=" * 60)

    # 5. Evaluate assertions
    if inconclusive_cases:
        print(f"\nFAILURE: {len(inconclusive_cases)} case(s) were inconclusive or incomplete.", file=sys.stderr)
        return 2

    if benign_failures:
        print(f"\nFAILURE: {len(benign_failures)} benign task(s) failed.", file=sys.stderr)
        return 1

    if defense == "gateway" and attack_successes:
        print(
            f"\nFAILURE: {len(attack_successes)} attack(s) succeeded despite gateway defense.",
            file=sys.stderr,
        )
        return 1

    print("\nSUCCESS: All regression assertions passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentbreak",
        description="AgentBreak security regression CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    regress_parser = subparsers.add_parser("regress", help="Execute regression suite")
    regress_parser.add_argument(
        "--mode",
        choices=["fixture", "live"],
        default="fixture",
        help="Execution mode (default: fixture)",
    )
    regress_parser.add_argument(
        "--defense",
        choices=["baseline", "gateway"],
        default="gateway",
        help="Defense preset (default: gateway)",
    )
    regress_parser.add_argument(
        "--server-url",
        default=os.environ.get("AGENTBREAK_SERVER_URL", "http://localhost:8000"),
        help="AgentBreak API base URL (default: http://localhost:8000)",
    )
    regress_parser.add_argument(
        "--scenario-ids",
        nargs="+",
        default=["doc_exfil", "email_bola"],
        help="Scenario IDs to test (default: doc_exfil email_bola)",
    )
    regress_parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0)",
    )
    regress_parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Overall timeout in seconds (default: 300.0)",
    )

    args = parser.parse_args(argv)
    if args.subcommand == "regress":
        return run_regress(
            server_url=args.server_url,
            mode=args.mode,
            defense=args.defense,
            scenario_ids=args.scenario_ids,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
        )

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

