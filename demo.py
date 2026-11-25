"""Run the comparative SYN defense demonstration and build its evidence report."""
import argparse
from collections import Counter, deque
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import subprocess
import sys
import time

from client_benchmark import probe
from generate_charts import write_report
from lab_http import service
from pressure_model import CAPACITY, DEFAULT_REQUESTS, REQUEST_PROFILES, SCENARIOS, TICKS, QueueModel
from syn_defense_agent import DefenseAgent, Reading, timestamp

BASE = Path(__file__).resolve().parent


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def probes_per_window(requests):
    base, remainder = divmod(requests, TICKS)
    return tuple(base + (index < remainder) for index in range(TICKS))


def compare(output, pace, say, requests=DEFAULT_REQUESTS):
    probes, windows, events = [], [], []
    pending = deque()
    schedule = probes_per_window(requests)
    with service(pending.popleft) as port:
        say(f"Local HTTP service ready on 127.0.0.1:{port}/health")
        for scenario in SCENARIOS:
            model = QueueModel(scenario)
            agent = DefenseAgent(20, 2, model.enable_cookies) if scenario.automated else None
            say(f"\n{scenario.title}")
            for tick, probe_count in enumerate(schedule, 1):
                active_during_window = model.cookies
                window = model.step(tick, probe_count)
                pending.extend(window.decisions)
                window_probes = []
                for number, verdict in enumerate(window.decisions, 1):
                    result = probe("127.0.0.1", port)
                    expected = 200 if verdict == "served" else 503
                    if result.status != expected or result.outcome not in {"ok", "http_error"}:
                        raise RuntimeError(f"Unexpected HTTP result at {scenario.key}/{tick}/{number}: {result}")
                    window_probes.append(dict(
                        scenario=scenario.key, tick=tick, probe=number, modeled_verdict=verdict,
                        defense_active=active_during_window, **asdict(result),
                    ))
                if pending:
                    raise RuntimeError("HTTP handler did not consume every scheduled verdict")
                probes.extend(window_probes)
                stamp = timestamp()
                if agent:
                    decision = agent.sample(Reading(stamp, window.syn_recv_count, window.syn_ack_ratio))
                    if decision.event:
                        say(f"  {stamp}  {decision.event}; SYN_RECV={decision.syn_recv_count}; "
                            f"defense={decision.defense_status} for next window")
                    events.append(dict(scenario=scenario.key, tick=tick, **asdict(decision)))
                fields = asdict(window)
                fields.pop("decisions")
                codes = Counter(row["status"] for row in window_probes)
                windows.append(dict(
                    scenario=scenario.key, timestamp=stamp, defense_active=active_during_window,
                    http_200=codes[200], http_503=codes[503], **fields,
                ))
                say(f"  Window {tick}  queue {window.syn_recv_count:2}/{CAPACITY}  "
                    f"200 x{codes[200]}  503 x{codes[503]}  "
                    f"filter drops {window.per_source_drops:2}  upstream blocked {window.upstream_drops}")
                if pace:
                    time.sleep(pace)
    write_csv(output / "http.csv", probes)
    write_csv(output / "windows.csv", windows)
    write_csv(output / "agent.csv", events)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="New directory for this run")
    parser.add_argument("--pace", type=float, default=0, help="Seconds between model windows")
    parser.add_argument("--requests", type=int, choices=REQUEST_PROFILES, default=DEFAULT_REQUESTS,
                        help="Legitimate HTTP probes per scenario (default: %(default)s)")
    parser.add_argument("--kernel-check", action="store_true",
                        help="Add an isolated Linux kernel and benign packet capture verification")
    args = parser.parse_args()
    if not args.pace >= 0:
        parser.error("Pacing must be nonnegative")
    suffix = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    output = (args.out or BASE / "runs" / suffix).resolve()
    output.mkdir(parents=True)
    logging.basicConfig(filename=output / "agent.log", level=logging.INFO,
                        format="%(levelname)s %(message)s")
    with (output / "console.txt").open("w") as journal:
        def say(message):
            print(message, flush=True)
            print(message, file=journal, flush=True)

        say("TCP SYN defense lab | modeled pressure and live loopback HTTP")
        say(f"{args.requests} legitimate HTTP probes per scenario over {TICKS} model windows")
        compare(output, args.pace, say, args.requests)
        if args.kernel_check:
            say("\nLinux kernel verification | disposable loopback-only namespace")
            environment = os.environ.copy()
            environment["SYN_LAB_PARENT_NETNS"] = os.readlink("/proc/self/ns/net")
            try:
                result = subprocess.run(
                    ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable,
                     str(BASE / "kernel_check.py"), str(output)],
                    env=environment, text=True, capture_output=True, check=False,
                )
            except OSError as error:
                error_details = str(error)
            else:
                error_details = result.stderr.strip() or result.stdout.strip()
                (output / "kernel-check.log").write_text(result.stderr + result.stdout)
                if result.returncode == 0:
                    say(result.stdout.strip())
                    error_details = ""
                elif not error_details:
                    error_details = f"Kernel check exited with status {result.returncode}"
            if error_details:
                (output / "kernel-error.txt").write_text(error_details + "\n")
                say(f"Kernel verification failed. See {output / 'kernel-error.txt'}")
        write_report(output)
        say(f"\nEvidence report {output / 'report.html'}")
        if args.kernel_check and (output / "kernel-error.txt").exists():
            sys.exit(1)


if __name__ == "__main__":
    main()
