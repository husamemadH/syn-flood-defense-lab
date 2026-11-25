"""Verify real kernel SYN cookies, firewall counters and a benign HTTP capture."""
import argparse
from contextlib import contextmanager
import csv
from dataclasses import asdict
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from client_benchmark import Probe, probe
from lab_http import service
from syn_defense_agent import DefenseAgent, Reading, read_syn_recv, timestamp

COOKIE_PATH = Path("/proc/sys/net/ipv4/tcp_syncookies")
COUNTERS = ("SyncookiesSent", "SyncookiesRecv", "SyncookiesFailed")
BASE = Path(__file__).resolve().parent
PORT = 18080
PROBES = 6


def command(*args, **kwargs):
    return subprocess.run(args, text=True, check=True, **kwargs)


def firewall(action):
    try:
        return command("bash", str(BASE / "firewall_rules.sh"), action, str(PORT),
                       capture_output=True).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"Firewall {action}: {error.stderr.strip()}") from error


def stats():
    lines = Path("/proc/net/netstat").read_text().splitlines()
    for names, values in zip(lines[::2], lines[1::2]):
        if names.startswith("TcpExt:") and values.startswith("TcpExt:"):
            fields = dict(zip(names.split()[1:], map(int, values.split()[1:])))
            return {key: fields[key] for key in COUNTERS}
    raise RuntimeError("Linux TcpExt counters are unavailable")


def measure(port, phase):
    rows = []
    for seq in range(1, PROBES + 1):
        result = probe("127.0.0.1", port)
        rows.append(dict(phase=phase, probe=seq, **asdict(result)))
    return rows


@contextmanager
def capture(output):
    path = output / "benign-http.pcap"
    with (output / "capture.log").open("w+") as log:
        process = subprocess.Popen(
            ["dumpcap", "-q", "-P", "-i", "lo", "-f", f"tcp port {PORT}", "-w", str(path)],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read().strip())
                if path.exists() and path.stat().st_size >= 24:
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("Packet capture did not become ready")
            yield path
            wait_for_responses(path, process)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def wait_for_responses(path, process):
    # Loopback requests can finish before libpcap delivers its first buffered batch.
    deadline = time.monotonic() + 5
    checked_size = 24
    while time.monotonic() < deadline and process.poll() is None:
        size = path.stat().st_size
        if size > checked_size:
            checked_size = size
            observed = subprocess.run(
                ["tshark", "-n", "-r", str(path), "-d", f"tcp.port=={PORT},http",
                 "-Y", "http.response.code == 200", "-T", "fields", "-e", "http.response.code"],
                text=True, capture_output=True,
            )
            if observed.returncode == 0 and len(observed.stdout.splitlines()) >= PROBES * 2:
                return
        time.sleep(0.05)
    raise RuntimeError("Capture did not receive every HTTP response. See capture.log")


def packet_summary(path, output):
    names = ("frame.number", "tcp.stream", "ip.src", "ip.dst", "tcp.srcport",
             "tcp.dstport", "tcp.flags", "http.response.code")
    with (output / "handshakes.tsv").open("w") as table:
        command("tshark", "-n", "-r", str(path), "-d", f"tcp.port=={PORT},http",
                "-T", "fields", "-E", "header=y",
                *(part for field in names for part in ("-e", field)),
                stdout=table, stderr=subprocess.DEVNULL)
    with (output / "handshakes.tsv").open() as table:
        rows = list(csv.DictReader(table, delimiter="\t"))
    return dict(
        frames=len(rows),
        streams=len({row["tcp.stream"] for row in rows if row["tcp.stream"]}),
        initial_syns=sum(row["tcp.flags"] == "0x0002" for row in rows),
        syn_acks=sum(row["tcp.flags"] == "0x0012" for row in rows),
        http_200=sum(row["http.response.code"] == "200" for row in rows),
    )


def run(output):
    namespace = os.readlink("/proc/self/ns/net")
    if not os.environ.get("SYN_LAB_PARENT_NETNS") or namespace == os.environ["SYN_LAB_PARENT_NETNS"]:
        raise RuntimeError("Kernel check requires a separate network namespace")
    for binary in ("ip", "nft", "dumpcap", "tshark"):
        if not shutil.which(binary):
            raise RuntimeError(f"Kernel check requires {binary}")
    command("ip", "link", "set", "lo", "up")
    interfaces = json.loads(command("ip", "-j", "link", "show", capture_output=True).stdout)
    if [item["ifname"] for item in interfaces] != ["lo"]:
        raise RuntimeError("Kernel check requires loopback as the sole interface")
    original = COOKIE_PATH.read_text().strip()
    installed = False

    def activate():
        nonlocal installed
        firewall("apply")
        installed = True
        COOKIE_PATH.write_text("2\n")
        if COOKIE_PATH.read_text().strip() != "2":
            raise RuntimeError("Could not verify kernel cookie test mode")

    with capture(output) as packet_file, service(lambda: "served", PORT) as port:
        before = stats()
        observed = read_syn_recv(port)
        rows = measure(port, "normal")
        after_normal = stats()
        agent = DefenseAgent(20, 2, activate)
        try:
            # The detector consumes a fixed alert fixture. All network traffic is ordinary HTTP.
            decisions = [agent.sample(Reading(timestamp(), 32, None)) for _ in range(2)]
            if not agent.active:
                raise RuntimeError("Kernel mitigation failed")
            active_mode = COOKIE_PATH.read_text().strip()
            rules_before = firewall("status")
            rows.extend(measure(port, "cookie_test_mode"))
            after_test = stats()
            rules_after = firewall("status")
        finally:
            try:
                if installed:
                    firewall("reset")
            finally:
                if COOKIE_PATH.read_text().strip() != original:
                    COOKIE_PATH.write_text(original + "\n")

    restored = COOKIE_PATH.read_text().strip()
    firewall_absent = subprocess.run(
        ["nft", "list", "table", "ip", "syn_defense_lab"], capture_output=True,
    ).returncode != 0
    summary = dict(
        kernel=os.uname().release,
        namespace=namespace,
        interfaces=["lo"],
        service=f"127.0.0.1:{port}",
        tcp_max_syn_backlog=Path("/proc/sys/net/ipv4/tcp_max_syn_backlog").read_text().strip(),
        tcp_synack_retries=Path("/proc/sys/net/ipv4/tcp_synack_retries").read_text().strip(),
        observed_baseline_syn_recv=observed,
        cookies=dict(original=original, active=active_mode, restored=restored),
        counters=dict(before=before, after_normal=after_normal, after_test=after_test),
        test_deltas={key: after_test[key] - after_normal[key] for key in COUNTERS},
        fixture_decisions=[asdict(decision) for decision in decisions],
        packet_capture=packet_summary(packet_file, output),
        firewall_removed=firewall_absent,
    )
    (output / "kernel-check.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "firewall-before.txt").write_text(rules_before)
    (output / "firewall-after.txt").write_text(rules_after)
    with (output / "kernel-http.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("phase", "probe", *Probe.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(rows)
    if (restored != original or not firewall_absent
            or any(row["outcome"] != "ok" for row in rows)
            or any(summary["test_deltas"][key] < PROBES for key in COUNTERS[:2])
            or summary["test_deltas"]["SyncookiesFailed"]
            or summary["packet_capture"]["http_200"] != PROBES * 2
            or f"counter packets {PROBES} " not in rules_after
            or rules_before.count("counter packets 0 ") != 2):
        raise RuntimeError("Kernel check evidence failed validation. Inspect kernel-check.json")
    print(f"Kernel check: {PROBES * 2} HTTP 200 responses, "
          f"{summary['test_deltas']['SyncookiesSent']} SYN cookies sent, "
          f"{summary['test_deltas']['SyncookiesRecv']} validated, original configuration restored.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    run(args.output)


if __name__ == "__main__":
    main()
