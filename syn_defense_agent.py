"""Detect sustained half-open socket pressure and invoke a mitigation callback."""
import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path
import signal
import time
from typing import Callable

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Reading:
    timestamp: str
    syn_recv_count: int
    syn_ack_ratio: float | None


@dataclass(frozen=True)
class Decision:
    timestamp: str
    syn_recv_count: int
    syn_ack_ratio: float | None
    defense_status: str
    consecutive: int
    event: str


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class DefenseAgent:
    def __init__(self, threshold: int, windows: int, activate: Callable[[], None]):
        if threshold < 1 or windows < 1:
            raise ValueError("Threshold and window count must be positive")
        self.threshold = threshold
        self.windows = windows
        self.activate = activate
        self.consecutive = 0
        self.active = False

    def sample(self, reading: Reading) -> Decision:
        self.consecutive = self.consecutive + 1 if reading.syn_recv_count >= self.threshold else 0
        event = ""
        status = "active" if self.active else "watching"
        if not self.active and self.consecutive >= self.windows:
            event = "suspected SYN flood"
            LOGGER.warning(
                "%s %s | SYN_RECV=%d SYN/ACK=%s consecutive=%d",
                reading.timestamp, event, reading.syn_recv_count, reading.syn_ack_ratio,
                self.consecutive,
            )
            try:
                self.activate()
            except (RuntimeError, OSError):
                LOGGER.exception("Mitigation failed")
                status = "error"
            else:
                self.active = True
                status = "active"
                LOGGER.info("%s defense active", timestamp())
        return Decision(**asdict(reading), defense_status=status,
                        consecutive=self.consecutive, event=event)


def read_syn_recv(port):
    count = 0
    for name in ("tcp", "tcp6"):
        try:
            with Path("/proc/net", name).open() as table:
                next(table)
                for row in table:
                    fields = row.split()
                    if fields[3] == "03" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                        count += 1
        except FileNotFoundError:
            if name == "tcp":
                raise
    return count


def enabled_cookies():
    path = Path("/proc/sys/net/ipv4/tcp_syncookies")
    if path.read_text().strip() == "0":
        path.write_text("1\n")
    if path.read_text().strip() not in {"1", "2"}:
        raise RuntimeError("Could not verify Linux SYN cookies")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--threshold", type=int, default=20)
    parser.add_argument("--windows", type=int, default=2)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--csv", type=Path, default=Path("live-agent.csv"))
    parser.add_argument("--enable-cookies", action="store_true",
                        help="Enable Linux overflow-mode SYN cookies if currently disabled")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not args.interval > 0 or args.threshold < 1 or args.windows < 1:
        parser.error("Use a valid port and positive sampling arguments")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    activate = enabled_cookies if args.enable_cookies else lambda: LOGGER.info("Alert-only mode")
    agent = DefenseAgent(args.threshold, args.windows, activate)
    with args.csv.open("x", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=Decision.__dataclass_fields__)
        writer.writeheader()
        try:
            while True:
                result = asdict(agent.sample(Reading(timestamp(), read_syn_recv(args.port), None)))
                if not args.enable_cookies and result["defense_status"] == "active":
                    result["defense_status"] = "alert-only"
                writer.writerow(result)
                output.flush()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
