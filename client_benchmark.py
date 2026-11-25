"""Send ordinary HTTP GET requests to a loopback service and record results."""
import argparse
import csv
from dataclasses import asdict, dataclass
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
from pathlib import Path
import time

from syn_defense_agent import timestamp


@dataclass(frozen=True)
class Probe:
    timestamp: str
    status: int | None
    outcome: str
    latency_ms: float


def probe(host, port, timeout=3.0):
    if not ip_address(host).is_loopback:
        raise ValueError("The benchmark accepts loopback IP addresses only")
    connection = HTTPConnection(host, port, timeout=timeout)
    started = time.perf_counter()
    status = None
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        status = response.status
        response.read()
        outcome = "ok" if status == 200 else "http_error"
    except TimeoutError:
        outcome = "timeout"
    except (OSError, HTTPException):
        outcome = "transport_error"
    finally:
        connection.close()
    return Probe(timestamp(), status, outcome, round((time.perf_counter() - started) * 1000, 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--csv", type=Path, default=Path("http-benchmark.csv"))
    args = parser.parse_args()
    try:
        local = ip_address(args.host).is_loopback
    except ValueError:
        local = False
    if not local or not 1 <= args.port <= 65535 or args.requests < 1 or not args.timeout > 0 or not args.interval >= 0:
        parser.error("Use a loopback IP address, valid port and valid request settings")
    with args.csv.open("x", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=Probe.__dataclass_fields__)
        writer.writeheader()
        for index in range(args.requests):
            result = probe(args.host, args.port, args.timeout)
            writer.writerow(asdict(result))
            output.flush()
            print(f"{index + 1:2}  {result.status or '-':>3}  {result.outcome:16} {result.latency_ms:.3f} ms")
            if index + 1 < args.requests:
                time.sleep(args.interval)


if __name__ == "__main__":
    main()
