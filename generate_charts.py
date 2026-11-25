"""Build a standalone report and charts from the recorded CSV evidence."""
import argparse
from collections import defaultdict
import csv
from html import escape
import json
from pathlib import Path
from statistics import mean

from pressure_model import CAPACITY, SCENARIOS


STYLE = """
:root{color-scheme:dark;--bg:#0c1723;--panel:#122234;--line:#304054;--text:#eff5fc;
--muted:#b4c4d5;--blue:#8bc9ff;--teal:#61e2cc;--amber:#ffb785}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}
main{max-width:1160px;margin:auto;padding:46px 35px 64px}
h1{font-size:clamp(34px,5vw,60px);line-height:1.06;letter-spacing:-.055em;margin:12px 0 14px}
h2{font-size:29px;line-height:1.15;letter-spacing:-.03em;margin:30px 0 12px}
h3{font-size:20px;margin:0 0 8px} p{margin:0 0 14px;color:var(--muted)}
a{color:var(--blue);text-underline-offset:4px} a:focus-visible{outline:2px solid var(--teal)}
.kicker{font-size:13px;color:var(--teal);font-weight:750;letter-spacing:.115em;text-transform:uppercase}
.lead{max-width:80ch;font-size:17px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px;margin-top:22px}
.card,.chart{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px 20px}
.card.success strong{color:var(--teal)}.card.failure strong{color:var(--amber)}
.big{display:block;font-size:36px;font-weight:750;line-height:1.15;letter-spacing:-.04em;margin-bottom:5px}
.card p{margin:4px 0 0}.chart h3{margin-bottom:15px}
.bar-row{display:grid;grid-template-columns:160px minmax(50px,1fr) 67px;gap:8px;align-items:center;margin:8px 0;font-size:13px}
.track{height:9px;background:#26394d;border-radius:8px;overflow:hidden;display:flex}
.fill{height:100%;background:var(--teal)}.fill.fail{background:var(--amber)}
.fill.queue{background:var(--blue)}.fill.latency{background:#a1a9ff}
.value{text-align:right;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:14px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
thead th{color:var(--muted);font-weight:600}tbody th{font-weight:600}
.scroller{overflow:auto}
.files{display:flex;flex-wrap:wrap;gap:8px 20px;padding:0;list-style:none}
.mono{font-family:ui-monospace,monospace}.small{font-size:13px}.bad{color:var(--amber)}
footer{margin-top:28px;color:var(--muted)}
@media(max-width:800px){main{padding:26px 18px}.grid{grid-template-columns:1fr}.bar-row{grid-template-columns:134px 1fr 64px}}
"""
SHORT = {
    "baseline": "Baseline", "open-single": "Open · single",
    "open-distributed": "Open · changing", "filter-single": "Filter · single",
    "filter-distributed": "Filter · changing", "auto-success": "Auto · recovery",
    "auto-failure": "Auto · upstream limit",
}


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def summarize(output):
    probes, windows = defaultdict(list), defaultdict(list)
    for row in read_csv(output / "http.csv"):
        probes[row["scenario"]].append(row)
    for row in read_csv(output / "windows.csv"):
        windows[row["scenario"]].append(row)
    summary = []
    for scenario in SCENARIOS:
        key = scenario.key
        rows = probes[key]
        successful = [float(row["latency_ms"]) for row in rows if row["outcome"] == "ok"]
        active = [row for row in rows if row["defense_active"] == "True"]
        during_pressure = [row for row in rows if row["defense_active"] == "False" and int(row["tick"]) >= 2]
        before = sum(row["outcome"] == "ok" for row in during_pressure)
        after = sum(row["outcome"] == "ok" for row in active)
        peak = max(int(row["syn_recv_count"]) for row in windows[key])
        summary.append(dict(
            scenario=key, attempted=len(rows), successful=len(successful),
            success_pct=round(100 * len(successful) / len(rows), 1),
            avg_success_ms=round(mean(successful), 3) if successful else None,
            peak_syn_recv=peak, modeled_capacity=CAPACITY,
            peak_utilization_pct=round(100 * peak / CAPACITY, 1),
            filter_drops=sum(int(row["per_source_drops"]) for row in windows[key]),
            upstream_drops=sum(int(row["upstream_drops"]) for row in windows[key]),
            before_active_success=before, before_active_attempted=len(during_pressure),
            active_success=after, active_attempted=len(active),
        ))
    return summary


def bar(label, value, primary, css="", secondary=0):
    return (f'<div class="bar-row"><span>{label}</span><span class="track" aria-hidden="true">'
            f'<span class="fill {css}" style="width:{primary}%"></span>'
            f'<span class="fill fail" style="width:{secondary}%"></span></span>'
            f'<span class="value">{value}</span></div>')


def write_report(output):
    summary = summarize(output)
    with (output / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=summary[0])
        writer.writeheader()
        writer.writerows(summary)
    success, failure = summary[-2:]
    cards = ""
    for style, title, row in (("success", "Service recovers", success), ("failure", "Service stays impaired", failure)):
        before = f"{row['before_active_success']}/{row['before_active_attempted']}"
        after = f"{row['active_success']}/{row['active_attempted']}"
        reason = ("Cookies let legitimate connections bypass the full modeled backlog."
                  if style == "success" else "The upstream limit still admits about one quarter of probes.")
        cards += (f'<article class="card {style}"><h3>{title}</h3>'
                  f'<strong class="big">{before} → {after}</strong>'
                  f'<p>HTTP 200 during pressure, before and after activation. {reason}</p></article>')
    avail, queues, latency, table = [], [], [], []
    ceiling = max(row["avg_success_ms"] or 0 for row in summary) * 1.1 or 1
    for row, scenario in zip(summary, SCENARIOS):
        short = SHORT[scenario.key]
        pct = row["success_pct"]
        avail.append(bar(short, f"{pct:g}%", pct, secondary=100 - pct))
        queue = row["peak_utilization_pct"]
        queues.append(bar(short, f"{row['peak_syn_recv']}/{CAPACITY}", queue, "queue"))
        ms = row["avg_success_ms"]
        latency.append(bar(short, f"{ms:.3f}" if ms is not None else "—", 100 * (ms or 0) / ceiling, "latency"))
        table.append(f"<tr><th scope='row'>{escape(scenario.title)}</th><td>{row['successful']}/{row['attempted']}</td>"
                     f"<td>{pct:g}%</td><td>{row['peak_syn_recv']}/{CAPACITY}</td>"
                     f"<td>{row['filter_drops']}</td><td>{row['upstream_drops']}</td></tr>")
    log = []
    for row in read_csv(output / "agent.csv"):
        if row["event"]:
            log.append(f"<tr><th scope='row'>{SHORT[row['scenario']]}</th><td>{row['timestamp']}</td>"
                       f"<td>{row['tick']}</td><td>{row['syn_recv_count']}</td>"
                       f"<td>{row['syn_ack_ratio'] or '—'}</td><td>{row['defense_status']}</td></tr>")
    kernel_path = output / "kernel-check.json"
    files = ["summary.csv", "http.csv", "windows.csv", "agent.csv", "agent.log", "console.txt"]
    if (output / "kernel-error.txt").exists():
        kernel = '<p class="bad">Verification failed. See the linked error log.</p>'
        files += ["kernel-error.txt"]
    elif kernel_path.exists():
        k = json.loads(kernel_path.read_text())
        delta, pcap, cookies = k["test_deltas"], k["packet_capture"], k["cookies"]
        kernel = (
            f'<div class="grid"><article class="card"><h3>Linux SYN cookies</h3>'
            f'<strong class="big">{delta["SyncookiesSent"]} sent · {delta["SyncookiesRecv"]} validated</strong>'
            f'<p>Kernel {escape(k["kernel"])}. Setting {cookies["original"]} → {cookies["active"]} → '
            f'{cookies["restored"]}. The demo firewall was removed.</p></article>'
            f'<article class="card"><h3>Benign packet capture</h3><strong class="big">{pcap["http_200"]} HTTP 200</strong>'
            f'<p>{pcap["streams"]} TCP streams and {pcap["frames"]} frames on loopback.</p></article></div>'
            '<p class="small">A fixed alert fixture triggered Linux cookie test mode. Standard GETs exercised '
            'real TCP handshakes and the firewall admit counter.</p>'
        )
        files.extend(["kernel-check.json", "kernel-check.log", "kernel-http.csv", "benign-http.pcap",
                      "handshakes.tsv", "firewall-before.txt", "firewall-after.txt"])
    else:
        kernel = '<p>Run with <code>--kernel-check</code> to add Linux cookie counters and a benign packet capture.</p>'
    links = "".join(f'<li><a href="{name}">{name}</a></li>' for name in files)
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCP SYN defense lab results</title><style>{STYLE}</style></head>
<body><main>
<div class="kicker">Network security experiment</div><h1>TCP SYN defense lab</h1>
<p class="lead">Compare per-source filtering and automated SYN-cookie mitigation. Each scenario runs
{summary[0]['attempted']} legitimate localhost HTTP probes under fixed modeled conditions. The separate Linux
check exercises kernel cookies with ordinary TCP connections.</p>
<div class="grid">{cards}</div>
<h2>Comparative results</h2>
<div class="grid">
<section class="chart"><h3>HTTP 200 and 503 share</h3>{''.join(avail)}
<p class="small">Green indicates 200. Orange indicates 503.</p></section>
<section class="chart"><h3>Peak modeled SYN queue</h3>{''.join(queues)}</section>
<section class="chart"><h3>Mean HTTP 200 latency · ms</h3>{''.join(latency)}
<p class="small">Local HTTP response times for successful probes.</p></section>
</div>
<div class="scroller"><table><thead><tr><th scope="col">Scenario</th><th scope="col">HTTP 200</th>
<th scope="col">Success</th><th scope="col">Queue peak</th><th scope="col">Modeled filter drops</th>
<th scope="col">Modeled upstream drops</th></tr></thead><tbody>{''.join(table)}</tbody></table></div>
<h2>Detector transitions</h2><p>Two consecutive observations at or above 20 half-open connections activate the
defense for the next sample window. The SYN-to-ACK ratio is diagnostic and is blank if completions are zero.</p>
<div class="scroller"><table><thead><tr><th scope="col">Scenario</th><th scope="col">UTC timestamp</th>
<th scope="col">Window</th><th scope="col">SYN_RECV</th><th scope="col">SYN/ACK</th>
<th scope="col">Defense</th></tr></thead><tbody>{''.join(log)}</tbody></table></div>
<h2>Linux kernel verification</h2>{kernel}
<h2>Evidence files</h2><ul class="files">{links}</ul>
<footer>Model rejection is represented by an application-generated 503. The model expresses queue and upstream
bottlenecks. The isolated capture records benign traffic. Real-world flood performance is outside these measurements.</footer>
</main></body></html>"""
    (output / "report.html").write_text(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    write_report(args.run)


if __name__ == "__main__":
    main()
