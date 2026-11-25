"""Render an editable slide deck, browser screenshots and a captioned walkthrough."""
import argparse
import json
from html import escape
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

from generate_charts import STYLE, read_csv, summarize

SCENE_STYLE = """
main{max-width:1160px;padding-top:44px} h1{font-size:57px} .lead{font-size:20px}
.flow{display:grid;grid-template-columns:1fr 45px 1fr 45px 1fr;gap:8px;align-items:center;margin:24px 0}
.flow span{text-align:center;color:var(--teal);font-size:26px}
pre{font:15px/1.58 ui-monospace,monospace;white-space:pre-wrap;margin:0;color:var(--text)}
.card p{margin-bottom:7px} table{font-size:17px}
code{color:var(--teal)} .hint{margin-top:20px}
"""


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def scene(title, lead, body):
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>{escape(title)}</title><style>{STYLE}{SCENE_STYLE}</style><main>
<div class="kicker">TCP SYN defense lab</div><h1>{escape(title)}</h1><p class="lead">{escape(lead)}</p>
{body}</main></html>"""


def case_terminal(output, heading):
    return (output / "console.txt").read_text().split(heading + "\n", 1)[1].split("\n\n", 1)[0]


def slides(output):
    summary = {row["scenario"]: row for row in summarize(output)}
    kernel = json.loads((output / "kernel-check.json").read_text())
    def transition(key):
        row = summary[key]
        return (f"{row['before_active_success']}/{row['before_active_attempted']} before to "
                f"{row['active_success']}/{row['active_attempted']} HTTP 200 after")
    comparative = [
        f"{title}  ·  {summary[key]['successful']}/{summary[key]['attempted']} HTTP 200"
        for key, title in (
            ("baseline", "Baseline"), ("open-single", "Unfiltered · single source"),
            ("open-distributed", "Unfiltered · changing sources"), ("filter-single", "Filter · single source"),
            ("filter-distributed", "Filter · changing sources"),
        )
    ]
    return [
        ("Run the comparison", [
            "python demo.py --kernel-check --pace 0.6",
            "In-memory SYN queue and upstream limit",
            "Ordinary TCP connections and measured localhost HTTP responses",
            "Optional disposable Linux namespace for live kernel verification",
        ]),
        ("Per-source firewall", comparative),
        ("Same detector. Two outcomes.", [
            "Activation after two consecutive samples at or above 20 half-open entries",
            f"Recovery  ·  {transition('auto-success')}",
            f"Upstream bottleneck  ·  {transition('auto-failure')}",
            "The modeled backlog stays at 32/32 in both cases",
        ]),
        ("Linux verification", [
            f"{kernel['packet_capture']['http_200']} HTTP 200 responses from benign GETs",
            f"{kernel['test_deltas']['SyncookiesSent']} cookies sent and "
            f"{kernel['test_deltas']['SyncookiesRecv']} validated in kernel test mode",
            "Six initial SYNs admitted by the demo firewall, zero drops",
            "Original cookie setting restored and lab firewall table removed",
        ]),
        ("Interpret the evidence", [
            "HTTP 503 represents a modeled admission failure",
            "Live capture records benign loopback handshakes",
            "Yang et al. studied handshake tracking on a programmable switch",
            "SmartCookie splits cryptographic verification across switches and hosts",
            "See the technical report for scope, sources and limitations",
        ]),
    ]


def write_deck(scratch, target, content):
    styles = "".join(
        f'<style:style style:name="P{name}" style:family="paragraph">'
        f'<style:paragraph-properties fo:margin-bottom="{margin}"/></style:style>'
        f'<style:style style:name="T{name}" style:family="text"><style:text-properties '
        f'fo:font-family="Liberation Sans" fo:font-size="{size}" fo:color="{color}" '
        f'fo:font-weight="{weight}"/></style:style>'
        for name, margin, size, color, weight in (
            ("Kicker", "0cm", "13pt", "#57dec9", "bold"), ("Title", "0cm", "36pt", "#ffffff", "bold"),
            ("Body", "0.48cm", "21pt", "#d7e4f2", "normal"),
        )
    )

    def frame(y, height, style, lines):
        paragraphs = "".join(f'<text:p text:style-name="P{style}"><text:span text:style-name="T{style}">'
                             f'{escape(line)}</text:span></text:p>' for line in lines)
        return (f'<draw:frame draw:style-name="Clear" svg:x="1.35cm" svg:y="{y}cm" '
                f'svg:width="30.8cm" svg:height="{height}cm">'
                f'<draw:text-box>{paragraphs}</draw:text-box></draw:frame>')

    pages = "".join(
        f'<draw:page draw:name="{escape(title, quote=True)}" draw:style-name="Dark" draw:master-page-name="Default">'
        + frame(1.05, 0.8, "Kicker", ["TCP SYN DEFENSE LAB"])
        + frame(2.15, 2.2, "Title", [title])
        + frame(5.6, 11.8, "Body", lines)
        + "</draw:page>"
        for title, lines in content
    )
    source = scratch / "TCP-SYN-Defense-Lab.fodp"
    source.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
 xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
 xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
 xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
 office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.presentation">
 <office:automatic-styles>{styles}
 <style:style style:family="graphic" style:name="Clear"><style:graphic-properties draw:fill="none" draw:stroke="none"/></style:style>
 <style:page-layout style:name="Wide"><style:page-layout-properties fo:page-width="33.87cm" fo:page-height="19.05cm"/></style:page-layout>
 <style:style style:family="drawing-page" style:name="Dark"><style:drawing-page-properties draw:fill="solid" draw:fill-color="#0c1723"/></style:style>
 </office:automatic-styles><office:master-styles><style:master-page style:name="Default" style:page-layout-name="Wide"/></office:master-styles>
 <office:body><office:presentation>{pages}</office:presentation></office:body>
</office:document>""", encoding="utf-8")
    run("soffice", f"-env:UserInstallation={(scratch / 'office-profile').as_uri()}",
        "--headless", "--convert-to", "pptx:Impress MS PowerPoint 2007 XML", "--outdir", str(target), str(source))
    if not (target / "TCP-SYN-Defense-Lab.pptx").is_file():
        raise RuntimeError("LibreOffice did not create the presentation")


def make(run_dir, target, scratch):
    data = slides(run_dir)
    qualified, limited = data[2][1][1:3]
    recovery = case_terminal(run_dir, "Automated defense / recovery")
    failure = case_terminal(run_dir, "Automated defense / upstream bottleneck")
    comparative = "".join(f"<tr><td>{escape(row)}</td></tr>" for row in data[1][1])
    alerts = read_csv(run_dir / "agent.csv")
    alert_time = next(row["timestamp"] for row in alerts if row["event"])
    kernel = json.loads((run_dir / "kernel-check.json").read_text())
    pcap = kernel["packet_capture"]
    delta = kernel["test_deltas"]
    entries = [
        ("Run the comparison", "Ordinary HTTP requests carry outcomes from a fixed model.", f"""
<div class="flow">
<article class="card"><h3>Scenario</h3><p>Source groups and upstream capacity</p></article><span>→</span>
<article class="card"><h3>Queue + detector</h3><p>Observe pressure and enable cookies</p></article><span>→</span>
<article class="card"><h3>HTTP benchmark</h3><p>Measure 200, 503 and elapsed time</p></article></div>
<p class="hint">From the project directory, run <code>python demo.py --kernel-check --pace 0.6</code>.</p>""",
         "Run the comparison with one Python command. The fixed queue model sets admission outcomes while the Python benchmark performs real localhost HTTP requests."),
        ("Per-source filtering", "The same modeled pressure is presented under two source patterns.",
         f'<section class="card"><table>{comparative}</table></section>',
         "All probes succeeded when the fixture used one source and per-source filtering. With changing sources, only the quiet-window probes succeeded."),
        ("Recovery after activation", qualified,
         f'<section class="card"><pre>{escape(recovery)}</pre></section>'
         f'<p class="hint">The first recorded alert was at {escape(alert_time)} UTC.</p>',
         "The detector alerts at window three. Starting in window four, every probe succeeds even with a full modeled backlog."),
        ("Defense activates. Most probes fail.", limited,
         f'<section class="card"><pre>{escape(failure)}</pre></section>'
         '<p class="hint">The modeled upstream path still admits about one quarter of probes.</p>',
         "The same detector activates in window three. The upstream limit still blocks about three of every four requests. The HTTP service represents those failures with status 503."),
        ("Live Linux verification", "Standard GETs verify the kernel response in an isolated network namespace.",
         f'<div class="grid"><article class="card"><h3>Kernel counters</h3><strong class="big">{delta["SyncookiesSent"]}'
         f' sent · {delta["SyncookiesRecv"]} validated</strong><p>Cookie setting returned to its original value.</p></article>'
         f'<article class="card"><h3>Packet capture</h3><strong class="big">{pcap["http_200"]} HTTP 200</strong>'
         f'<p>{pcap["streams"]} benign TCP streams and {pcap["frames"]} captured frames.</p></article></div>'
         '<p class="hint">Inspect <code>kernel-check.json</code>, <code>firewall-after.txt</code> and <code>benign-http.pcap</code>.</p>',
         "The disposable namespace recorded six SYN cookies sent and six validated. All twelve benign requests succeeded. The cookie setting and firewall were restored."),
    ]
    profile = scratch / "chrome"

    def screenshot(source, destination, dimensions):
        run("chromium", "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
            "--disable-background-networking", "--no-first-run", f"--user-data-dir={profile}",
            "--hide-scrollbars", f"--window-size={dimensions}", f"--screenshot={destination}", source.as_uri(),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    screenshot(run_dir / "report.html", target / "01-results.png", "1280,1500")
    frames = []
    for index, (title, lead, body, _) in enumerate(entries, 1):
        source = scratch / f"scene-{index}.html"
        source.write_text(scene(title, lead, body), encoding="utf-8")
        name = f"scene-{index}.png"
        screenshot(source, scratch / name, "1280,720")
        frames.append(name)
    shutil.copyfile(scratch / frames[0], target / "02-architecture.png")
    shutil.copyfile(scratch / frames[2], target / "03-recovery.png")
    shutil.copyfile(scratch / frames[3], target / "04-upstream-failure.png")
    shutil.copyfile(scratch / frames[4], target / "05-kernel-verification.png")
    timeline = scratch / "frames.txt"
    captions = scratch / "captions.srt"
    duration = 11
    timeline.write_text("".join(f"file '{frame}'\nduration {duration}\n" for frame in frames)
                        + f"file '{frames[-1]}'\n")
    notes = ["# Walkthrough transcript", ""]
    subtitle = []
    for index, (title, _, _, narration) in enumerate(entries):
        start, end = index * duration, (index + 1) * duration
        notes.extend((f"## {start // 60:02}:{start % 60:02} · {title}", "", narration, ""))
        subtitle.append(f"{index + 1}\n00:{start // 60:02}:{start % 60:02},000 --> "
                        f"00:{end // 60:02}:{end % 60:02},000\n{narration}\n\n")
    (target / "transcript.md").write_text("\n".join(notes), encoding="utf-8")
    captions.write_text("".join(subtitle), encoding="utf-8")
    run("ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-threads", "2",
        "-f", "concat", "-safe", "0", "-i", str(timeline), "-i", str(captions),
        "-vf", "fps=25,format=yuv420p", "-c:v", "libx264", "-preset", "fast", "-threads", "2",
        "-c:s", "mov_text", "-metadata:s:s:0", "language=eng", "-movflags", "+faststart",
        "-t", str(len(frames) * duration), str(target / "walkthrough.mp4"))
    write_deck(scratch, target, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    target = args.destination.resolve()
    target.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="syn-lab-handoff-") as working:
        make(args.run.resolve(), target, Path(working))


if __name__ == "__main__":
    main()
