# TCP SYN defense lab

This lab compares per-source filtering and automated SYN-cookie mitigation when a TCP SYN flood appears to come from one source or many. A deterministic Python model represents the flood and any upstream bottleneck. An ordinary loopback client measures HTTP responses selected by the model. A separate Linux check validates real SYN-cookie issuance and firewall counters with benign traffic.

## Team guides

| Team | Guide |
|---|---|
| Attacker | [Simulated attack methodology, files and metrics](docs/attacker-team.md) |
| Defender | [Detection, mitigation, verification and ownership](docs/defender-team.md) |
| Environment | [Ubuntu VM setup, isolation and reproducibility](docs/environment-team.md) |

## Run the demo

Use Python 3.10 or later for the local comparison. Each request profile specifies the total number of legitimate HTTP probes **per scenario**. The default is 24. The larger profiles keep the simulated flood and detector settings fixed.

```bash
python demo.py --requests 100
python demo.py --requests 250
python demo.py --requests 500
```

Open the `report.html` path printed by the demo. Add `--kernel-check` on Linux to include real kernel verification and a benign packet capture. That option needs Linux user and network namespaces plus `unshare`, `ip`, `nft`, `dumpcap` and `tshark`.

## Run in Ubuntu

Build the Ubuntu 24.04 VM once with Python 3.11 or later, QEMU, `qemu-img`, `xorriso` and `curl`. The build uses the official Ubuntu cloud image and package repositories. Runtime uses an offline guest and exports evidence automatically.

```bash
python vm/build-vm.py
python vm/run-vm.py --requests 500
```

## Evidence

- [Original 24-request comparison](evidence/report.html) and [technical report](TECHNICAL_REPORT.md)
- [100-, 250- and 500-request results from the Ubuntu VM](evidence/workloads/README.md)
- [Operator manual and architecture diagram](MANUAL.md)
- [Walkthrough transcript](handoff/transcript.md), [video](handoff/walkthrough.mp4), and [editable slide deck](handoff/TCP-SYN-Defense-Lab.pptx)

Run the tests with `python -m unittest discover -s tests -v`.
