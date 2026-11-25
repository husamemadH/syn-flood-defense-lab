# Defender team · detection and mitigation

## Method

[syn_defense_agent.py](../syn_defense_agent.py) checks half-open occupancy. The comparison fixture triggers on two consecutive windows with at least 20 modeled `SYN_RECV` entries. The agent logs the transition at the end of window 3. The model applies cookies in window 4. An alert indicates sustained half-open pressure. It carries no source attribution.

| Window | What the comparison is doing |
|---|---|
| 1 | Run the legitimate client before pressure starts. |
| 2–3 | Apply simulated SYN pressure and observe the queue. The detector triggers at the end of window 3. |
| 4–6 | Keep the pressure running with modeled SYN cookies active. Use these probes for the post-activation result. |

[firewall_rules.sh](../firewall_rules.sh) manages a scoped nftables table used by the separate kernel check. [kernel_check.py](../kernel_check.py) runs in a loopback-only Linux network namespace. It injects fixed detector readings, enables Linux’s unconditional SYN-cookie test mode, sends ordinary HTTP requests, verifies the cookie and firewall counters, and restores the previous configuration.

A SYN cookie encodes information in the server’s SYN-ACK sequence number. The server can verify the client’s final ACK without keeping an ordinary half-open entry for that SYN. Linux normally uses cookies as an overflow fallback when `net.ipv4.tcp_syncookies=1`. The test sets it to `2` inside the temporary namespace so regular connections exercise cookies without requiring backlog overflow. Inspect `SyncookiesSent`, `SyncookiesRecv` and `SyncookiesFailed` in the exported `kernel-check.json`. [Linux kernel settings](https://docs.kernel.org/networking/ip-sysctl.html#tcp-syncookies)

## Team ownership

| Project part | Responsibility |
|---|---|
| [syn_defense_agent.py](../syn_defense_agent.py) | Own detection, mitigation activation, error handling and agent logs. |
| [firewall_rules.sh](../firewall_rules.sh), [kernel_check.py](../kernel_check.py) | Own firewall policy, real kernel verification, packet capture and reset. |
| [client_benchmark.py](../client_benchmark.py), [generate_charts.py](../generate_charts.py) | Own client availability and latency measurements, report charts and outcome interpretation. |

## What to show

In the recovery case, cookies allow legitimate handshakes to complete while the modeled backlog is full. In the upstream case, about one in four legitimate connection attempts reaches the modeled server. The same defense helps the attempts that arrive. The comparative HTTP `503` statuses are application responses representing modeled rejections. For real cookie issuance and validation, open `kernel-check.json` from the separate benign traffic check. [Ubuntu workload evidence](../evidence/workloads/README.md)

[Detector timing diagram](architecture.md#detector-timing) · [Kernel verification sequence](architecture.md#linux-kernel-verification)
