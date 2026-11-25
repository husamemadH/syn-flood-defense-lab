# Comparative SYN flood defense

## Method

The experiment pairs a deterministic SYN queue and upstream admission model with an ordinary localhost HTTP service. The model runs six windows of four legitimate HTTP probes for each of seven cases. Window 1 is a quiet starting point. For all pressure cases, windows 2 through 6 have the same aggregate modeled incomplete-connection pressure. The source grouping varies by scenario. An under-capacity queue slot is retired after three model windows. The comparative firewall admits at most two modeled arrivals per source per window. The queue holds 32 half-open entries in the model.

Every probe opens its own real TCP connection and requests `/health`. For a denied modeled admission, the handler deliberately returns HTTP 503. Success means a complete HTTP 200 response, and latency is elapsed time through reading the response body. The chart averages only successful responses. Timeout and transport failure are accepted benchmark outcomes and are recorded separately by the standalone benchmark. A 503 is a service response. Packet loss requires packet-level evidence.

The agent uses an inclusive threshold of 20 modeled half-open entries over two consecutive samples. It records the alert in window 3 and operates starting in window 4. The diagnostic ratio is admitted initial connection attempts divided by modeled handshake completions in the current window. The denominator can be zero, in which case the ratio field is empty. The live monitor reads socket states from Linux `/proc/net/tcp` and `tcp6` and leaves the ratio empty. Half-open pressure can also be caused by other conditions and cannot identify spoofed sources on its own.

## Comparative results

| Case | HTTP 200 | Success | Peak modeled queue |
|---|---:|---:|---:|
| Baseline | 24/24 | 100.0% | 0/32 |
| No defense, single source | 4/24 | 16.7% | 32/32 |
| No defense, changing sources | 4/24 | 16.7% | 32/32 |
| Per-source filter, single source | 24/24 | 100.0% | 6/32 |
| Per-source filter, changing sources | 4/24 | 16.7% | 32/32 |
| Automated defense, recovery | 16/24 | 66.7% | 32/32 |
| Automated defense, upstream bottleneck | 7/24 | 29.2% | 32/32 |

Both automated cases begin with 0/8 successes during pressure before activation. After activation, the recovery case reaches 12/12 because the model permits legitimate completion when the queue is full and cookies are available. In the upstream-limited case, the same response produces 3/12 successes. Three probes per window are blocked by the modeled upstream limit after defense activates. Both cases still show a full modeled backlog. A cookie can admit a completed handshake without making half-open entries already in the queue disappear.

In the model, the per-source filter dropped 180 arrivals with a single source and zero with changing sources. This follows from the fixture and the modeled per-source rule. Mean measured latency among successes was under 1 ms in the recorded localhost run. Local HTTP timing reflects the demo service and environment. [Comparison charts and raw measurements](evidence/report.html)

The Ubuntu VM workload extension compares 100, 250 and 500 legitimate probes per scenario under the same fixed pressure fixtures. [Workload comparison and raw evidence](evidence/workloads/README.md)

## Linux verification

The separate verification started a new Linux network namespace with loopback as its only interface. It served six ordinary GETs with the original cookie setting and six after the fixture alerted and switched to unconditional kernel cookie test mode. All 12 returned HTTP 200. The kernel recorded six extra `SyncookiesSent` and six `SyncookiesRecv`, with zero `SyncookiesFailed`. The capture contains 144 frames across 12 ordinary TCP streams. During the post-trigger phase, the firewall recorded six allowed initial SYNs and zero drops. Cleanup restored the namespace cookie setting from 2 to 1 and removed the project's nftables table. The configured `tcp_max_syn_backlog` was 1024 and `tcp_synack_retries` was 5. Those are configuration readings. The comparison experiment uses a separate, fixed model capacity. [Kernel counters and cleanup evidence](evidence/kernel-check.json) · [Netfilter counters](evidence/firewall-after.txt) · [Packet capture](evidence/benign-http.pcap) · [Linux IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html#tcp-syncookies)

## Research comparison

| Approach | Mechanism | Strengths and limits |
|---|---|---|
| This lab | Python socket-state detection, Linux SYN cookies and a scoped per-source firewall | Runs on a single Linux host. Protects local connection state in the modeled case. Upstream pressure remains outside a host's direct control. |
| Yang et al. (2023) | Programmable switch with handshake tracking, revised cuckoo hashing and MAC-based allow and block lists | Can drop unwanted traffic earlier when the switch observes useful source MAC identities. Reported reductions are specific to the authors' bmv2 experiment and comparators. Applicability depends on network placement and identity visibility. |
| SmartCookie, Yoo et al. (2024) | Cryptographic verification split across programmable switches and host-side components using Linux eBPF | Moves high-volume verification to a programmable data plane. The authors reported lower benign latency than the switch-based defenses in their experiment. Deployment depends on switch capabilities and integration. |

The published systems evaluate different architectures and workloads. Their numerical results are independent of this lab. [Yang et al., *Sensors*](https://www.mdpi.com/1424-8220/23/8/3817) · [Yoo et al., *USENIX Security*](https://www.usenix.org/conference/usenixsecurity24/presentation/yoo)

## Limits

The comparison evaluates a queue abstraction and an application-level signal for unavailability. Linux's real queue capacity, flood throughput, packet loss, detection false positives and recovery under attack remain unmeasured. The Linux capture verifies benign handshakes in cookie test mode. Real per-source drops are outside the benign check. The upstream constraint is a fixed limit and does not model link dynamics. The sample cutoff and two-window rule are demonstration settings.
