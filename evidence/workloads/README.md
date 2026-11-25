# Ubuntu VM workload results

These runs used the offline Ubuntu 24.04 VM. Each profile sets the number of sequential legitimate HTTP probes per scenario. All seven scenarios run for six model windows. The SYN pressure fixtures are held fixed. The post-activation columns cover windows 4–6. The other probes ran during the initial quiet window and during pressure before activation.

| Probes per scenario | Baseline HTTP 200 | Recovery after activation | Upstream-limited after activation | Evidence |
|---:|---:|---:|---:|---|
| 100 | 100/100 | 49/49 | 12/49 | [Report](100/report.html) · [Summary CSV](100/summary.csv) |
| 250 | 250/250 | 124/124 | 31/124 | [Report](250/report.html) · [Summary CSV](250/summary.csv) |
| 500 | 500/500 | 249/249 | 63/249 | [Report](500/report.html) · [Summary CSV](500/summary.csv) |

Both automated cases had zero successful HTTP probes during modeled pressure before activation. With more probes, the recovery rate stayed at 100% and the upstream-limited rate stayed close to 25%. Each separate Linux kernel check also recorded six real SYN cookies sent, six validated, and 12 benign HTTP 200 responses.

The comparison uses real local HTTP responses to represent outcomes of a fixed model. These results describe how the outcome persists across larger client samples. The packet captures show the benign kernel checks.
