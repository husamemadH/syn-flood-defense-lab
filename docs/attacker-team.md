# Attacker team · simulated pressure

## Question

Why does a per-IP limit help against pressure from one apparent source but lose effectiveness when the same aggregate pressure is spread across changing source identities?

## Method

The attacker role is the in-memory workload in [pressure_model.py](../pressure_model.py). It represents incoming SYNs whose handshakes stay unfinished. The single-source and changing-source fixtures keep the total modeled pressure equal. A source label is simply a bucket in a Python calculation. The model creates zero packets and has no network target. All real requests come from the legitimate benchmark client.

Each case starts with a quiet window. Subsequent windows apply the same pressure fixture while the comparison changes the source grouping or defense setting. A separate fixture limits legitimate attempts before they reach the modeled server. This demonstrates the effect of an upstream bottleneck even when host mitigation activates.

## Team ownership

| Project part | Responsibility |
|---|---|
| [pressure_model.py](../pressure_model.py) | Own the source grouping fixtures, queue assumptions and upstream scenario. Keep aggregate pressure comparable across cases. |
| [windows.csv](../evidence/windows.csv) | Explain modeled arrivals, half-open occupancy, and rejection counts. |
| [test_pipeline.py](../tests/test_pipeline.py) | Maintain assertions about source grouping, equal aggregate pressure and workload profiles. |

## What to show

Compare `filter-single` and `filter-distributed` in the report. Under the same modeled pressure, the single-source case shows filter rejections and the queue stays below capacity. The changing-source case fills the model’s queue. The HTTP 200 counter measures the legitimate client. Model traffic never finishes a handshake, so the simulated attacker has zero completed connections by design.
