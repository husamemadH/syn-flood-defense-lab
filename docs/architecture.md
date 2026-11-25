# Project architecture and diagrams

Start with the [system architecture](#system-architecture), then follow the [comparison](#comparison-data-flow) or the [Linux verification](#linux-kernel-verification). The comparison models a SYN flood and measures real localhost HTTP responses. The separate kernel check measures real Linux SYN cookies with benign traffic.

## System architecture

```mermaid
flowchart TD
    launch["Host<br/>QEMU launcher"]
    output["Host<br/>Report and raw evidence"]
    subgraph guest["Ubuntu VM · no network adapter"]
        direction TB
        runner["Guest demo runner<br/>Runs the selected profile"]
        comparison["Comparison on loopback<br/>Pressure model, detector and real HTTP"]
        subgraph ns["Disposable loopback namespace"]
            kernel["Kernel check<br/>SYN cookies, nftables and capture"]
        end
        bundle["Guest evidence archive"]
        runner --> comparison
        runner --> kernel
        comparison --> bundle
        kernel --> bundle
    end
    launch -->|"Boot disk overlay"| guest
    guest -->|"Virtual serial port"| output

    classDef model fill:#fff0e0,stroke:#ad602d,color:#361c11;
    classDef live fill:#e5f3ff,stroke:#4078a5,color:#0d2941;
    classDef evidence fill:#eaf0f7,stroke:#647b94,color:#1a3047;
    class comparison model;
    class kernel live;
    class bundle,output evidence;
```

The automatic VM run performs the comparison first, then the kernel check. It packages the evidence from both stages for export to the host.

| Component | Responsibility |
|---|---|
| [VM builder](../vm/build-vm.py) and [guest provisioning](../vm/provision-guest.sh) | Install Ubuntu dependencies and the project into a bootable image. |
| [VM launcher](../vm/run-vm.py) and [demo runner](../demo.py) | Boot the isolated VM, choose a request profile, run the comparison and export the results. |
| [Pressure model](../pressure_model.py) | Represent source grouping, the half-open queue, modeled cookies and the upstream limit. |
| [Defense agent](../syn_defense_agent.py) | Sample half-open occupancy and call the appropriate mitigation backend. |
| [Benchmark](../client_benchmark.py) and [HTTP service](../lab_http.py) | Send ordinary loopback requests and translate model verdicts into HTTP responses. |
| [Kernel verification](../kernel_check.py) and [firewall rules](../firewall_rules.sh) | Exercise real cookies, validate counters, capture benign traffic and restore lab settings. |
| [Report generator](../generate_charts.py) | Build the comparison tables and charts from the recorded CSVs. |

## TCP handshake and flood pressure

```mermaid
sequenceDiagram
    participant C as TCP initiator
    participant S as TCP server
    C->>S: SYN
    alt Ordinary completed handshake
        S-->>C: SYN-ACK
        Note right of S: Keep a half-open entry until the final ACK
        C->>S: ACK
        C->>S: HTTP GET over the established connection
    else Unfinished handshake during modeled pressure
        S-->>C: SYN-ACK
        Note over C,S: The final ACK never arrives
        Note right of S: Unfinished entries can fill the backlog
    else SYN cookies available when the backlog is full
        S-->>C: SYN-ACK with a cookie in its sequence number
        Note right of S: Avoid allocating a new half-open entry for this SYN
        C->>S: Valid final ACK
        S->>S: Validate the cookie and establish the connection
        C->>S: HTTP GET over the established connection
    end
```

The middle branch explains why the simulated attacker can make the service unavailable while completing zero connections. The benchmark counts HTTP requests from the legitimate client. [Attacker team guide](attacker-team.md) · [Defender team guide](defender-team.md)

## Comparison data flow

```mermaid
flowchart TD
    fixture["Fixed pressure fixture<br/>One source or changing source labels"]
    model["QueueModel<br/>Computes half-open occupancy and probe verdicts"]
    agent["DefenseAgent in automated cases<br/>Checks occupancy after each window"]
    client["Legitimate HTTP benchmark<br/>Opens a new TCP connection for each probe"]
    service["Python HTTP server on loopback<br/>Consumes the modeled verdict for each GET"]
    files["Comparison evidence<br/>windows.csv · agent.csv · http.csv"]

    fixture --> model
    model -->|"Sample modeled occupancy after the window"| agent
    agent -->|"Enable modeled SYN cookies for the next window"| model
    model -->|"Supply modeled admission verdicts"| service
    client -->|"Real GET /health"| service
    service -->|"Real HTTP 200 or application-generated 503"| client
    model --> files
    agent --> files
    client --> files

    classDef model fill:#fff0e0,stroke:#ad602d,color:#361c11;
    classDef live fill:#e5f3ff,stroke:#4078a5,color:#0d2941;
    classDef defense fill:#dff7ed,stroke:#358264,color:#153b2a;
    classDef evidence fill:#eaf0f7,stroke:#647b94,color:#1a3047;
    class fixture,model model;
    class client,service live;
    class agent defense;
    class files evidence;
```

A `503` represents a modeled rejection. The local client still completed its TCP handshake with the Python service to receive that response. The request profile changes the number of sequential legitimate probes. The modeled flood pressure stays fixed. [Workload results](../evidence/workloads/README.md)

## Per-source filtering

```mermaid
flowchart TD
    pressure["Same total simulated SYN pressure"]
    single["One apparent source<br/>The per-source filter limits that source"]
    changing["Changing apparent sources<br/>Each source stays within its own limit"]
    singleResult["Peak backlog 6/32<br/>500/500 legitimate HTTP 200s"]
    changingResult["Peak backlog 32/32<br/>84/500 legitimate HTTP 200s"]

    pressure --> single --> singleResult
    pressure --> changing --> changingResult

    classDef allowed fill:#dff7ed,stroke:#358264,color:#153b2a;
    classDef limited fill:#fff0e0,stroke:#ad602d,color:#361c11;
    class singleResult allowed;
    class changingResult limited;
```

These counts cover all six windows of the 500-request profile. In the changing-source case, the 84 successful probes came from window 1, before pressure started. [500-request summary](../evidence/workloads/500/summary.csv)

## Detector timing

```mermaid
flowchart LR
    w1["Window 1<br/>Quiet baseline<br/>84 probes"]
    w2["Window 2<br/>First high sample<br/>84 probes"]
    w3["Window 3<br/>Second high sample<br/>83 probes"]
    activate["At end of window 3<br/>Agent enables modeled SYN cookies"]
    w46["Windows 4–6<br/>Defense active<br/>249 probes"]

    w1 --> w2 --> w3 --> activate --> w46

    classDef pressure fill:#fff0e0,stroke:#ad602d,color:#361c11;
    classDef active fill:#dff7ed,stroke:#358264,color:#153b2a;
    class w2,w3 pressure;
    class activate,w46 active;
```

In the 500-request profile, both automated cases sample 32 modeled half-open entries at the end of windows 2 and 3. The detector activates after two consecutive samples at or above 20. Only windows 4–6 contribute to the post-activation denominator of 249. [Agent records](../evidence/workloads/500/agent.csv) · [Window records](../evidence/workloads/500/windows.csv)

## Recovery and the upstream limit

```mermaid
flowchart TD
    probes["249 legitimate attempts after activation"]
    path{"Does the model limit the path before the server?"}
    open["All 249 attempts reach the modeled server"]
    limited["63 reach the modeled server<br/>186 are blocked earlier in the path"]
    full["249/249 HTTP 200"]
    partial["63/249 HTTP 200"]

    probes --> path
    path -->|"Recovery case"| open
    path -->|"Upstream bottleneck case"| limited
    open -->|"Modeled cookies allow completion with a full backlog"| full
    limited -->|"Modeled cookies help the 63 attempts that reach it"| partial

    classDef recovery fill:#dff7ed,stroke:#358264,color:#153b2a;
    classDef limit fill:#fff0e0,stroke:#ad602d,color:#361c11;
    class open,full recovery;
    class limited,partial limit;
```

An upstream bottleneck is a capacity limit before the server, such as a saturated link. A SYN cookie protects the server’s half-open state once traffic arrives. The simulated upstream limit remains active in the second branch. [500-request summary](../evidence/workloads/500/summary.csv)

## Linux kernel verification

```mermaid
sequenceDiagram
    participant K as Kernel check
    participant A as Defense agent
    participant L as Linux and nftables
    participant C as Loopback client
    K->>L: Record settings and start capture
    C->>L: Six HTTP GETs in original mode
    K->>A: Two fixed high readings
    A->>L: Add lab rules and enable mode 2
    C->>L: Six HTTP GETs in mode 2
    K->>L: Read cookie and firewall counters
    K->>L: Remove lab rules and restore settings
    Note over K,C: Save the capture, counters and cleanup evidence
```

The runner uses cookie test mode `2` inside the temporary namespace so ordinary connections exercise the mechanism. The recorded VM check shows six cookies sent, six validated and twelve HTTP 200 responses across the two phases. The capture contains only the benign kernel-check traffic. [Kernel counters](../evidence/workloads/500/kernel-check.json) · [Packet capture](../evidence/workloads/500/benign-http.pcap)

## VM build and evidence export

```mermaid
flowchart TD
    subgraph provision["Provisioning · temporary NAT"]
        direction LR
        source["Ubuntu image<br/>and project files"]
        setup["Install packages<br/>and project with cloud-init"]
        disk["Standalone<br/>QCOW2 disk"]
        source --> setup --> disk
    end
    subgraph runtime["Automatic run · offline"]
        direction LR
        boot["Boot temporary disk overlay<br/>without a network adapter"]
        run["Run comparison<br/>and kernel check"]
        report["Extract report and raw evidence<br/>into vm/runs on the host"]
        boot --> run -->|"Virtual serial port"| report
    end
    provision -->|"Boot saved disk"| runtime

    classDef evidence fill:#eaf0f7,stroke:#647b94,color:#1a3047;
    class disk,report evidence;
```

Provisioning uses internet access to install packages. The finished VM runs offline, exports the evidence and shuts down automatically. [Environment team guide](environment-team.md)
