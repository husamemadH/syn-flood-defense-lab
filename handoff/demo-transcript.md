# Narrated demo transcript

[Watch the demo](syn-defense-demo.mp4)

## 00:00 · Overview

This lab asks whether people can still reach a web service during a multi-source TCP SYN flood. We will follow the handshake, the defense, and a recorded 500-request run inside Ubuntu.

## 00:12 · TCP handshake

A normal client starts the TCP handshake by sending a SYN. The server replies with SYN-ACK and records a half-open connection in its SYN backlog. The final ACK completes the handshake. The client can now send its HTTP request.

## 00:29 · Attack model

The simulated attacker starts handshakes but leaves them unfinished. Half-open entries accumulate in the server queue. All modeled attack attempts establish zero connections. A full queue can still deny access to legitimate clients.

## 00:44 · Firewall comparison

A per-IP firewall rule can limit pressure from one apparent source. Spread that pressure among many source labels and each can stay within its own limit. In the 500-request run, the single-source filter case served every legitimate probe. With changing sources, only the 84 quiet-window probes succeeded.

## 01:04 · SYN-cookie defense

When the backlog is full, a server using SYN cookies can send SYN-ACK without allocating the usual half-open entry. The sequence number carries a cookie. The server can verify the final ACK and establish the connection. An unfinished flood attempt still sets up no connection. The incoming SYN packets can still consume bandwidth.

## 01:24 · VM architecture

The Ubuntu guest has no network adapter. A Python model supplies queue readings to the detector, and a benchmark sends real HTTP requests over loopback. A separate loopback namespace verifies actual Linux SYN cookies and firewall counters. The guest exports its evidence to the host over a virtual serial port.

## 01:46 · Recorded VM run

Here is the recorded Ubuntu run. We launched the 500-request profile and followed the recovery case. Windows two and three both hit 32 half-open entries. The detector activates protection at the end of window three. By window four, all 83 legitimate probes return HTTP 200, although the modeled queue remains full.

## 02:09 · Measured HTTP outcomes

Over the final three windows, all 249 legitimate probes succeeded when the backlog was the constraint. With an upstream limit, 63 of those 249 probes succeeded. Most attempts were blocked before reaching the modeled server. Cookies can help a connection that reaches the server. Upstream capacity is still limited.

## 02:31 · Linux kernel check

The comparison uses real HTTP responses to represent a modeled flood. The kernel check is a separate run with 12 ordinary HTTP requests. Linux sent six SYN cookies and validated six. The lab saved a packet capture, restored the cookie setting, and removed its firewall table.

## 02:53 · Reproduce the demo

Run the 500-request profile to replay the comparison. The repository includes the evidence and a guide for each team.

## Sources

- [Recorded 500-request report](../evidence/workloads/500/report.html) and [workload results](../evidence/workloads/README.md). The video also shows a repeat run of the same Ubuntu profile.
- [Linux kernel SYN-cookie settings](https://docs.kernel.org/networking/ip-sysctl.html#tcp-syncookies).
- Narration was synthesized locally with Piper. [LJ Speech voice model](https://huggingface.co/rhasspy/piper-voices/blob/main/en/en_US/ljspeech/high/MODEL_CARD).
