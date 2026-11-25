# Walkthrough transcript

## 00:00 · Run the comparison

Run the comparison with one Python command. The fixed queue model sets admission outcomes while the Python benchmark performs real localhost HTTP requests.

## 00:11 · Per-source filtering

The per-source policy kept 24 of 24 probes successful when the fixture used one source. With changing sources, only the four quiet-window probes succeeded.

## 00:22 · Recovery after activation

The detector alerts at window three. Starting in window four, all twelve probes succeed even with a full modeled backlog.

## 00:33 · Defense activates. Most probes fail.

The same detector activates in window three. The upstream limit still blocks three of every four requests. Nine of twelve post-activation probes return HTTP 503.

## 00:44 · Live Linux verification

The disposable namespace recorded six SYN cookies sent and six validated. All twelve benign requests succeeded. The cookie setting and firewall were restored.
