#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: firewall_rules.sh apply|status|reset [port]"
    echo "Run inside the demo's loopback-only namespace."
}

action=${1:-}
if [[ "$action" == --help ]]; then
    usage
    exit 0
fi

port=${2:-18080}
if (( $# > 2 )) || [[ ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )); then
    usage >&2
    exit 2
fi
if [[ -z "${SYN_LAB_PARENT_NETNS:-}" ]] ||
    [[ "$(readlink /proc/self/ns/net)" == "$SYN_LAB_PARENT_NETNS" ]] ||
    [[ "$(ip -o link show | cut -d: -f2 | xargs)" != lo ]]; then
    echo "Use the disposable loopback-only namespace created by demo.py." >&2
    exit 1
fi

case "$action" in
    apply)
        if nft list table ip syn_defense_lab >/dev/null 2>&1; then
            echo "The lab table already exists. Use status or reset." >&2
            exit 1
        fi
        nft -f - <<RULES
add table ip syn_defense_lab
add chain ip syn_defense_lab input { type filter hook input priority filter; policy accept; }
add rule ip syn_defense_lab input iifname "lo" tcp dport $port tcp flags & (fin | syn | rst | ack) == syn meter by_source { ip saddr timeout 10s limit rate over 30/second burst 12 packets } counter drop
add rule ip syn_defense_lab input iifname "lo" tcp dport $port tcp flags & (fin | syn | rst | ack) == syn counter
RULES
        ;;
    status)
        if ! nft list table ip syn_defense_lab; then
            exit 1
        fi
        ;;
    reset)
        if nft list table ip syn_defense_lab >/dev/null 2>&1; then
            nft delete table ip syn_defense_lab
        fi
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
