#!/usr/bin/env bash
set -euo pipefail

finish() {
    status=$?
    if (( status != 0 )); then
        echo "[SYNLAB] Provisioning failed (status $status)" >&2
    fi
    sync
    systemctl --no-block poweroff
}
trap finish EXIT

echo "[SYNLAB] Installing Ubuntu guest dependencies"
export DEBIAN_FRONTEND=noninteractive
sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
apt-get -o Acquire::Retries=2 -o Acquire::https::Timeout=15 update
apt-get -o Acquire::Retries=2 -o Acquire::https::Timeout=15 install -y --no-install-recommends \
    iproute2 nftables tshark
apt-get clean
find /var/lib/apt/lists -maxdepth 1 -type f -delete

install -d -m 0755 /mnt/synlab-seed /var/lib/syn-lab
mount -o ro /dev/disk/by-label/cidata /mnt/synlab-seed 2>/dev/null ||
    mount -o ro /dev/disk/by-label/CIDATA /mnt/synlab-seed
python3 - /mnt/synlab-seed/project.zip <<'PY'
import sys
from zipfile import ZipFile

with ZipFile(sys.argv[1]) as archive:
    archive.extractall("/opt")
PY
chmod 0755 /opt/syn-flood-defense-lab/firewall_rules.sh
umount /mnt/synlab-seed

cat >/usr/local/sbin/run-syn-lab <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/syn-flood-defense-lab
if (( $# > 1 )); then
    echo 'Usage: syn-lab [24|100|250|500]' >&2
    exit 2
fi
requests=${1:-24}
port=''
if [[ "$requests" == --batch ]]; then
    shopt -s nullglob
    ports=(/dev/virtio-ports/synlab.evidence.*)
    if (( ${#ports[@]} != 1 )); then
        echo '[SYNLAB] Expected one evidence serial port' >&2
        exit 2
    fi
    port=${ports[0]}
    requests=${port##*.}
fi
case "$requests" in
    24|100|250|500) ;;
    *) echo 'Usage: syn-lab [24|100|250|500]' >&2; exit 2 ;;
esac
run_root="$(mktemp -d /var/lib/syn-lab/run.XXXXXXXX)"
chmod 0755 "$run_root"
status=0
echo "[SYNLAB] Starting demo inside $(. /etc/os-release && printf '%s' "$PRETTY_NAME")"
printf '[SYNLAB] Guest kernel %s | Guest interfaces: %s\n' "$(uname -r)" "$(ls /sys/class/net | paste -sd,)"
python3 -B demo.py --kernel-check --pace 0.35 --requests "$requests" --out "$run_root/evidence" || status=$?
if [[ -d "$run_root/evidence" ]]; then
    chmod -R a+rX "$run_root/evidence"
    ln -sfn "$run_root/evidence" /var/lib/syn-lab/latest
    if [[ -n "$port" ]]; then
        tar -C "$run_root" -cz evidence >"$port"
    fi
fi
if (( status == 0 )); then
    echo "[SYNLAB] Guest verification passed"
else
    echo "[SYNLAB] Guest verification failed (status $status)"
fi
exit "$status"
EOF
chmod 0755 /usr/local/sbin/run-syn-lab

cat >/usr/local/bin/syn-lab <<'EOF'
#!/bin/sh
exec sudo -n /usr/local/sbin/run-syn-lab "$@"
EOF
cat >/usr/local/bin/syn-lab-poweroff <<'EOF'
#!/bin/sh
exec sudo -n /usr/sbin/poweroff
EOF
chmod 0755 /usr/local/bin/syn-lab /usr/local/bin/syn-lab-poweroff
cat >/etc/sudoers.d/syn-lab <<'EOF'
Cmnd_Alias SYN_LAB = /usr/local/sbin/run-syn-lab "", /usr/local/sbin/run-syn-lab 24, /usr/local/sbin/run-syn-lab 100, /usr/local/sbin/run-syn-lab 250, /usr/local/sbin/run-syn-lab 500
demo ALL=(root) NOPASSWD: SYN_LAB, /usr/sbin/poweroff ""
EOF
chmod 0440 /etc/sudoers.d/syn-lab
visudo -c -f /etc/sudoers.d/syn-lab

install -d /etc/systemd/system/serial-getty@ttyS0.service.d
cat >/etc/systemd/system/serial-getty@ttyS0.service.d/syn-lab.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin demo --keep-baud 115200,38400,9600 %I $TERM
EOF
cat >>/home/demo/.profile <<'EOF'

if [ "$(tty)" = /dev/ttyS0 ]; then
    printf '\n  TCP SYN defense lab\n  Run the demo with syn-lab [24|100|250|500]\n  Shut down with syn-lab-poweroff\n\n'
fi
EOF

cat >/etc/udev/rules.d/90-syn-lab.rules <<'EOF'
SUBSYSTEM=="virtio-ports", ATTR{name}=="synlab.evidence.*", TAG+="systemd", ENV{SYSTEMD_WANTS}+="syn-lab-autostart.service"
EOF
cat >/etc/systemd/system/syn-lab-autostart.service <<'EOF'
[Unit]
Description=Run and export the isolated SYN defense demo
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/run-syn-lab --batch
ExecStopPost=/usr/bin/systemctl --no-block poweroff
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=150
EOF
systemctl disable --now ssh.service ssh.socket 2>/dev/null || true
systemctl mask systemd-networkd-wait-online.service
touch /etc/cloud/cloud-init.disabled
echo "[SYNLAB] Appliance provisioning complete"
