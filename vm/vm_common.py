"""QEMU helpers for the offline SYN defense appliance."""
from pathlib import Path
import shutil
import subprocess
from threading import Thread

QEMU = "qemu-system-x86_64"
DISK = "syn-flood-defense-ubuntu.qcow2"


def disk_option(path, *, cdrom=False):
    filename = str(Path(path).resolve()).replace(",", ",,")
    if cdrom:
        return f"file={filename},media=cdrom,format=raw,readonly=on"
    return f"file={filename},if=virtio,format=qcow2"


def machine(disk, accel):
    if not shutil.which(QEMU):
        raise RuntimeError(f"{QEMU} is required")
    if accel == "auto":
        # Let QEMU fall back if KVM is absent or unavailable to this account.
        acceleration = ["-accel", "kvm", "-accel", "tcg"]
    else:
        acceleration = ["-accel", accel]
    return [QEMU, "-name", "SYN Defense Lab", "-machine", "q35",
            *acceleration, "-smp", "2", "-m", "2048",
            "-display", "none", "-drive", disk_option(disk)]


def run_logged(command, log_path, timeout, *, quiet_boot=False):
    with log_path.open("wb") as log, subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True,
    ) as process:
        def capture():
            visible = not quiet_boot
            for line in process.stdout:
                log.write(line)
                log.flush()
                if b"[SYNLAB]" in line:
                    visible = True
                if visible:
                    print(line.decode("utf-8", errors="replace").rstrip(), flush=True)

        reader = Thread(target=capture)
        reader.start()
        try:
            code = process.wait(timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"VM did not shut down within {timeout} seconds. See {log_path}") from error
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            reader.join()
    if code:
        raise RuntimeError(f"QEMU exited with code {code}. See {log_path}")
