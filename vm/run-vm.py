"""Boot the isolated Ubuntu SYN defense appliance."""
import argparse
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

from vm_common import DISK, machine, run_logged

HERE = Path(__file__).resolve().parent


def export_evidence(archive, output):
    with tarfile.open(archive, "r:gz") as bundle:
        for item in bundle:
            path = PurePosixPath(item.name)
            if path == PurePosixPath("evidence") and item.isdir():
                continue
            if len(path.parts) != 2 or path.parts[0] != "evidence" or path.name == ".." or not item.isfile():
                raise RuntimeError(f"Unexpected guest export entry {item.name!r}")
            source = bundle.extractfile(item)
            with source, (output / path.name).open("xb") as target:
                shutil.copyfileobj(source, target)


def batch(command, output, requests):
    output.mkdir(parents=True)
    archive = output / "guest-evidence.tar.gz"
    log = output / "guest-console.log"
    filename = str(archive).replace(",", ",,")
    run_logged(
        [*command, "-monitor", "none", "-serial", "stdio",
         "-device", "virtio-serial-pci",
         "-chardev", f"file,id=synout,path={filename}",
         "-device", f"virtserialport,chardev=synout,name=synlab.evidence.{requests}"],
        log, 240, quiet_boot=True,
    )
    if archive.exists() and archive.stat().st_size > 0:
        export_evidence(archive, output)
    if "[SYNLAB] Guest verification passed" not in log.read_text(errors="replace"):
        raise RuntimeError(f"Guest verification failed. See {log}")
    if not (output / "report.html").is_file():
        raise RuntimeError(f"Guest did not export a complete report. See {log}")
    print(f"\nGuest report {output / 'report.html'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=HERE / DISK)
    parser.add_argument("--out", type=Path, help="New directory for the guest report and raw evidence")
    parser.add_argument("--console", action="store_true", help="Open an interactive guest serial console")
    parser.add_argument("--requests", type=int, choices=(24, 100, 250, 500),
                        help="Legitimate HTTP probes per scenario in automatic mode (default: 24)")
    parser.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    args = parser.parse_args()
    image = args.image.resolve()
    if not image.is_file():
        parser.error(f"VM image not found at {image}")
    if args.console and (args.out or args.requests):
        parser.error("--out and --requests are for automatic mode; run syn-lab [count] inside the console")
    command = [*machine(image, args.accel), "-nic", "none", "-snapshot"]
    if args.console:
        subprocess.run([*command, "-serial", "mon:stdio"], check=True)
    else:
        suffix = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        output = (args.out or HERE / "runs" / suffix).resolve()
        print("Booting the Ubuntu VM with no network adapter. The demo will run automatically.", flush=True)
        batch(command, output, args.requests or 24)


if __name__ == "__main__":
    main()
