"""Build an Ubuntu-based QEMU appliance from an official cloud image."""
import argparse
from base64 import b64encode
import hashlib
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from urllib.request import urlopen
from zipfile import ZIP_DEFLATED, ZipFile

from vm_common import DISK, disk_option, machine, run_logged

HERE = Path(__file__).resolve().parent
URL = "https://cloud-images.ubuntu.com/releases/24.04/release/"
IMAGE = "ubuntu-24.04-server-cloudimg-amd64.img"


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def get_base(cache):
    cache.mkdir(parents=True, exist_ok=True)
    with urlopen(URL + "SHA256SUMS", timeout=30) as response:
        checksums = response.read().decode().splitlines()
    expected = next(line.split()[0] for line in checksums if line.split()[-1].lstrip("*") == IMAGE)
    base = cache / IMAGE
    if base.exists() and checksum(base) == expected:
        return base, expected
    partial = cache / (IMAGE + ".partial")
    subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(partial), URL + IMAGE], check=True)
    if checksum(partial) != expected:
        raise RuntimeError("Downloaded Ubuntu image does not match Canonical's SHA-256 checksum")
    partial.replace(base)
    return base, expected


def pack_project(root, destination):
    files = [*root.glob("*.py"), *root.glob("*.md"), root / "firewall_rules.sh"]
    for name in ("tests", "docs", "evidence", "handoff"):
        files.extend(path for path in (root / name).glob("*") if path.is_file())
    with ZipFile(destination, "w", ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, Path("syn-flood-defense-lab") / path.relative_to(root))


def build(project, image, cache, accel):
    if image.exists():
        raise FileExistsError(f"Choose a new output path. {image} already exists.")
    for name in ("qemu-img", "qemu-system-x86_64", "xorriso"):
        if not shutil.which(name):
            raise RuntimeError(f"{name} is required to build the VM")
    base, digest = get_base(cache)
    print(f"Verified Canonical cloud image SHA-256 {digest}", flush=True)
    image.parent.mkdir(parents=True, exist_ok=True)
    log = image.with_suffix(".build.log")
    with TemporaryDirectory(prefix="syn-vm-build-", dir=image.parent) as work:
        work = Path(work)
        seed_root = work / "seed"
        seed_root.mkdir()
        init = b64encode((HERE / "provision-guest.sh").read_bytes()).decode()
        (seed_root / "meta-data").write_text("instance-id: syn-defense-appliance\nlocal-hostname: syn-defense-lab\n")
        (seed_root / "user-data").write_text(f"""#cloud-config
users:
  - name: demo
    shell: /bin/bash
    lock_passwd: true
ssh_pwauth: false
disable_root: true
write_files:
  - path: /var/tmp/provision-syn-lab.sh
    permissions: '0700'
    encoding: b64
    content: {init}
runcmd:
  - [bash, /var/tmp/provision-syn-lab.sh]
""")
        pack_project(project, seed_root / "project.zip")
        seed = work / "seed.iso"
        subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata",
                        "-joliet", "-rock", "-output", str(seed), str(seed_root)], check=True)
        temporary_disk = work / DISK
        subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base),
                        str(temporary_disk), "10G"], check=True)
        command = [*machine(temporary_disk, accel), "-serial", "stdio", "-monitor", "none",
                   "-drive", disk_option(seed, cdrom=True),
                   "-nic", "user,model=virtio-net-pci"]
        run_logged(command, log, 600, quiet_boot=True)
        if "[SYNLAB] Appliance provisioning complete" not in log.read_text(errors="replace"):
            raise RuntimeError(f"Ubuntu provisioning did not complete. See {log}")
        standalone = work / "standalone.qcow2"
        subprocess.run(["qemu-img", "convert", "-c", "-f", "qcow2", "-O", "qcow2",
                        "-o", "compression_type=zstd",
                        str(temporary_disk), str(standalone)], check=True)
        subprocess.run(["qemu-img", "check", str(standalone)], check=True)
        standalone.replace(image)
    image.with_suffix(".base-sha256.txt").write_text(f"{digest}  {IMAGE}\n")
    print(f"Bootable image {image}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=HERE.parent, help="Project source directory")
    parser.add_argument("--image", type=Path, default=HERE / DISK)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "syn-flood-defense-vm")
    parser.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    args = parser.parse_args()
    build(args.project.resolve(), args.image.resolve(), args.cache.resolve(), args.accel)


if __name__ == "__main__":
    main()
