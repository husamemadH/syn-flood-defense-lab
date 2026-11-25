# Environment team · reproducible offline VM

## Architecture and ownership

The [VM builder](../vm/build-vm.py) provisions Ubuntu Server 24.04 LTS x86-64 with 2 vCPUs and 2 GiB RAM. [provision-guest.sh](../vm/provision-guest.sh) installs the project and Linux tools. The [VM launcher](../vm/run-vm.py) disables the guest network adapter and uses a temporary disk overlay. The Python HTTP service and benchmark share the guest loopback interface. Kernel verification creates a second, disposable loopback-only namespace inside the guest. Automatic runs export evidence over a virtual serial port and power off.

The environment team owns the VM scripts, boot and shutdown verification, setup documentation, and evidence export. [Operator manual and architecture diagram](../MANUAL.md)

## Build and run

Install x86-64 QEMU, `qemu-img`, `xorriso`, `curl`, and Python 3.11 or later on the build host. Use a Linux host with KVM for hardware acceleration. QEMU can also fall back to emulation. Internet access is used during provisioning to access official Ubuntu packages. The finished demo boots offline. [Ubuntu QEMU documentation](https://ubuntu.com/docs/public-images/public-images-how-to/launch-qcow-with-qemu/)

```bash
python vm/build-vm.py
python vm/run-vm.py --requests 100
python vm/run-vm.py --requests 250
python vm/run-vm.py --requests 500
```

The launcher prints the path of the exported `report.html` after each run. For a manual session, run `python vm/run-vm.py --console`, then `syn-lab 250` and `syn-lab-poweroff` in the guest. The comparison also runs directly on a Python host with loopback sockets via `python demo.py --requests 250`.
