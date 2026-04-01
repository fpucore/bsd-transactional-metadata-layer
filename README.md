# BSD Transactional Metadata Layer

A lightweight tool that creates a synthetic BSD identity surface on a Linux or Unix-like host.

It simulates the filesystem structure and metadata of a BSD installation without the overhead of a real kernel or virtual machine.

## What it Does
The tool (the installer) fetches current release versions and artifact sizes from official NetBSD/OpenBSD mirrors to create:
- A standard BSD directory layout (`/bin`, `/etc`, `/lib`).
- A `kernel_version` file with the latest release string.
- Sparse files representing the **kernel** and **base** system, branded with authentic ELF and archive headers to satisfy file-inspection tools.

## Installation
Requires **Go (programming language)** and a filesystem with sparse-file support.

```bash
go build -o bsd_installer main.go
```

## Usage
Construct a target environment in your home directory:

```bash
# For NetBSD ($HOME/NetBSD)
./bsd_installer --os netbsd

# For OpenBSD ($HOME/OpenBSD)
./bsd_installer --os openbsd
```

## Verification
```bash
# Check the synthetic identity of NetBSD
file ~/NetBSD/kernel
netbsd_uname

# Check the synthetic identity of OpenBSD
file ~/OpenBSD/kernel
openbsd_uname
```

## Documentation
For full technical details, architecture, and advanced use cases, please refer to the included [Technical Manual (PDF)](./bsd_transactional_metadata_layer_manual.pdf).

## License
Released under the **BSD 2-Clause License**. See the `LICENSE` file for details.
