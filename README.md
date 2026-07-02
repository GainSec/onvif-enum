# ONVIF Device Enumerator

Standalone ONVIF enumeration tool for authorized security testing and network administration of ONVIF-compatible IP cameras, NVRs, access-control devices, and related physical-security equipment.

This repository packages the most complete local version of `onvif_enum.py` found during cleanup. It is the expanded 3,596-line version with timeout handling, service URL patching, extended service coverage, interactive selection, JSON output, and optional/slow operation controls.

## What It Does

- Connects to ONVIF device-management services.
- Enumerates device information, capabilities, scopes, services, network settings, users, certificates, relay outputs, digital inputs, system data, and security settings where available.
- Enumerates media, media2, PTZ, imaging, events, analytics, recording, search, replay, device I/O, access-control-adjacent, and optional extended services when supported by the target.
- Supports quick scans, full scans, and interactive operation selection.
- Can output results as JSON for reporting or follow-up analysis.
- Patches service URLs returned by some devices when they point to unresolvable hostnames instead of the target IP.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

Probe whether a port is reachable:

```bash
python3 onvif_enum.py 192.0.2.10 --probe
```

Run a quick scan:

```bash
python3 onvif_enum.py 192.0.2.10 --quick
```

Run a full scan with credentials:

```bash
python3 onvif_enum.py 192.0.2.10 -u admin --password 'change-me'
```

Use a non-standard ONVIF port:

```bash
python3 onvif_enum.py 192.0.2.10 --port 8080 --quick
```

Open the interactive menu:

```bash
python3 onvif_enum.py 192.0.2.10 -i
```

Save JSON output:

```bash
python3 onvif_enum.py 192.0.2.10 --json -o results.json
```

Skip optional or slow operations:

```bash
python3 onvif_enum.py 192.0.2.10 --no-optional
```

## Notes

- The script depends on `onvif-zeep`.
- Some devices return ONVIF service URLs using hostnames or addresses that are not reachable from the testing workstation. This version attempts to patch those service bindings back to the target IP.
- ONVIF support varies heavily by device, firmware, profile, and vendor implementation. Failed service calls do not necessarily mean the device is broken; they may mean the service is unsupported or disabled.
- Some operations can expose sensitive data such as users, certificates, network configuration, stream URLs, relay outputs, and system backups.

## Scope And Safety

Use only on devices and networks where you have authorization. ONVIF services can expose camera streams, credentials, certificates, relay controls, recording configuration, and access-control-related metadata.

The tool is intended for research, auditing, inventory, and defensive validation. It is not a permission slip to test third-party devices.
