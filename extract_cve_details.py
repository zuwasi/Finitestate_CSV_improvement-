"""
Extract Affected File/Path, Function, and Subsystem from CVE scan CSV descriptions.
Usage: python extract_cve_details.py scan_for_Elta.csv
"""

import csv
import re
import sys
from pathlib import Path

# Regex patterns
FILE_PATH_RE = re.compile(
    r'(?:in\s+|file\s+)?'
    r'([a-zA-Z_][\w\-]*/[\w\-]+(?:/[\w\-\.]+)*\.(?:c|h|cpp|py|rs|java|S))',
    re.IGNORECASE,
)
FUNCTION_RE = re.compile(
    r'\b([a-zA-Z_][\w]*(?:_[\w]+)+)\s*\(\)',  # snake_case functions with ()
)
FUNCTION_IN_RE = re.compile(
    r'(?:in|via|from|function|calls?)\s+([a-zA-Z_][\w]*(?:_[\w]+)*)\s*\(',
)

# Map top-level kernel directories to human-readable subsystem names
SUBSYSTEM_MAP = {
    "net/ipv4": "Networking / IPv4",
    "net/ipv6": "Networking / IPv6",
    "net/wireless": "Networking / Wireless (cfg80211)",
    "net/bluetooth": "Networking / Bluetooth",
    "net/rds": "Networking / RDS",
    "net/netfilter": "Networking / Netfilter",
    "net/core": "Networking / Core",
    "net/socket": "Networking / Socket",
    "net": "Networking",
    "drivers/net/wireless/marvell": "WiFi Driver / Marvell",
    "drivers/net/wireless/ath": "WiFi Driver / Atheros",
    "drivers/net/wireless/realtek": "WiFi Driver / Realtek",
    "drivers/net/wireless": "WiFi Driver",
    "drivers/net/ethernet": "Ethernet Driver",
    "drivers/net": "Network Driver",
    "drivers/media/usb": "Media / USB",
    "drivers/media": "Media Driver",
    "drivers/usb/gadget": "USB Gadget Driver",
    "drivers/usb": "USB Driver",
    "drivers/scsi": "SCSI Driver",
    "drivers/staging": "Staging Driver",
    "drivers/soc": "SoC Driver",
    "drivers/gpu/drm/amd": "GPU / AMD Display",
    "drivers/gpu/drm": "GPU / DRM",
    "drivers/target": "SCSI Target (LIO)",
    "drivers/block": "Block Driver",
    "drivers": "Kernel Driver",
    "fs/btrfs": "Filesystem / Btrfs",
    "fs/xfs": "Filesystem / XFS",
    "fs/jfs": "Filesystem / JFS",
    "fs": "Filesystem",
    "sound/usb": "Audio / USB",
    "sound": "Audio",
    "security/apparmor": "Security / AppArmor",
    "security": "Security",
    "kernel": "Kernel Core",
    "mm": "Memory Management",
    "arch/x86": "Architecture / x86",
    "arch": "Architecture",
    "virt/kvm": "Virtualization / KVM",
    "crypto": "Crypto",
    "lib": "Kernel Lib",
}


def extract_file_paths(description: str) -> list[str]:
    """Extract source file paths from the description text."""
    matches = FILE_PATH_RE.findall(description)
    # Deduplicate while preserving order
    seen = set()
    result = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def extract_functions(description: str) -> list[str]:
    """Extract function names from the description text."""
    funcs = set()
    for m in FUNCTION_RE.findall(description):
        funcs.add(m)
    for m in FUNCTION_IN_RE.findall(description):
        # Filter out common false positives
        if m.lower() not in ("the", "this", "that", "which", "version", "before", "after"):
            funcs.add(m)
    return sorted(funcs)


def classify_subsystem(file_paths: list[str], description: str) -> str:
    """Derive a subsystem label from file paths or description keywords."""
    for fp in file_paths:
        # Try longest prefix match first
        for prefix in sorted(SUBSYSTEM_MAP.keys(), key=len, reverse=True):
            if fp.startswith(prefix):
                return SUBSYSTEM_MAP[prefix]

    # Fallback: keyword matching on description
    desc_lower = description.lower()
    keyword_map = [
        ("wifi", "WiFi"),
        ("wireless", "Wireless"),
        ("bluetooth", "Bluetooth"),
        ("netfilter", "Networking / Netfilter"),
        ("ipv4", "Networking / IPv4"),
        ("ipv6", "Networking / IPv6"),
        ("tcp", "Networking / TCP"),
        ("udp", "Networking / UDP"),
        ("nfs", "Filesystem / NFS"),
        ("btrfs", "Filesystem / Btrfs"),
        ("xfs", "Filesystem / XFS"),
        ("scsi", "SCSI"),
        ("usb", "USB"),
        ("kvm", "Virtualization / KVM"),
        ("apparmor", "Security / AppArmor"),
        ("eap-pwd", "WPA / EAP-PWD"),
        ("sae", "WPA / SAE"),
        ("hostapd", "WPA / hostapd"),
        ("wpa_supplicant", "WPA / wpa_supplicant"),
        ("openwrt", "OpenWrt"),
        ("rdma", "Networking / RDMA"),
        ("tipc", "Networking / TIPC"),
        ("bpf", "BPF / eBPF"),
        ("drm", "GPU / DRM"),
    ]
    for keyword, subsystem in keyword_map:
        if keyword in desc_lower:
            return subsystem

    return ""


def process_csv(input_path: str):
    output_path = str(Path(input_path).with_stem(Path(input_path).stem + "_enriched"))

    with open(input_path, "r", encoding="utf-8", errors="replace") as infile:
        # Handle multiline descriptions by reading all content
        content = infile.read()

    # Use csv reader
    reader = csv.reader(content.splitlines())
    header = next(reader)

    # Find description column index
    desc_idx = None
    for i, col in enumerate(header):
        if col.strip().lower() == "description":
            desc_idx = i
            break

    if desc_idx is None:
        print("ERROR: Could not find 'Description' column in the CSV header.")
        print(f"  Columns found: {header}")
        sys.exit(1)

    print(f"Found Description at column index {desc_idx} (column letter: {chr(65 + desc_idx)})")

    # New columns to add
    new_header = header + ["Affected File/Path", "Affected Function(s)", "Affected Subsystem"]

    rows_out = []
    stats = {"total": 0, "with_file": 0, "with_func": 0, "with_subsys": 0}

    for row in reader:
        if len(row) <= desc_idx:
            rows_out.append(row + ["", "", ""])
            continue

        desc = row[desc_idx]
        stats["total"] += 1

        files = extract_file_paths(desc)
        funcs = extract_functions(desc)
        subsystem = classify_subsystem(files, desc)

        if files:
            stats["with_file"] += 1
        if funcs:
            stats["with_func"] += 1
        if subsystem:
            stats["with_subsys"] += 1

        row_out = row + [
            "; ".join(files),
            "; ".join(funcs),
            subsystem,
        ]
        rows_out.append(row_out)

    # Write enriched CSV
    with open(output_path, "w", encoding="utf-8", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(new_header)
        writer.writerows(rows_out)

    print(f"\nDone! Enriched CSV written to: {output_path}")
    print(f"\nExtraction stats:")
    print(f"  Total CVE rows:              {stats['total']}")
    print(f"  Rows with file/path found:   {stats['with_file']}")
    print(f"  Rows with function found:    {stats['with_func']}")
    print(f"  Rows with subsystem derived: {stats['with_subsys']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        input_file = r"C:\Amp_demos\Elta-Finitestate\scan_for_Elta.csv"
    else:
        input_file = sys.argv[1]

    process_csv(input_file)
