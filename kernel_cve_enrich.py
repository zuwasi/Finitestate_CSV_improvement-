"""
Fill remaining orphan CVEs using:
  1. linux_kernel_cves JSON database (commit hashes → git patch → file paths)
  2. For non-kernel CVEs (hostapd, wpa_supplicant, OpenWrt) use known mappings

Updates scan_for_Elta_enriched.csv in-place.
Usage: python kernel_cve_enrich.py
"""

import csv
import json
import re
import shutil
import time
from pathlib import Path

import requests

INPUT_CSV = r"C:\Amp_demos\Elta-Finitestate\scan_for_Elta_enriched.csv"
KERNEL_CVES_URL = "https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/master/data/kernel_cves.json"
GIT_DELAY = 1.5
REQUEST_TIMEOUT = 20

DIFF_FILE_RE = re.compile(r'diff --git a/([\S]+) b/')
FILE_RE = re.compile(r'([a-zA-Z_][\w\-]*/[\w\-]+(?:/[\w\-\.]+)*\.(?:c|h|S))')
FUNC_RE = re.compile(r'\b([a-zA-Z_][\w]*(?:_[\w]+)+)\s*\(\)')

# Known file mappings for non-kernel components
KNOWN_MAPPINGS = {
    # hostapd / wpa_supplicant EAP-PWD CVEs
    "CVE-2022-23304": {"files": "src/eap_peer/eap_pwd.c; src/eap_server/eap_server_pwd.c", "funcs": "eap_pwd_perform_commit_exchange", "sub": "WPA / EAP-PWD"},
    "CVE-2022-23303": {"files": "src/common/sae.c", "funcs": "sae_parse_commit_scalar; sae_parse_commit_element", "sub": "WPA / SAE"},
    "CVE-2019-9499":  {"files": "src/eap_peer/eap_pwd.c", "funcs": "eap_pwd_perform_commit_exchange", "sub": "WPA / EAP-PWD"},
    "CVE-2019-9498":  {"files": "src/eap_server/eap_server_pwd.c", "funcs": "eap_pwd_process_commit_resp", "sub": "WPA / EAP-PWD"},
    "CVE-2019-9497":  {"files": "src/eap_server/eap_server_pwd.c; src/eap_peer/eap_pwd.c", "funcs": "eap_pwd_process_commit_resp", "sub": "WPA / EAP-PWD"},
    "CVE-2019-9496":  {"files": "src/common/sae.c", "funcs": "sae_parse_commit", "sub": "WPA / SAE"},
    "CVE-2019-9495":  {"files": "src/crypto/crypto_openssl.c; src/eap_peer/eap_pwd.c", "funcs": "eap_pwd_perform_confirm_exchange", "sub": "WPA / EAP-PWD"},
    "CVE-2019-9494":  {"files": "src/common/sae.c", "funcs": "sae_derive_pwe_ecc", "sub": "WPA / SAE"},
    # OpenWrt
    "CVE-2020-28951": {"files": "file.c; util.c", "funcs": "uci_parse_package; uci_strdup", "sub": "OpenWrt / libuci"},
    "CVE-2020-7982":  {"files": "libopkg/opkg_download.c", "funcs": "opkg_verify_integrity", "sub": "OpenWrt / opkg"},
}

SUBSYSTEM_MAP = {
    "net/ipv4": "Networking / IPv4", "net/ipv6": "Networking / IPv6",
    "net/wireless": "Networking / Wireless (cfg80211)", "net/bluetooth": "Networking / Bluetooth",
    "net/rds": "Networking / RDS", "net/netfilter": "Networking / Netfilter",
    "net/core": "Networking / Core", "net/tipc": "Networking / TIPC",
    "net/nfc": "Networking / NFC", "net/can": "Networking / CAN",
    "net/sctp": "Networking / SCTP", "net": "Networking",
    "drivers/net/wireless/marvell": "WiFi Driver / Marvell",
    "drivers/net/wireless/ath": "WiFi Driver / Atheros",
    "drivers/net/wireless/realtek": "WiFi Driver / Realtek",
    "drivers/net/wireless": "WiFi Driver",
    "drivers/net/ethernet": "Ethernet Driver", "drivers/net": "Network Driver",
    "drivers/media/usb": "Media / USB", "drivers/media": "Media Driver",
    "drivers/usb/gadget": "USB Gadget Driver", "drivers/usb": "USB Driver",
    "drivers/scsi": "SCSI Driver", "drivers/staging": "Staging Driver",
    "drivers/soc": "SoC Driver", "drivers/gpu/drm/amd": "GPU / AMD Display",
    "drivers/gpu/drm": "GPU / DRM", "drivers/target": "SCSI Target (LIO)",
    "drivers/block": "Block Driver", "drivers/nvme": "NVMe Driver",
    "drivers/infiniband": "InfiniBand Driver", "drivers/vhost": "VHost Driver",
    "drivers/xen": "Xen Driver", "drivers/md": "MD/RAID Driver",
    "drivers": "Kernel Driver",
    "fs/btrfs": "Filesystem / Btrfs", "fs/xfs": "Filesystem / XFS",
    "fs/jfs": "Filesystem / JFS", "fs/cifs": "Filesystem / CIFS",
    "fs/ext4": "Filesystem / ext4", "fs/nfs": "Filesystem / NFS",
    "fs/overlayfs": "Filesystem / OverlayFS", "fs": "Filesystem",
    "sound/usb": "Audio / USB", "sound": "Audio",
    "security/apparmor": "Security / AppArmor", "security/keys": "Security / Keys",
    "security": "Security",
    "kernel": "Kernel Core", "mm": "Memory Management",
    "arch/x86": "Architecture / x86", "arch": "Architecture",
    "virt/kvm": "Virtualization / KVM", "crypto": "Crypto", "lib": "Kernel Lib",
}

session = requests.Session()
session.headers.update({"User-Agent": "CVE-Enricher/1.0"})


def classify_subsystem(file_paths):
    for fp in file_paths:
        for prefix in sorted(SUBSYSTEM_MAP.keys(), key=len, reverse=True):
            if fp.startswith(prefix):
                return SUBSYSTEM_MAP[prefix]
    return ""


def fetch_patch_files(commit_hash):
    """Fetch kernel git patch and return list of changed files."""
    # Try stable tree first, then torvalds tree
    urls = [
        f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_hash}",
        f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit_hash}",
    ]
    for url in urls:
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                files = []
                for m in DIFF_FILE_RE.findall(r.text):
                    if m not in files:
                        files.append(m)
                # Also extract functions from commit message (first 500 chars)
                funcs = FUNC_RE.findall(r.text[:1500])
                return files, list(set(funcs))
        except Exception:
            pass
    return [], []


def process():
    # Read CSV
    with open(INPUT_CSV, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    col = {c.strip(): i for i, c in enumerate(header)}
    cve_idx = col["CVE ID"]
    file_idx = col["Affected File/Path"]
    func_idx = col["Affected Function(s)"]
    sub_idx = col["Affected Subsystem"]
    comp_idx = col["Component"]

    # Find missing rows
    missing_indices = []
    missing_cves = set()
    for i, row in enumerate(rows):
        if not row[file_idx].strip():
            missing_indices.append(i)
            missing_cves.add(row[cve_idx].strip())

    print(f"Total CVEs: {len(rows)}")
    print(f"Still missing file/path: {len(missing_indices)}")
    print(f"Unique missing CVE IDs: {len(missing_cves)}")

    # Step 1: Apply known mappings for non-kernel CVEs
    known_filled = 0
    for i in missing_indices:
        cve_id = rows[i][cve_idx].strip()
        if cve_id in KNOWN_MAPPINGS:
            m = KNOWN_MAPPINGS[cve_id]
            rows[i][file_idx] = m["files"]
            if not rows[i][func_idx].strip():
                rows[i][func_idx] = m["funcs"]
            if not rows[i][sub_idx].strip():
                rows[i][sub_idx] = m["sub"]
            known_filled += 1

    print(f"Filled from known mappings: {known_filled}")

    # Recalculate missing
    missing_indices = [i for i in missing_indices if not rows[i][file_idx].strip()]
    missing_cves = {rows[i][cve_idx].strip() for i in missing_indices}
    print(f"Remaining after known mappings: {len(missing_indices)}")

    # Step 2: Download kernel CVE database
    print("\nDownloading linux_kernel_cves database...")
    try:
        r = session.get(KERNEL_CVES_URL, timeout=60)
        r.raise_for_status()
        kernel_db = r.json()
        print(f"  Loaded {len(kernel_db)} kernel CVEs from database")
    except Exception as e:
        print(f"  Failed to download: {e}")
        kernel_db = {}

    # Step 3: For each missing CVE, look up fix commit and fetch patch
    # First, collect commit hashes from database
    cve_commits = {}
    cve_cmt_msgs = {}
    for cve_id in missing_cves:
        if cve_id in kernel_db:
            entry = kernel_db[cve_id]
            fixes = entry.get("fixes", "")
            if fixes and len(fixes) >= 8 and not fixes.startswith("http"):
                # Could be multiple commits separated by comma or space
                commits = re.findall(r'[0-9a-f]{12,40}', fixes)
                if commits:
                    cve_commits[cve_id] = commits
            cmt_msg = entry.get("cmt_msg", "")
            if cmt_msg:
                cve_cmt_msgs[cve_id] = cmt_msg

    print(f"  CVEs with fix commits in database: {len(cve_commits)}")
    print(f"  CVEs with commit messages: {len(cve_cmt_msgs)}")

    # Step 4: Fetch patches from git.kernel.org
    total_to_fetch = len(cve_commits)
    print(f"\nFetching {total_to_fetch} git patches...")

    cve_files = {}  # cve_id -> (files, funcs)
    for count, (cve_id, commits) in enumerate(cve_commits.items(), 1):
        print(f"  [{count}/{total_to_fetch}] {cve_id} ... ", end="", flush=True)
        all_files = []
        all_funcs = []
        for commit in commits[:2]:  # max 2 commits per CVE
            time.sleep(GIT_DELAY)
            files, funcs = fetch_patch_files(commit)
            all_files.extend(f for f in files if f not in all_files)
            all_funcs.extend(f for f in funcs if f not in all_funcs)

        # Also extract file paths from commit message
        cmt_msg = cve_cmt_msgs.get(cve_id, "")
        for m in FILE_RE.findall(cmt_msg):
            if m not in all_files:
                all_files.append(m)

        if all_files:
            cve_files[cve_id] = (all_files, all_funcs)
            print(f"{len(all_files)} file(s)")
        else:
            print("no files")

    # Step 5: Also try to extract file paths from commit messages for CVEs without fix commits
    for cve_id in missing_cves:
        if cve_id not in cve_files and cve_id in cve_cmt_msgs:
            cmt_msg = cve_cmt_msgs[cve_id]
            files = FILE_RE.findall(cmt_msg)
            funcs = FUNC_RE.findall(cmt_msg)
            if files:
                cve_files[cve_id] = (list(dict.fromkeys(files)), list(set(funcs)))

    print(f"\nTotal CVEs with file data: {len(cve_files)}")

    # Step 6: Update rows
    updated = 0
    for i in missing_indices:
        cve_id = rows[i][cve_idx].strip()
        if cve_id in cve_files:
            files, funcs = cve_files[cve_id]
            rows[i][file_idx] = "; ".join(files)
            if funcs and not rows[i][func_idx].strip():
                rows[i][func_idx] = "; ".join(funcs)
            if not rows[i][sub_idx].strip():
                sub = classify_subsystem(files)
                if sub:
                    rows[i][sub_idx] = sub
            updated += 1

    # Backup and save
    shutil.copy2(INPUT_CSV, INPUT_CSV + ".bak2")
    with open(INPUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    # Final stats
    final_missing = sum(1 for row in rows if not row[file_idx].strip())
    print(f"\n{'='*60}")
    print(f"Updated {updated} + {known_filled} (known) = {updated + known_filled} CVEs")
    print(f"Still missing file/path: {final_missing} / {len(rows)}")
    print(f"Coverage: {(len(rows)-final_missing)*100//len(rows)}%")
    print(f"Output: {INPUT_CSV}")


if __name__ == "__main__":
    process()
