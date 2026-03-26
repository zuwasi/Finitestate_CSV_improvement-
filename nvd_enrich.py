"""
Enrich CVEs that are missing Affected File/Path by querying:
  1. NVD API v2.0  – to get git commit reference URLs
  2. git.kernel.org / github.com commit pages – to extract changed file paths

Updates scan_for_Elta_enriched.csv in-place (backs up original first).

Usage:  python nvd_enrich.py [--limit N]  (default: process all missing rows)
"""

import csv
import re
import sys
import shutil
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INPUT_CSV = r"C:\Amp_demos\Elta-Finitestate\scan_for_Elta_enriched.csv"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
NVD_DELAY = 6.5          # seconds between NVD calls (no API key = 5 req / 30s)
GIT_DELAY = 1.0          # seconds between git page fetches
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2

# Subsystem classifier (same as in extract_cve_details.py)
SUBSYSTEM_MAP = {
    "net/ipv4": "Networking / IPv4",
    "net/ipv6": "Networking / IPv6",
    "net/wireless": "Networking / Wireless (cfg80211)",
    "net/bluetooth": "Networking / Bluetooth",
    "net/rds": "Networking / RDS",
    "net/netfilter": "Networking / Netfilter",
    "net/core": "Networking / Core",
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

KEYWORD_SUBSYSTEM = [
    ("wifi", "WiFi"), ("wireless", "Wireless"), ("bluetooth", "Bluetooth"),
    ("netfilter", "Networking / Netfilter"), ("ipv4", "Networking / IPv4"),
    ("ipv6", "Networking / IPv6"), ("tcp", "Networking / TCP"),
    ("udp", "Networking / UDP"), ("nfs", "Filesystem / NFS"),
    ("btrfs", "Filesystem / Btrfs"), ("xfs", "Filesystem / XFS"),
    ("scsi", "SCSI"), ("usb", "USB"), ("kvm", "Virtualization / KVM"),
    ("apparmor", "Security / AppArmor"), ("eap-pwd", "WPA / EAP-PWD"),
    ("sae", "WPA / SAE"), ("hostapd", "WPA / hostapd"),
    ("wpa_supplicant", "WPA / wpa_supplicant"), ("openwrt", "OpenWrt"),
    ("rdma", "Networking / RDMA"), ("tipc", "Networking / TIPC"),
    ("bpf", "BPF / eBPF"), ("drm", "GPU / DRM"), ("cifs", "Filesystem / CIFS"),
    ("ext4", "Filesystem / ext4"), ("smb", "Filesystem / SMB"),
]

# Regex for C/kernel file paths
FILE_RE = re.compile(r'([a-zA-Z_][\w\-]*/[\w\-]+(?:/[\w\-\.]+)*\.(?:c|h|S))')
FUNC_RE = re.compile(r'\b([a-zA-Z_][\w]*(?:_[\w]+)+)\s*\(\)')
FUNC_IN_RE = re.compile(r'(?:in|via|from|function)\s+([a-zA-Z_][\w]*(?:_[\w]+)*)\s*\(')

# For parsing git.kernel.org diff pages
KERNEL_DIFF_FILE_RE = re.compile(r'diff --git a/([\S]+) b/')
# For parsing github commit pages (raw diff)
GITHUB_DIFF_FILE_RE = re.compile(r'diff --git a/([\S]+) b/')

session = requests.Session()
session.headers.update({"User-Agent": "CVE-Enricher/1.0"})


def classify_subsystem(file_paths, description=""):
    for fp in file_paths:
        for prefix in sorted(SUBSYSTEM_MAP.keys(), key=len, reverse=True):
            if fp.startswith(prefix):
                return SUBSYSTEM_MAP[prefix]
    desc_lower = description.lower()
    for kw, sub in KEYWORD_SUBSYSTEM:
        if kw in desc_lower:
            return sub
    return ""


def extract_functions(text):
    funcs = set()
    for m in FUNC_RE.findall(text):
        funcs.add(m)
    for m in FUNC_IN_RE.findall(text):
        if m.lower() not in ("the", "this", "that", "which", "version", "before", "after"):
            funcs.add(m)
    return sorted(funcs)


def fetch_nvd(cve_id):
    """Query NVD API and return list of reference URLs."""
    url = NVD_API_URL + "?cveId=" + cve_id
    for attempt in range(MAX_RETRIES):
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return [], ""
                cve_data = vulns[0].get("cve", {})
                # Get references
                refs = [ref.get("url", "") for ref in cve_data.get("references", [])]
                # Also get full description for keyword extraction
                descs = cve_data.get("descriptions", [])
                full_desc = ""
                for d in descs:
                    if d.get("lang") == "en":
                        full_desc = d.get("value", "")
                        break
                return refs, full_desc
            elif r.status_code == 403:
                # Rate limited, wait longer
                time.sleep(30)
            else:
                return [], ""
        except Exception:
            time.sleep(5)
    return [], ""


def fetch_git_diff_files(url):
    """Fetch a git commit page and extract changed file paths."""
    files = []
    try:
        parsed = urlparse(url)

        # git.kernel.org – fetch the patch
        if "git.kernel.org" in (parsed.hostname or ""):
            # Handle /stable/c/<hash> format
            stable_match = re.search(r'/stable/c/([0-9a-f]+)', url)
            if stable_match:
                commit_hash = stable_match.group(1)
                patch_url = f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_hash}"
            else:
                # Standard /commit/ to /patch/ conversion
                patch_url = url.replace("/commit/", "/patch/")
            r = session.get(patch_url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                for m in KERNEL_DIFF_FILE_RE.findall(r.text):
                    if m not in files:
                        files.append(m)

        # github.com – fetch the .patch
        elif "github.com" in (parsed.hostname or ""):
            patch_url = url.rstrip("/") + ".patch"
            r = session.get(patch_url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                for m in GITHUB_DIFF_FILE_RE.findall(r.text):
                    if m not in files:
                        files.append(m)

    except Exception:
        pass
    return files


def is_git_commit_url(url):
    """Check if URL points to a git commit."""
    if not url:
        return False
    if "git.kernel.org" in url:
        return True
    if "github.com" in url and "/commit/" in url:
        return True
    if "gitlab" in url and "/commit/" in url:
        return True
    return False


def process():
    limit = None
    if "--limit" in sys.argv:
        idx = sys.argv.index("--limit")
        limit = int(sys.argv[idx + 1])

    # Read CSV
    with open(INPUT_CSV, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    col = {c.strip(): i for i, c in enumerate(header)}
    cve_idx = col["CVE ID"]
    desc_idx = col["Description"]
    file_idx = col["Affected File/Path"]
    func_idx = col["Affected Function(s)"]
    sub_idx = col["Affected Subsystem"]

    # Find rows missing file/path
    missing = []
    for i, row in enumerate(rows):
        if not row[file_idx].strip():
            missing.append(i)

    total_missing = len(missing)
    if limit:
        missing = missing[:limit]
    to_process = len(missing)

    print(f"Total CVEs: {len(rows)}")
    print(f"Missing Affected File/Path: {total_missing}")
    print(f"Will process: {to_process} CVEs via NVD API + git commit lookups")
    print(f"Estimated time: ~{to_process * (NVD_DELAY + GIT_DELAY) / 60:.0f} minutes")
    print()

    # Backup
    backup = INPUT_CSV + ".bak"
    shutil.copy2(INPUT_CSV, backup)
    print(f"Backup saved: {backup}")

    enriched = 0
    errors = 0
    last_nvd_call = 0

    for count, row_idx in enumerate(missing, start=1):
        row = rows[row_idx]
        cve_id = row[cve_idx].strip()
        existing_desc = row[desc_idx] if desc_idx < len(row) else ""

        print(f"[{count}/{to_process}] {cve_id} ... ", end="", flush=True)

        # Rate limit NVD calls
        elapsed = time.time() - last_nvd_call
        if elapsed < NVD_DELAY:
            time.sleep(NVD_DELAY - elapsed)

        refs, nvd_desc = fetch_nvd(cve_id)
        last_nvd_call = time.time()

        if not refs:
            print("no NVD refs found")
            errors += 1
            continue

        # Find git commit URLs and fetch diffs
        all_files = []
        all_funcs = []
        git_urls = [u for u in refs if is_git_commit_url(u)]

        for git_url in git_urls[:3]:  # limit to 3 commits per CVE
            time.sleep(GIT_DELAY)
            diff_files = fetch_git_diff_files(git_url)
            all_files.extend(diff_files)

        # Also try regex on NVD description (might have more detail than FS export)
        combined_desc = existing_desc + " " + nvd_desc
        for m in FILE_RE.findall(combined_desc):
            if m not in all_files:
                all_files.append(m)

        funcs_from_desc = extract_functions(combined_desc)
        all_funcs.extend(funcs_from_desc)

        # Deduplicate
        seen_f = set()
        unique_files = []
        for f in all_files:
            if f not in seen_f:
                seen_f.add(f)
                unique_files.append(f)

        seen_fn = set()
        unique_funcs = []
        for fn in all_funcs:
            if fn not in seen_fn:
                seen_fn.add(fn)
                unique_funcs.append(fn)

        # Update row
        if unique_files:
            row[file_idx] = "; ".join(unique_files)
        if unique_funcs and not row[func_idx].strip():
            row[func_idx] = "; ".join(unique_funcs)
        if not row[sub_idx].strip():
            sub = classify_subsystem(unique_files, combined_desc)
            if sub:
                row[sub_idx] = sub

        if unique_files:
            enriched += 1
            print(f"found {len(unique_files)} file(s): {unique_files[0]}{'...' if len(unique_files) > 1 else ''}")
        else:
            print("no files found in refs")

        rows[row_idx] = row

        # Save progress every 50 CVEs
        if count % 50 == 0:
            _save(header, rows)
            print(f"  [checkpoint saved at {count}/{to_process}]")

    # Final save
    _save(header, rows)
    print(f"\n{'='*60}")
    print(f"Done! Enriched {enriched} / {to_process} CVEs with file paths")
    print(f"Errors/skipped: {errors}")
    print(f"Output: {INPUT_CSV}")


def _save(header, rows):
    with open(INPUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


if __name__ == "__main__":
    process()
