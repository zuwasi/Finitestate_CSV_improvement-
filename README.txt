==============================================================================
  Finite State CVE Scan Report Enrichment Pipeline
==============================================================================

Enriches Finite State CVE scan reports by extracting affected file paths,
functions, and subsystems from NVD API, kernel git patches, and
linux_kernel_cves DB. Transforms generic "Linux 4.9.152" into actionable
paths like "drivers/net/wireless/marvell/mwifiex/ie.c". Outputs color-coded
Excel with filter dropdowns.


PROBLEM
========

Finite State scan exports list CVEs with a generic "Component" field
(e.g., "Linux 4.9.152") that provides no actionable detail for
remediation or team assignment. The real information (affected source
files, functions, subsystems) is buried in free-text descriptions or
not present at all.


SOLUTION
=========

A five-script Python pipeline that enriches the CVE data in five phases:

Phase 1 - Regex extraction from descriptions
Phase 2 - NVD API + git kernel patch lookups
Phase 3 - Linux kernel CVE tracker database + known component mappings
Phase 4 - Formatted Excel output with colors and filter dropdowns
Phase 5 - CWE mitigation enrichment from local CWE XML database (air-gap safe)


RESULTS
========

                          ORIGINAL         ENRICHED
                          --------         --------
  Total CVEs:             2,695            2,695
  Columns:                21               25 (4 new)

  Affected File/Path:     0 (0%)           2,664 (98%)
  Affected Function(s):   0 (0%)           1,282 (48%)
  Affected Subsystem:     0 (0%)           2,621 (97%)
  CWE Mitigation:         0 (0%)           2,250 (83%)

  Unique subsystems:      N/A              67 categories


SCRIPTS
========

  extract_cve_details.py      - Phase 1: regex extraction from descriptions
  nvd_enrich.py               - Phase 2: NVD API + git patch lookups
  kernel_cve_enrich.py        - Phase 3: kernel CVE tracker + known mappings
  create_excel_report.py      - Phase 4: Excel formatting, colors, dropdowns
  cwe_mitigation_enrich.py    - Phase 5: CWE mitigation from local XML DB


USAGE
======

  1. python extract_cve_details.py <scan_file.csv>
  2. python nvd_enrich.py
  3. python kernel_cve_enrich.py
  4. python create_excel_report.py
  5. python cwe_mitigation_enrich.py              (uses local DB)
     python cwe_mitigation_enrich.py --download   (downloads DB first)

Phase 2 takes approximately 2-3 hours due to NVD API rate limits.
All other phases complete in under a minute.

Air-gapped deployment: Transfer cwe_db/cwec_latest.xml.zip from the
sanitisation server into the cwe_db/ directory, then run Phase 5
without --download.


REQUIREMENTS
=============

  Python 3.10+
  openpyxl
  requests


FILES
======

  scan_for_Elta.csv                     - Original Finite State export
  scan_for_Elta_enriched.csv            - Enriched CSV with 3 new columns
  scan_for_Elta_enriched.xlsx           - Formatted Excel output
  CVE_Report_Improvement_Summary.txt    - Detailed process documentation


EXCEL COLUMN LAYOUT
=====================

  A = CVE ID
  B = Severity              (color-coded + dropdown filter)
  C = Affected File/Path    (azure background)
  D = Affected Function(s)  (light green background)
  E = Affected Subsystem    (light orange background + dropdown filter)
  F onward = remaining original columns (CVSS, KEV, CWE, Description, etc.)

==============================================================================
