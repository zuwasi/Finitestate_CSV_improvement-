"""
Convert enriched CVE CSV to a formatted Excel workbook with:
 - Color-coded columns: File/Path (azure), Function (light green), Subsystem (light orange)
 - AutoFilter on all columns
 - Data Validation dropdown on Subsystem column for easy filtering
 - Frozen header row
 - Auto-fitted column widths
"""

import csv
import sys
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation


def create_excel(input_csv: str):
    output_xlsx = str(Path(input_csv).with_suffix(".xlsx"))

    # --- Read CSV ---------------------------------------------------------
    with open(input_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    # --- Identify the 3 enriched columns ----------------------------------
    col_names = {c.strip(): i for i, c in enumerate(header)}
    file_col = col_names.get("Affected File/Path")
    func_col = col_names.get("Affected Function(s)")
    sub_col = col_names.get("Affected Subsystem")

    if any(c is None for c in (file_col, func_col, sub_col)):
        print("ERROR: enriched columns not found. Run extract_cve_details.py first.")
        sys.exit(1)

    # --- Reorder columns: move the 3 affected columns right after Severity (B) ---
    enriched_indices = [file_col, func_col, sub_col]
    sev_idx = col_names.get("Severity", 1)
    insert_after = sev_idx  # insert after Severity (index 1 = column B)

    # Build new column order
    original_order = list(range(len(header)))
    remaining = [i for i in original_order if i not in enriched_indices]
    new_order = remaining[:insert_after + 1] + enriched_indices + remaining[insert_after + 1:]

    header = [header[i] for i in new_order]
    rows = [[row[i] if i < len(row) else "" for i in new_order] for row in rows]

    # Recalculate column positions after reorder
    col_names = {c.strip(): i for i, c in enumerate(header)}
    file_col = col_names["Affected File/Path"]
    func_col = col_names["Affected Function(s)"]
    sub_col = col_names["Affected Subsystem"]

    # Convert to 1-based for openpyxl
    file_col_1 = file_col + 1
    func_col_1 = func_col + 1
    sub_col_1 = sub_col + 1

    # --- Colour definitions -----------------------------------------------
    AZURE_FILL = PatternFill(start_color="DCE6F1", end_color="DCE6F1", fill_type="solid")
    GREEN_FILL = PatternFill(start_color="D5F5E3", end_color="D5F5E3", fill_type="solid")
    ORANGE_FILL = PatternFill(start_color="FDEBD0", end_color="FDEBD0", fill_type="solid")

    AZURE_HDR = PatternFill(start_color="5B9BD5", end_color="5B9BD5", fill_type="solid")
    GREEN_HDR = PatternFill(start_color="70AD47", end_color="70AD47", fill_type="solid")
    ORANGE_HDR = PatternFill(start_color="ED7D31", end_color="ED7D31", fill_type="solid")
    GREY_HDR = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")

    HEADER_FONT = Font(bold=True, color="FFFFFF", size=11)
    BODY_FONT = Font(size=10)
    THIN_BORDER = Border(
        left=Side(style="thin", color="BFBFBF"),
        right=Side(style="thin", color="BFBFBF"),
        top=Side(style="thin", color="BFBFBF"),
        bottom=Side(style="thin", color="BFBFBF"),
    )

    # Severity colour map
    SEV_FILLS = {
        "critical": PatternFill(start_color="FF4D4D", end_color="FF4D4D", fill_type="solid"),
        "high": PatternFill(start_color="FF9933", end_color="FF9933", fill_type="solid"),
        "medium": PatternFill(start_color="FFDD57", end_color="FFDD57", fill_type="solid"),
        "low": PatternFill(start_color="85E085", end_color="85E085", fill_type="solid"),
    }
    SEV_FONTS = {
        "critical": Font(bold=True, color="FFFFFF", size=10),
        "high": Font(bold=True, color="FFFFFF", size=10),
        "medium": Font(bold=True, color="333333", size=10),
        "low": Font(bold=True, color="333333", size=10),
    }

    # --- Build workbook ---------------------------------------------------
    wb = Workbook()
    ws = wb.active
    ws.title = "CVE Scan - Enriched"

    total_cols = len(header)

    # Write header
    for c_idx, col_name in enumerate(header, start=1):
        cell = ws.cell(row=1, column=c_idx, value=col_name)
        cell.font = HEADER_FONT
        cell.border = THIN_BORDER
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

        if c_idx == file_col_1:
            cell.fill = AZURE_HDR
        elif c_idx == func_col_1:
            cell.fill = GREEN_HDR
        elif c_idx == sub_col_1:
            cell.fill = ORANGE_HDR
        else:
            cell.fill = GREY_HDR

    # Write data rows
    sev_col_idx = col_names.get("Severity")
    for r_idx, row in enumerate(rows, start=2):
        for c_idx in range(1, total_cols + 1):
            value = row[c_idx - 1] if c_idx - 1 < len(row) else ""
            cell = ws.cell(row=r_idx, column=c_idx, value=value)
            cell.font = BODY_FONT
            cell.border = THIN_BORDER
            cell.alignment = Alignment(vertical="center", wrap_text=False)

            # Apply enriched-column fills
            if c_idx == file_col_1:
                cell.fill = AZURE_FILL
            elif c_idx == func_col_1:
                cell.fill = GREEN_FILL
            elif c_idx == sub_col_1:
                cell.fill = ORANGE_FILL

            # Severity colour
            if sev_col_idx is not None and c_idx == sev_col_idx + 1:
                sev = value.strip().lower()
                if sev in SEV_FILLS:
                    cell.fill = SEV_FILLS[sev]
                    cell.font = SEV_FONTS[sev]

    last_row = len(rows) + 1

    # --- AutoFilter (enables Excel filter dropdowns on every column) ------
    ws.auto_filter.ref = f"A1:{get_column_letter(total_cols)}{last_row}"

    # --- Data Validation dropdown on Subsystem column ---------------------
    # Collect unique subsystem values
    subsystems = sorted(
        {row[sub_col].strip() for row in rows if sub_col < len(row) and row[sub_col].strip()}
    )
    if subsystems:
        # Excel data validation formula list (max ~255 chars for inline list)
        formula_list = ",".join(subsystems)
        if len(formula_list) <= 255:
            dv = DataValidation(
                type="list",
                formula1=f'"{formula_list}"',
                allow_blank=True,
                showDropDown=False,
            )
        else:
            # Put subsystem list on a hidden helper sheet
            ws_helper = wb.create_sheet("_Subsystems")
            for i, s in enumerate(subsystems, start=1):
                ws_helper.cell(row=i, column=1, value=s)
            ws_helper.sheet_state = "hidden"
            dv = DataValidation(
                type="list",
                formula1=f"=_Subsystems!$A$1:$A${len(subsystems)}",
                allow_blank=True,
                showDropDown=False,
            )
        dv.prompt = "Select a subsystem to filter"
        dv.promptTitle = "Subsystem Filter"
        sub_letter = get_column_letter(sub_col_1)
        dv.add(f"{sub_letter}2:{sub_letter}{last_row}")
        ws.add_data_validation(dv)

    # --- Data Validation dropdown on Severity column ---------------------
    if sev_col_idx is not None:
        severities = sorted(
            {row[sev_col_idx].strip() for row in rows if sev_col_idx < len(row) and row[sev_col_idx].strip()}
        )
        if severities:
            sev_formula = ",".join(severities)
            dv_sev = DataValidation(
                type="list",
                formula1=f'"{sev_formula}"',
                allow_blank=True,
                showDropDown=False,
            )
            dv_sev.prompt = "Select a severity to filter"
            dv_sev.promptTitle = "Severity Filter"
            sev_letter = get_column_letter(sev_col_idx + 1)
            dv_sev.add(f"{sev_letter}2:{sev_letter}{last_row}")
            ws.add_data_validation(dv_sev)

    # --- Freeze top row ---------------------------------------------------
    ws.freeze_panes = "A2"

    # --- Auto-fit column widths (capped) ----------------------------------
    MAX_WIDTH = 45
    MIN_WIDTH = 10
    for c_idx in range(1, total_cols + 1):
        max_len = len(str(header[c_idx - 1]))
        # Sample first 200 rows for width
        for r_idx in range(2, min(last_row + 1, 202)):
            val = ws.cell(row=r_idx, column=c_idx).value
            if val:
                max_len = max(max_len, min(len(str(val)), MAX_WIDTH))
        ws.column_dimensions[get_column_letter(c_idx)].width = max(min(max_len + 2, MAX_WIDTH), MIN_WIDTH)

    # --- Save -------------------------------------------------------------
    wb.save(output_xlsx)
    print(f"Excel report saved to: {output_xlsx}")
    print(f"  Total rows: {len(rows)}")
    print(f"  Unique subsystems in dropdown: {len(subsystems)}")
    print(f"\nColumn colour legend:")
    print(f"  Azure  (col {get_column_letter(file_col_1)}) = Affected File/Path")
    print(f"  Green  (col {get_column_letter(func_col_1)}) = Affected Function(s)")
    print(f"  Orange (col {get_column_letter(sub_col_1)}) = Affected Subsystem")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        csv_file = r"C:\Amp_demos\Elta-Finitestate\scan_for_Elta_enriched.csv"
    else:
        csv_file = sys.argv[1]
    create_excel(csv_file)
