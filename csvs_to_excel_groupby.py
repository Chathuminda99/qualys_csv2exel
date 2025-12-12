#!/usr/bin/env python3
"""
csvs_to_excel_groupby.py

Usage:
  python csvs_to_excel_groupby.py -i /path/to/csvs -o out.xlsx
  python csvs_to_excel_groupby.py --group-by ip

Features:
 - Supports grouping by DNS (FQDN) or IP addresses.
 - Interactive prompt asks user to choose grouping (dns/ip) when not provided as an arg.
 - Tries to detect flexible column names for DNS or IP in each CSV.
 - All previous formatting, severity parsing, covered-hosts behavior preserved.
"""

from pathlib import Path
import argparse
import sys
import re
import json
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Border, Side
from openpyxl.utils import get_column_letter

# Input columns expected (Type still used for filtering)
INPUT_KEEP_COLS = [
    "DNS", "Title", "Type", "Port", "Protocol", "CVE ID",
    "Vendor Reference", "CVSS3.1 Base", "Threat", "Impact",
    "Solution Exploitability", "Results"
]

# FINAL_COLS template will have the grouping field name substituted for "GROUP_FIELD"
FINAL_COLS_TEMPLATE = [
    "GROUP_FIELD", "Title", "Port", "Protocol", "CVE ID", "Vendor Reference",
    "CVSS3.1 Base", "Severity", "Threat", "Impact",
    "Solution Exploitability", "Results"
]

CVSS_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)")

# Common alternatives for DNS and IP column names
DNS_ALIASES = ["DNS", "FQDN", "FQDNs", "Hostname", "Host", "Host Name", "HostName"]
IP_ALIASES = ["IP", "IP Address", "IPAddress", "Address", "Host IP", "HostIP", "IPv4", "IPv6"]

def parse_cvss_score(cvss_field):
    if pd.isna(cvss_field):
        return None
    m = CVSS_RE.search(str(cvss_field))
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None

def cvss_to_severity(score):
    if score is None:
        return "Unknown"
    if score == 0.0:
        return "None"
    if 0.0 < score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    if 9.0 <= score <= 10.0:
        return "Critical"
    return "Unknown"

def sanitize_sheet_name(name, fallback="sheet"):
    if pd.isna(name):
        return fallback
    s = str(name)
    for ch in [':', '\\', '/', '?', '*', '[', ']']:
        s = s.replace(ch, '_')
    s = s.strip()
    if len(s) == 0:
        return fallback
    if len(s) > 31:
        s = s[:31]
    return s

def detect_group_column(df: pd.DataFrame, mode: str):
    """
    Detect the actual column name to use for grouping based on mode ('dns' or 'ip').
    Returns column name string or None if not found.
    """
    candidates = DNS_ALIASES if mode == "dns" else IP_ALIASES
    cols_lower = {c.lower(): c for c in df.columns}
    for alias in candidates:
        if alias.lower() in cols_lower:
            return cols_lower[alias.lower()]
    # not found
    return None

def collect_all_group_values(input_folder: Path, mode: str):
    """
    Scan all CSV files and collect all unique grouping values for the chosen mode,
    using detection of column aliases. Missing/empty become "<UNKNOWN>".
    """
    values = set()
    csv_files = sorted([p for p in input_folder.iterdir() if p.suffix.lower() == ".csv"])
    for f in csv_files:
        try:
            df = pd.read_csv(f, skiprows=7, dtype=str, low_memory=False)
        except Exception:
            continue
        col = detect_group_column(df, mode)
        if not col:
            # If the preferred grouping column missing, treat file as having unknown host
            values.add("<UNKNOWN>")
            continue
        vals = df[col].astype(str).str.strip().replace({"nan": pd.NA}).dropna().unique()
        for v in vals:
            vstr = str(v).strip()
            if vstr == "":
                values.add("<UNKNOWN>")
            else:
                values.add(vstr)
    return sorted(values)

def process_folder(input_folder: Path, mode: str):
    """
    Read each CSV, filter for VULN rows, and group rows by the detected grouping field for the chosen mode.
    Returns dict mapping group_value -> dataframe (with final columns, Type dropped).
    """
    csv_files = sorted([p for p in input_folder.iterdir() if p.suffix.lower() == ".csv"])
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {input_folder}")

    group_to_parts = {}
    print(f"Found {len(csv_files)} CSV files. Processing for VULN rows (group by {mode})...")

    for f in csv_files:
        print(f"  Reading {f.name} ...")
        try:
            df = pd.read_csv(f, skiprows=7, dtype=str, low_memory=False)
        except Exception as e:
            print(f"    ERROR reading {f.name}: {e}. Skipping.")
            continue

        # Ensure input columns exist so selection won't fail
        for col in INPUT_KEEP_COLS:
            if col not in df.columns:
                df[col] = pd.NA

        # Find which column to use for grouping in this CSV
        group_col = detect_group_column(df, mode)
        if group_col is None:
            # create placeholder column to ensure grouping will put rows under <UNKNOWN>
            df["_GROUP_PLACEHOLDER_"] = pd.NA
            group_col = "_GROUP_PLACEHOLDER_"

        # Filter Type == VULN (case-insensitive)
        df['Type'] = df['Type'].astype(str).str.strip()
        mask_vuln = df['Type'].str.upper() == 'VULN'
        df_vuln = df[mask_vuln].copy()
        if df_vuln.empty:
            print(f"    No VULN rows in {f.name}.")
            continue

        # Keep only necessary columns (including the group_col if not present in INPUT_KEEP_COLS)
        # Ensure we include the group column in the dataframe we keep
        keep_cols = list(INPUT_KEEP_COLS)
        if group_col not in keep_cols:
            # append to ensure grouping value is present (we'll rename later)
            keep_cols = [group_col] + keep_cols
        df_vuln = df_vuln[keep_cols].copy()

        # Parse CVSS -> Severity
        scores = df_vuln['CVSS3.1 Base'].apply(parse_cvss_score)
        severities = scores.apply(cvss_to_severity)
        df_vuln['Severity'] = severities

        # Reorder to ensure Severity after CVSS3.1 Base
        cols = list(df_vuln.columns)
        if "CVSS3.1 Base" in cols:
            idx = cols.index("CVSS3.1 Base")
            cols = [c for c in cols if c != "Severity"]
            cols = cols[:idx+1] + ["Severity"] + cols[idx+1:]
            df_vuln = df_vuln[cols]

        # Drop Type column from outputs
        if "Type" in df_vuln.columns:
            df_vuln.drop(columns=["Type"], inplace=True)

        # Rename the detected group column to a standard name "GROUP_FIELD" so we can substitute later
        df_vuln = df_vuln.rename(columns={group_col: "GROUP_FIELD"})

        # Normalize group values and group
        df_vuln['GROUP_FIELD'] = df_vuln['GROUP_FIELD'].astype(str).str.strip()
        df_vuln['GROUP_FIELD'] = df_vuln['GROUP_FIELD'].replace({"nan": pd.NA})
        df_vuln['GROUP_FIELD'] = df_vuln['GROUP_FIELD'].fillna("<UNKNOWN>")

        for group_val, grp in df_vuln.groupby('GROUP_FIELD', dropna=False):
            key = group_val if (group_val is not None and group_val != "") else "<UNKNOWN>"
            if key not in group_to_parts:
                group_to_parts[key] = []
            group_to_parts[key].append(grp)

    # Concatenate parts per group
    group_frames = {}
    for g, parts in group_to_parts.items():
        concatenated = pd.concat(parts, ignore_index=True)
        # Ensure final columns in expected order (replace GROUP_FIELD with actual header later)
        group_frames[g] = concatenated
    return group_frames

def write_to_excel(all_groups, group_frames: dict, out_file: Path, col_widths: dict, mode: str):
    """
    Writes Covered Hosts sheet first with counts, then a sheet per host (only for hosts with VULN rows).
    FINAL_COLS_TEMPLATE will be expanded with group header name (DNS or IP).
    """
    group_header = "DNS" if mode == "dns" else "IP"
    final_cols = [c if c != "GROUP_FIELD" else group_header for c in FINAL_COLS_TEMPLATE]

    # prepare covered hosts rows with counts
    rows = []
    for g in all_groups:
        df = group_frames.get(g)
        if df is None:
            rows_count = 0
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        else:
            if "Severity" not in df.columns:
                df["Severity"] = df["CVSS3.1 Base"].apply(lambda x: cvss_to_severity(parse_cvss_score(x)))
            rows_count = len(df)
            vc = df["Severity"].value_counts(dropna=False)
            counts = {
                "Critical": int(vc.get("Critical", 0)),
                "High": int(vc.get("High", 0)),
                "Medium": int(vc.get("Medium", 0)),
                "Low": int(vc.get("Low", 0))
            }
        rows.append({
            group_header: g,
            "Rows": rows_count,
            "Critical": counts["Critical"],
            "High": counts["High"],
            "Medium": counts["Medium"],
            "Low": counts["Low"]
        })
    covered_df = pd.DataFrame(rows).sort_values(by=group_header).reset_index(drop=True)

    # write with pandas then post-process for borders & widths
    with pd.ExcelWriter(out_file, engine="openpyxl") as writer:
        print(f"Writing Covered Hosts sheet ({len(covered_df)} hosts)...")
        covered_df.to_excel(writer, sheet_name="Covered Hosts", index=False)

        # write each host sheet only if it has VULN rows
        for host, df in sorted(group_frames.items(), key=lambda x: x[0]):
            sheet_name = sanitize_sheet_name(host, fallback="host")
            existing = writer.sheets.keys()
            base_name = sheet_name
            suffix = 1
            while sheet_name in existing:
                sheet_name = (base_name[:28] + f"_{suffix}") if len(base_name) > 28 else f"{base_name}_{suffix}"
                suffix += 1
            print(f"  Writing sheet '{sheet_name}' ({len(df)} rows)")
            # ensure final columns exist
            for c in final_cols:
                # map group header name -> existing "GROUP_FIELD" column in df
                if c == group_header:
                    if "GROUP_FIELD" not in df.columns:
                        df["GROUP_FIELD"] = host
                else:
                    if c not in df.columns:
                        df[c] = pd.NA
            # build df with ordered columns and rename GROUP_FIELD -> actual header
            df_to_write = df.copy()
            df_to_write = df_to_write.rename(columns={"GROUP_FIELD": group_header})
            df_to_write = df_to_write[[c if c != group_header else group_header for c in final_cols]]
            df_to_write.to_excel(writer, sheet_name=sheet_name, index=False)

    # post-process workbook
    print("Applying borders and column widths...")
    wb = load_workbook(out_file)
    thin = Side(border_style="thin", color="000000")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    def apply_borders_and_widths_to_sheet(ws, col_widths_map):
        max_row = ws.max_row
        max_col = ws.max_column
        for r in range(1, max_row + 1):
            for c in range(1, max_col + 1):
                cell = ws.cell(row=r, column=c)
                cell.border = border

        # set widths by header string
        headers = {}
        for c in range(1, max_col + 1):
            headers[c] = ws.cell(row=1, column=c).value
        for col_idx, header in headers.items():
            letter = get_column_letter(col_idx)
            width = None
            if header is not None and str(header) in col_widths_map:
                width = col_widths_map[str(header)]
            elif header is not None and header.strip() in col_widths_map:
                width = col_widths_map[header.strip()]
            else:
                width = col_widths_map.get("__default__", 15)
            try:
                ws.column_dimensions[letter].width = float(width)
            except Exception:
                ws.column_dimensions[letter].width = 15.0

    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        apply_borders_and_widths_to_sheet(ws, col_widths)

    wb.save(out_file)
    print(f"Saved formatted workbook to: {out_file}")

def parse_widths_arg(widths_arg: str):
    if not widths_arg:
        return {}
    try:
        mapping = json.loads(widths_arg)
        if isinstance(mapping, dict):
            return mapping
    except Exception:
        pass
    p = Path(widths_arg)
    if p.exists():
        try:
            with p.open("r", encoding="utf-8") as fh:
                mapping = json.load(fh)
                if isinstance(mapping, dict):
                    return mapping
        except Exception:
            pass
    raise ValueError("Unable to parse --widths. Provide a JSON string mapping or a path to a JSON file.")

def main():
    p = argparse.ArgumentParser(description="Merge CSVs into one Excel workbook grouped by DNS or IP.")
    p.add_argument("--input", "-i", help="Input folder containing CSV files")
    p.add_argument("--output", "-o", help="Output Excel file (e.g. out.xlsx)")
    p.add_argument("--group-by", "-g", choices=["dns", "ip"], help="Group by 'dns' (FQDN) or 'ip'")
    p.add_argument("--widths", "-w", help="JSON mapping of column widths or path to JSON file")
    args = p.parse_args()

    if not args.input:
        folder = input("Enter path to folder containing CSV files (default: current dir): ").strip()
        input_folder = Path(folder) if folder else Path.cwd()
    else:
        input_folder = Path(args.input)

    if not args.output:
        default_out = Path.cwd() / "merged_grouped.xlsx"
        out = input(f"Enter output Excel filename (default: {default_out}): ").strip()
        output_file = Path(out) if out else default_out
    else:
        output_file = Path(args.output)

    mode = args.group_by
    if not mode:
        # interactive ask as requested
        resp = input("Group by DNS (FQDN) or IP? Enter 'dns' or 'ip' (default: dns): ").strip().lower()
        mode = resp if resp in ("dns", "ip") else "dns"

    if not input_folder.exists() or not input_folder.is_dir():
        print(f"Input folder not found or not a directory: {input_folder}")
        sys.exit(1)

    # DEFAULT column widths (override via --widths)
    DEFAULT_COL_WIDTHS = {
        # grouping header will be "DNS" or "IP" at runtime
        "DNS": 30,
        "IP": 18,
        "Title": 60,
        "Port": 8,
        "Protocol": 10,
        "CVE ID": 14,
        "Vendor Reference": 25,
        "CVSS3.1 Base": 14,
        "Severity": 12,
        "Threat": 20,
        "Impact": 20,
        "Solution Exploitability": 30,
        "Results": 30,
        "Rows": 8,
        "Critical": 8,
        "High": 8,
        "Medium": 8,
        "Low": 8,
        "__default__": 18
    }

    user_widths = {}
    if args.widths:
        try:
            user_widths = parse_widths_arg(args.widths)
        except Exception as e:
            print("ERROR parsing --widths:", e)
            sys.exit(1)

    merged_widths = DEFAULT_COL_WIDTHS.copy()
    for k, v in user_widths.items():
        merged_widths[str(k)] = v

    try:
        all_groups = collect_all_group_values(input_folder, mode)
        group_frames = process_folder(input_folder, mode)
        # ensure all detected groups included
        for k in group_frames.keys():
            if k not in all_groups:
                all_groups.append(k)
        all_groups = sorted(all_groups)
        if not all_groups:
            print("No host/group entries found across CSVs. Nothing to write.")
            sys.exit(0)
        write_to_excel(all_groups, group_frames, output_file, merged_widths, mode)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
