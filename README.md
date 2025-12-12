# Qualys CSV → Excel Workbook Converter

**Group by DNS (FQDN) or IP | Severity Parsing | Host Sheets | Covered Hosts Summary**

This tool converts **Qualys vulnerability scan CSV exports** into a clean, well-structured Excel workbook.
It is useful for penetration testers, security engineers, and compliance teams who want to reorganize Qualys results for reporting, analysis, or segmentation reviews.

---

## ✨ Key Features

### ✔ Built for **Qualys CSV exports**

* Supports standard Qualys result structure.
* Handles CSVs where the **header begins at row 8** (Qualys convention).
* Supports mixed output where some CSVs contain DNS values and others contain IP addresses.

### ✔ Group results by either:

* **DNS / FQDN**, or
* **IP address**

The script will:

* Ask you interactively (or accept `--group-by dns|ip`)
* Detect the correct column (`DNS`, `FQDN`, `Hostname`, `IP Address`, etc.)

### ✔ Generates a complete Excel workbook

* First sheet: **Covered Hosts**

  * Lists *all* hosts found in all CSVs
  * Includes hosts with **zero VULN findings**
  * Severity counts per host:

    * Critical
    * High
    * Medium
    * Low

* Subsequent sheets:

  * One sheet per host **only if the host has VULN-type findings**
  * Columns include:

    * Host (DNS or IP)
    * Title
    * Port
    * Protocol
    * CVE ID
    * Vendor Reference
    * CVSS3.1 Base
    * **Severity (computed automatically)**
    * Threat
    * Impact
    * Solution Exploitability
    * Results

### ✔ CVSS v3.1 parsing

Extracts the score from Qualys-style strings like:

```
6.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N)
```

Mapped automatically to:

* Critical (9.0–10.0)
* High (7.0–8.9)
* Medium (4.0–6.9)
* Low (0.1–3.9)
* None (0.0)

### ✔ Fully formatted Excel output

* Thin borders around all cells
* Configurable column widths (script includes sensible defaults)
* Host sheet names automatically sanitized for Excel limits
* No empty sheets created

---

## 📦 Requirements

```bash
python3
pip install pandas openpyxl
```

---

## 🚀 Usage

### **Interactive mode**

```bash
python csvs_to_excel_groupby.py
```

The script will ask:

* Input folder containing Qualys CSVs
* Output Excel filename
* Whether to group by **DNS** or **IP**

---

### **Automated mode**

Group by DNS:

```bash
python csvs_to_excel_groupby.py -i ./csvs -o qualys_output.xlsx --group-by dns
```

Group by IP:

```bash
python csvs_to_excel_groupby.py -i ./csvs -o qualys_output.xlsx --group-by ip
```

Override column widths:

```bash
python csvs_to_excel_groupby.py -i ./csvs -o output.xlsx \
  --widths '{"DNS":35,"Title":70,"Severity":12,"__default__":20}'
```

Pass a JSON file for widths:

```bash
python csvs_to_excel_groupby.py --widths widths.json
```

---

## 🔧 Expected Qualys CSV Format

This script is designed around Qualys CSV output conventions:

* **Header row begins at CSV row 8**
* `Type` column is used to filter where `Type = "VULN"`
* Common Qualys fields such as:

  * `DNS`, `IP`, `Title`, `Threat`, `Impact`,
  * `Solution Exploitability`, `Results`, etc.

If a required column is missing, the script creates a blank one for consistent formatting.

---

## 📂 Output Workbook Structure

```
Workbook.xlsx
├── Covered Hosts
│     DNS/IP | Rows | Critical | High | Medium | Low
│
├── host1.example.com
├── host2.example.com
├── 10.10.10.1
└── 10.10.10.2
```

Only hosts with **at least one VULN** finding get their own sheet.

---

## 🧠 Smart Host Detection

The script automatically recognizes host fields:

### DNS mode:

* `DNS`
* `FQDN`
* `Hostname`
* `Host Name`
* `Host`

### IP mode:

* `IP`
* `IP Address`
* `Host IP`
* `IPAddress`

Custom aliases can be added easily by editing the arrays at the top of the script.

---

## ⚙ Column Width Customization

Widths are fully editable via:

* JSON passed to `--widths`
* A JSON file
* Editing the `DEFAULT_COL_WIDTHS` dictionary inside the script

Special key: `__default__` controls width for any unassigned columns.

---

## 🤝 Contributing

Pull requests welcome!
Useful improvements include:

* Adding Excel table styles
* Adding graphical dashboards or charts
* Exporting summary CSVs
* Automated testing for multiple Qualys CSV variants

---

## 📜 License

MIT License – free to modify and use commercially.
