# NCIIPC PS-02 Submission Generator Guide

## Overview

The `generate_submission.py` script generates a complete submission package that matches the **exact format** specified in the NCIIPC PS-02 Problem Statement (Annexure B).

## Output Format

The script generates:

```
PS-02_<Application_ID>_Submission/
├── PS-02_<Application_ID>_Submission_Set.xlsx    (Excel with 20 required columns)
├── PS-02_<Application_ID>_Evidences/              (PDF screenshots)
│   ├── <CSE>_<subdomain>_1.pdf
│   ├── <CSE>_<subdomain>_2.pdf
│   └── ...
└── PS-02_<Application_ID>_Documentation_folder/  (Documentation)
    └── README.txt
```

## Excel Columns (Annexure B Compliance)

The Excel file contains exactly 20 columns as required:

1. Application_ID
2. Source of detection
3. Identified Phishing/Suspected Domain Name
4. Corresponding CSE Domain Name
5. Critical Sector Entity Name
6. Phishing/Suspected Domains (Class Label)
7. Domain Registration Date
8. Registrar Name
9. Registrant Name or Registrant Organisation
10. Registrant Country
11. Name Servers
12. Hosting IP
13. Hosting ISP
14. Hosting Country
15. DNS Records (if any)
16. Evidence file name
17. Date of detection (DD-MM-YYYY)
18. Time of detection (HH-MM-SS)
19. Date of Post (If detection is from Source: social media)
20. Remarks (If any)

## Installation

### Install Required Dependencies

```bash
cd /home/turtleneck/Desktop/PS02
source env/bin/activate
pip install reportlab openpyxl
```

## Usage

### Basic Usage

Generate submission with your Application ID:

```bash
cd /home/turtleneck/Desktop/PS02
source env/bin/activate
cd AIML
python generate_submission.py --application-id AIGR-123456
```

### Filter by Verdict Type

Generate submission with only PHISHING domains:

```bash
python generate_submission.py --application-id AIGR-123456 --filter-verdict PHISHING
```

Available filters:
- `PHISHING` - Only phishing domains
- `SUSPICIOUS` - Only suspicious/suspected domains
- `PARKED` - Only parked domains
- `INACTIVE` - Only inactive/unregistered domains
- `BENIGN` - Only benign domains (usually not needed for submission)

### Custom Output Directory

Specify where to generate the submission:

```bash
python generate_submission.py \
    --application-id AIGR-123456 \
    --output-dir /path/to/submission
```

### Use ChromaDB as Data Source

Connect to ChromaDB instead of using JSONL:

```bash
python generate_submission.py \
    --application-id AIGR-123456 \
    --source chromadb \
    --chromadb-host localhost \
    --chromadb-port 8000
```

### Custom Data Paths

Specify custom paths for data and verdicts:

```bash
python generate_submission.py \
    --application-id AIGR-123456 \
    --jsonl-path /path/to/dump_all.jsonl \
    --verdict-dir /path/to/Pipeline/out
```

## Complete Examples

### Example 1: Generate Full Submission (Exclude BENIGN)

```bash
cd /home/turtleneck/Desktop/PS02
source env/bin/activate
cd AIML

python generate_submission.py \
    --application-id AIGR-123456 \
    --output-dir ~/Desktop/submissions
```

This will:
- Load data from `dump_all.jsonl`
- Load verdicts from `Pipeline/out/`
- Exclude BENIGN domains (default behavior)
- Create submission in `~/Desktop/submissions/PS-02_AIGR-123456_Submission/`

### Example 2: PHISHING Only for Stage 1 Evaluation

```bash
python generate_submission.py \
    --application-id AIGR-123456 \
    --filter-verdict PHISHING \
    --output-dir /home/turtleneck/Desktop/PS02/submission_stage1
```

### Example 3: All Suspicious Domains

```bash
python generate_submission.py \
    --application-id AIGR-123456 \
    --filter-verdict SUSPICIOUS
```

## Output Details

### Excel File Structure

- **Headers**: Bold formatting
- **Column widths**: Auto-adjusted (max 50 characters)
- **Date format**: DD-MM-YYYY (e.g., 27-10-2025)
- **Time format**: HH-MM-SS (e.g., 11-41-33)
- **Missing data**: Represented as "N/A" or NaN

### Evidence PDF Files

- **Format**: PDF (converted from PNG screenshots)
- **Naming**: `<CSE>_<subdomain>_<index>.pdf`
  - Example: `SBI_sbi123.co.in_1.pdf`
  - Example: `HDFCBANK_hdfcbank.live_6.pdf`
- **Size**: Scaled to fit A4 page
- **Fallback**: Placeholder PDF if screenshot not found

### Documentation Folder

Contains:
- `README.txt` - Instructions for completing documentation
- *You must add*: `PS-02_<Application_ID>_Report.pdf`
- *You must add*: Source code, architecture diagrams, etc.

## Data Mapping

### CSE Domain Mapping

The script maps detected domains to CSE organizations using:

1. `cse_baseline_profile.json` (from training data)
2. Built-in mappings for common CSEs:
   - `onlinesbi.com` → State Bank of India
   - `icicibank.com` → ICICI Bank
   - `hdfcbank.com` → HDFC Bank
   - `airtel.com` → Bharti Airtel Limited
   - etc.

### Verdict Classification

Raw verdicts are mapped to submission categories:

- `PHISHING` / `MALICIOUS` → **PHISHING**
- `SUSPICIOUS` / `SUSPECTED` → **SUSPICIOUS**
- `BENIGN` / `LEGITIMATE` → **BENIGN**
- `PARKED` → **PARKED**
- `INACTIVE` / `UNREGISTERED` → **INACTIVE**

### Source of Detection

Tracks where the verdict came from:
- `aiml_service` - Main AIML detector
- `crawler` - Pipeline crawler verdict
- `aiml_fallback_metadata` - Metadata-based analysis
- `cse_whitelist` - CSE whitelist match

## Post-Generation Steps

After running the generator:

### 1. Review Excel File

```bash
libreoffice PS-02_AIGR-123456_Submission/PS-02_AIGR-123456_Submission_Set.xlsx
```

Check:
- Domain names are correct
- Verdicts are appropriate
- CSE mappings are accurate
- Dates/times are formatted correctly

### 2. Verify Evidence PDFs

```bash
ls -lh PS-02_AIGR-123456_Submission/PS-02_AIGR-123456_Evidences/
```

Spot-check a few PDFs:
```bash
evince PS-02_AIGR-123456_Submission/PS-02_AIGR-123456_Evidences/SBI_sbi123.co.in_1.pdf
```

### 3. Add Documentation

Create the required report:

```bash
cd PS-02_AIGR-123456_Submission/PS-02_AIGR-123456_Documentation_folder/

# Add your comprehensive report (Arial 12pt, justified)
cp /path/to/your/report.pdf PS-02_AIGR-123456_Report.pdf

# Add source code, diagrams, etc.
```

The report should include (per Annexure B):
- Participant details and skill sets
- Detailed problem statement
- Proposed approach and scope
- Architecture diagrams
- Implementation details (technologies, tools, datasets, features)
- Scalability of the solution
- Resources used for detection
- How to setup and run the solution
- Results
- Conclusion
- References

### 4. Create ZIP Archive

```bash
cd /home/turtleneck/Desktop/PS02

zip -r PS-02_AIGR-123456_Submission.zip PS-02_AIGR-123456_Submission/
```

Verify the ZIP:
```bash
unzip -l PS-02_AIGR-123456_Submission.zip | head -30
```

### 5. Submit to NCIIPC Portal

Upload `PS-02_AIGR-123456_Submission.zip` to the NCIIPC AI Grand Challenge portal by the deadline.

## Troubleshooting

### Issue: "No module named 'reportlab'"

Solution:
```bash
source env/bin/activate
pip install reportlab openpyxl
```

### Issue: "Screenshot not found"

The script will create placeholder PDFs. Check screenshot paths:
```bash
ls -lh Pipeline/out/screenshots/ | head
```

If screenshots are in a different location, they might have different paths in metadata.

### Issue: "No data loaded"

Check that `dump_all.jsonl` exists:
```bash
ls -lh dump_all.jsonl
```

Or specify custom path:
```bash
python generate_submission.py \
    --application-id AIGR-123456 \
    --jsonl-path /path/to/your/data.jsonl
```

### Issue: "No CSE mapping"

The script will use domain name as organization name. To add custom mappings:

1. Edit `data/training/cse_baseline_profile.json`
2. Add `"cse_organizations"` section:

```json
{
  "domains": ["onlinesbi.com", "icicibank.com"],
  "cse_organizations": {
    "onlinesbi.com": "State Bank of India",
    "icicibank.com": "ICICI Bank Limited"
  }
}
```

### Issue: "Permission denied"

Ensure output directory is writable:
```bash
chmod +w /path/to/output/directory
```

## Statistics Example

After generation, you'll see output like:

```
======================================================================
SUBMISSION PACKAGE GENERATED SUCCESSFULLY
======================================================================
Location: /home/turtleneck/Desktop/PS02/PS-02_AIGR-123456_Submission
Total domains: 47
Excel file: PS-02_AIGR-123456_Submission_Set.xlsx
Evidence files: 42 PDFs

Next steps:
1. Add PS-02_<Application_ID>_Report.pdf to Documentation folder
2. Review Excel file for accuracy
3. Verify evidence PDFs are readable
4. Zip the folder: PS-02_AIGR-123456_Submission.zip
5. Submit on NCIIPC portal
======================================================================
```

## Command Line Help

For full help:
```bash
python generate_submission.py --help
```

## Integration with Pipeline

You can run this generator as the final step in your pipeline:

```bash
# After AIML detection completes
cd /home/turtleneck/Desktop/PS02
source env/bin/activate
cd AIML

python generate_submission.py \
    --application-id AIGR-123456 \
    --filter-verdict PHISHING \
    --output-dir ../submission_output
```

Or add to your automation scripts.

## Notes

- **Default behavior**: Excludes BENIGN domains (only suspicious/phishing/parked for submission)
- **NaN values**: Missing data shown as "N/A" in Excel
- **Timestamps**: Automatically converted from ISO format to DD-MM-YYYY HH-MM-SS
- **Evidence naming**: Follows Annexure B specification exactly
- **Folder structure**: Matches Annexure B requirements exactly

## Support

For issues or questions:
1. Check this guide
2. Review problem statement (Annexure B)
3. Check script logs for detailed error messages
4. Verify all dependencies are installed

## Version

Generated for NCIIPC AI Grand Challenge 2025 - Problem Statement 02
Script version: 1.0
Date: October 2025
