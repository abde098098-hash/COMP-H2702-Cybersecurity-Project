
# Security Log Investigation

## Project Overview

This project is a Python-based Security Log Investigation tool developed for COMP H2702 – Scripting for Cybersecurity.

The program analyses firewall and authentication logs to identify suspicious activity, repeated failed login attempts and blocked network traffic.

## Features

- Analyses firewall log events.
- Counts allowed and blocked connections.
- Identifies the most frequently blocked IP addresses.
- Identifies commonly targeted network ports.
- Analyses successful and failed login attempts.
- Identifies frequently targeted usernames.
- Detects account lock events.
- Compares suspicious IP addresses against both log files.
- Handles malformed log entries without crashing.
- Generates TXT and JSON investigation reports.

## Files

- `main.py` – Main Python investigation program.
- `firewall.log` – Firewall event dataset.
- `authentication.log` – Authentication event dataset.
- `suspicious_ips.txt` – IP addresses used for investigation.
- `investigation_report.txt` – Generated investigation report.
- `investigation_report.json` – Generated JSON results.

## Requirements

- Python 3
- No external Python libraries required.

## How to Run

1. Download or clone this repository.
2. Open the project folder.
3. Make sure the three dataset files are in the same folder as `main.py`.
4. Run the program using Python:

```bash
python main.py
```

5. The program analyses the logs and generates two report files.

## Error Handling

The program checks log entries for missing fields, invalid values and malformed data. Invalid entries are skipped and counted instead of stopping the investigation.

It also handles missing input files and file access errors.

## Security Notes

The dataset contains synthetic teaching data. The IP addresses are examples for investigation only and must not be contacted or scanned.

## Author

COMP H2702 – Scripting for Cybersecurity Project
