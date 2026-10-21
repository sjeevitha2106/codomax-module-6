# Security Architecture

## 1. Project Overview

The Cybersecurity Log Analyzer is a defensive security application that processes authorized authentication logs and highlights patterns requiring investigation.

## 2. Architecture

CSV Log File
    |
    v
Input Validation
    |
    v
Log Normalization
    |
    v
Detection Rules
    |
    v
Severity Classification
    |
    v
Streamlit Dashboard
    |
    v
CSV Report Export

## 3. Components

### Input Layer
Accepts CSV files containing timestamps, source IP addresses, usernames, event types, status, and details.

### Validation Layer
Checks required columns, parses timestamps, validates IP addresses, and excludes malformed records.

### Analysis Layer
Counts failed logins per IP address and flags patterns matching the configured threshold.

### Presentation Layer
Displays event statistics, charts, alerts, and filterable tables.

### Reporting Layer
Exports the analysis results to a downloadable CSV file.

## 4. Security Controls

- Input validation and error handling
- Use of synthetic training logs
- No active scanning or exploitation
- No password collection
- Warning against uploading sensitive data to public hosting
- Human review of alerts before conclusions are drawn

## 5. Limitations

The application uses basic detection rules and is not a replacement for an enterprise SIEM. It does not independently establish malicious intent, perform live monitoring, or guarantee detection of all attacks.

## 6. Future Improvements

- Time-window-based detection
- Configurable detection rules
- Additional event types
- Authentication and access controls
- Automated tests
- Secure storage and audit logging
-