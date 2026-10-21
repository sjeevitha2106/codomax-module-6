# Cybersecurity Log Analyzer

A Python-based defensive security dashboard that analyzes authentication logs, identifies repeated failed login attempts, highlights events for investigation, and exports analysis results.

## Features

- CSV log upload and validation
- Authentication event analysis
- Configurable repeated-failure threshold
- Severity classification
- Interactive Plotly charts
- Event filtering
- CSV report download
- Sample logs for demonstration

## Technology Stack

- Python
- Streamlit
- Pandas
- Plotly

## Project Structure

    Cybersecurity-Log-Analyzer/
    ├── app.py
    ├── sample_logs.csv
    ├── requirements.txt
    ├── README.md
    ├── security_architecture.md
    ├── testing_report.md
    └── .gitignore

## Run Locally

1. Install Python 3.
2. Open a terminal in the project directory.
3. Create a virtual environment:

       python -m venv .venv

4. Activate it on Windows:

       .venv\Scripts\activate

5. Install dependencies:

       python -m pip install -r requirements.txt

6. Start the dashboard:

       python -m streamlit run app.py

7. Open the local URL displayed in the terminal.

## CSV Format

The input file must contain:

- timestamp
- source_ip
- username
- event_type
- status
- details

For this prototype, login status values should be `success` or `failed`.

## Detection Logic

The application flags failed login events when the number of failures from the same IP reaches the configured threshold. It also flags subsequent successful logins from those IPs for further review.

These are heuristic rules, not proof of compromise.

## Security and Privacy

Use only logs you are authorized to analyze. The included records are synthetic training data. Avoid uploading confidential or personally identifiable information to a public hosting service.

## Limitations

- The prototype analyzes individual CSV records rather than live network traffic.
- Detection is based on simple rules.
- It does not replace an enterprise SIEM or professional incident investigation.
- Results require human review and may contain false positives.

## Author

Add your name and internship details here.