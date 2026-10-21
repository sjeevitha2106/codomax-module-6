# Testing Report — Cybersecurity Log Analyzer

## 1. Objective

Verify that the application accepts valid logs, identifies configured suspicious patterns, displays analysis results, and exports reports.

## 2. Test Environment

- Python
- Streamlit
- Pandas
- Plotly
- Synthetic CSV authentication logs

## 3. Test Cases

| ID | Test | Expected Result |
|---|---|---|
| TC-01 | Load included sample logs | Valid events appear |
| TC-02 | Upload a valid CSV | Events are analyzed |
| TC-03 | Upload a file missing required columns | A validation error appears |
| TC-04 | Include an invalid IP address | The invalid record is excluded |
| TC-05 | Include repeated failed logins from one IP | Matching events are flagged |
| TC-06 | Change the failure threshold | Flagged results update |
| TC-07 | Filter by severity | Only selected severities appear |
| TC-08 | Download the analysis report | A CSV file is downloaded |
| TC-09 | Upload an empty or malformed file | The application handles the error |
| TC-10 | Review successful logins | Normal events are displayed |

## 4. Results

Complete this section after executing the tests.

Record each test as PASS or FAIL and include the observed behavior.

## 5. Limitations

The tests use synthetic data. They do not demonstrate detection accuracy against real-world attacks or replace professional security testing.

## 6. Conclusion

The application should be considered ready for demonstration only after the required tests have been executed and any identified defects have been addressed.