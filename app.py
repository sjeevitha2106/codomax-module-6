from io import BytesIO
import ipaddress

import pandas as pd
import plotly.express as px
import streamlit as st


st.set_page_config(
    page_title="Cybersecurity Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "status",
    "details",
]


def load_sample_data():
    try:
        return pd.read_csv("sample_logs.csv")
    except FileNotFoundError:
        return pd.DataFrame(columns=REQUIRED_COLUMNS)


def normalize_logs(data):
    data = data.copy()
    data.columns = [str(col).strip().lower() for col in data.columns]

    missing = [col for col in REQUIRED_COLUMNS if col not in data.columns]
    if missing:
        raise ValueError(
            "Missing required columns: " + ", ".join(missing)
        )

    data = data[REQUIRED_COLUMNS].copy()

    for col in ["source_ip", "username", "event_type", "status", "details"]:
        data[col] = data[col].fillna("").astype(str).str.strip()

    data["timestamp"] = pd.to_datetime(
        data["timestamp"], errors="coerce"
    )

    data["status"] = data["status"].str.lower()
    data["event_type"] = data["event_type"].str.lower()

    data = data.dropna(subset=["timestamp"])
    data = data[
        data["source_ip"].ne("")
        & data["username"].ne("")
        & data["event_type"].ne("")
        & data["status"].isin(["success", "failed"])
    ].copy()

    # Validate IP addresses; invalid values are excluded.
    def valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    data = data[data["source_ip"].apply(valid_ip)].copy()
    return data.sort_values("timestamp")


def analyze_logs(data, threshold):
    data = data.copy()

    failed = data[
        (data["event_type"] == "login")
        & (data["status"] == "failed")
    ]

    # Count failed login events per source IP.
    failures_by_ip = failed.groupby("source_ip").size()
    flagged_ips = failures_by_ip[
        failures_by_ip >= threshold
    ].index.tolist()

    data["severity"] = "Informational"
    data["alert"] = "No rule triggered"

    failed_mask = (
        (data["event_type"] == "login")
        & (data["status"] == "failed")
    )
    data.loc[failed_mask, "severity"] = "Low"
    data.loc[failed_mask, "alert"] = "Failed login"

    repeated_mask = (
        failed_mask & data["source_ip"].isin(flagged_ips)
    )
    data.loc[repeated_mask, "severity"] = "High"
    data.loc[repeated_mask, "alert"] = "Repeated failed logins"

    # Flag successful logins from IPs with earlier failed attempts.
    for ip in flagged_ips:
        ip_events = data[data["source_ip"] == ip].sort_values("timestamp")
        failed_times = ip_events.loc[
            (ip_events["event_type"] == "login")
            & (ip_events["status"] == "failed"),
            "timestamp",
        ]

        if failed_times.empty:
            continue

        first_failure = failed_times.min()
        success_after = (
            (data["source_ip"] == ip)
            & (data["event_type"] == "login")
            & (data["status"] == "success")
            & (data["timestamp"] > first_failure)
        )

        data.loc[success_after, "severity"] = "High"
        data.loc[success_after, "alert"] = (
            "Success after repeated failures"
        )

    return data


st.title("🛡️ Cybersecurity Log Analyzer")
st.caption(
    "A defensive security project for analyzing authentication logs "
    "and identifying patterns that warrant investigation."
)

with st.sidebar:
    st.header("Analysis settings")
    threshold = st.slider(
        "Failed logins to flag per IP",
        min_value=2,
        max_value=10,
        value=3,
    )
    st.info(
        "This project uses simple detection rules. "
        "An alert is not proof of malicious activity."
    )

uploaded_file = st.file_uploader(
    "Upload a CSV security log",
    type=["csv"],
    help="Required columns: " + ", ".join(REQUIRED_COLUMNS),
)

if uploaded_file is not None:
    try:
        raw_data = pd.read_csv(uploaded_file)
    except Exception:
        st.error("The uploaded file could not be read as a CSV.")
        st.stop()
else:
    raw_data = load_sample_data()
    st.info("Showing included sample logs. Upload a CSV to analyze your own authorized data.")

try:
    logs = normalize_logs(raw_data)
except ValueError as error:
    st.error(str(error))
    st.stop()
except Exception:
    st.error("Unable to process the log file. Check its format.")
    st.stop()

if logs.empty:
    st.warning("No valid events were found in the file.")
    st.stop()

results = analyze_logs(logs, threshold)

total_events = len(results)
failed_count = int(
    (
        (results["event_type"] == "login")
        & (results["status"] == "failed")
    ).sum()
)
high_count = int((results["severity"] == "High").sum())
flagged_ips_count = int(
    results.loc[
        results["alert"].isin(
            ["Repeated failed logins", "Success after repeated failures"]
        ),
        "source_ip",
    ].nunique()
)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Valid events", total_events)
c2.metric("Failed logins", failed_count)
c3.metric("High-severity events", high_count)
c4.metric("IPs flagged", flagged_ips_count)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Events by severity")
    severity_counts = (
        results["severity"]
        .value_counts()
        .rename_axis("Severity")
        .reset_index(name="Count")
    )
    fig = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        color="Severity",
        title="Severity distribution",
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Login outcomes")
    outcomes = (
        results[results["event_type"] == "login"]["status"]
        .value_counts()
        .rename_axis("Outcome")
        .reset_index(name="Count")
    )
    if not outcomes.empty:
        fig2 = px.pie(
            outcomes,
            names="Outcome",
            values="Count",
            title="Successful vs failed logins",
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.write("No login events found.")

st.subheader("Security alerts")
alerts = results[results["severity"] == "High"].copy()

if alerts.empty:
    st.success("No high-severity events triggered by the current rules.")
else:
    st.warning(
        f"{len(alerts)} event(s) triggered high-severity rules. "
        "Review the context before drawing conclusions."
    )
    st.dataframe(
        alerts[
            [
                "timestamp",
                "source_ip",
                "username",
                "event_type",
                "status",
                "severity",
                "alert",
                "details",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

st.subheader("Filter events")

available_severities = results["severity"].unique().tolist()
selected_severities = st.multiselect(
    "Severity",
    options=available_severities,
    default=available_severities,
)

filtered = results[
    results["severity"].isin(selected_severities)
].copy()

st.dataframe(
    filtered,
    use_container_width=True,
    hide_index=True,
)

csv_bytes = results.to_csv(index=False).encode("utf-8")
st.download_button(
    label="Download full analysis report (CSV)",
    data=csv_bytes,
    file_name="security_analysis_report.csv",
    mime="text/csv",
)

st.caption(
    "Educational prototype. Detection rules are heuristic and may "
    "produce false positives or miss threats. Do not upload sensitive "
    "logs to a public deployment."
)