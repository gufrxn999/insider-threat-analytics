from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from insider_threat.analytics import analyze_events, read_events  # noqa: E402
from insider_threat.demo_data import generate_demo  # noqa: E402

DEMO_FILE = ROOT / "data" / "demo_events.csv"
MAX_UPLOAD_MB = 25

st.set_page_config(page_title="Insider Behavior Triage", page_icon="🛡️", layout="wide")
st.title("Insider Behavior Triage")
st.caption("Privacy-first research prototype · Synthetic audit events · Explainable risk signals")
st.info(
    "This demo uses synthetic data. Risk scores flag unusual activity for human review; "
    "they are not evidence of misconduct and must not drive automated employment decisions."
)

uploaded = st.file_uploader("Upload an audit-event CSV", type=["csv"], help=f"Maximum file size: {MAX_UPLOAD_MB} MB")
if uploaded is not None and uploaded.size > MAX_UPLOAD_MB * 1024 * 1024:
    st.error(f"File exceeds the {MAX_UPLOAD_MB} MB upload limit.")
    st.stop()

if uploaded is None and not DEMO_FILE.exists():
    generate_demo(DEMO_FILE)

try:
    events = read_events(uploaded if uploaded is not None else str(DEMO_FILE))
    daily = analyze_events(events)
except Exception as exc:
    st.error(str(exc))
    st.stop()

if uploaded is None:
    st.caption("Showing the bundled synthetic demo. Upload a compatible CSV to explore your own data locally.")

high = int(daily["risk_level"].eq("High").sum())
moderate = int(daily["risk_level"].eq("Moderate").sum())
ready = int(daily["risk_level"].ne("Insufficient history").sum())
c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{len(events):,}")
c2.metric("Users", f"{events['user_id'].nunique():,}")
c3.metric("High-risk user-days", f"{high:,}")
c4.metric("Moderate-risk user-days", f"{moderate:,}")
st.caption(f"{ready:,} user-days have enough personal history to score. A missing baseline is not a low-risk result.")

st.subheader("Risk trend")
trend = daily[daily["risk_level"].ne("Insufficient history")].groupby("activity_date")["risk_score"].mean()
if trend.empty:
    st.warning("Not enough activity history to establish baselines yet.")
else:
    st.line_chart(trend)

st.subheader("User-day triage queue")
queue = daily.sort_values(["risk_score", "activity_date"], ascending=[False, False]).copy()
queue["activity_date"] = queue["activity_date"].dt.strftime("%Y-%m-%d")
queue["reasons"] = queue["reasons"].apply(lambda value: ", ".join(value) if value else "No unusual signals")
st.dataframe(
    queue[["activity_date", "user_id", "department", "risk_level", "risk_score", "events_total", "reasons"]],
    use_container_width=True,
    hide_index=True,
)

st.subheader("Review a user-day")
eligible = daily[daily["risk_level"].ne("Insufficient history")]
if not eligible.empty:
    selected_user = st.selectbox("User", sorted(eligible["user_id"].unique()))
    user_days = eligible[eligible["user_id"].eq(selected_user)].sort_values("activity_date", ascending=False)
    selected_date = st.selectbox("Date", user_days["activity_date"].dt.strftime("%Y-%m-%d").tolist())
    selected = user_days[user_days["activity_date"].dt.strftime("%Y-%m-%d").eq(selected_date)].iloc[0]
    st.write(f"**{selected['risk_level']} risk · score {selected['risk_score']}/100**")
    if selected["reasons"]:
        for reason in selected["reasons"]:
            st.write(f"- {reason}")
    else:
        st.write("No configured signals crossed their thresholds for this user-day.")
    st.bar_chart(pd.Series({feature.replace("_", " ").title(): selected[feature] for feature in [
        "after_hours_events", "external_email_events", "usb_copy_events",
        "privilege_change_events", "bytes_transferred", "distinct_devices",
        "sensitive_access_events",
    ]}))

with st.expander("Expected CSV schema"):
    st.code("timestamp,user_id,event_type,resource,bytes_transferred,device_id,department\n2025-01-01T22:14:00Z,employee-01,file_access,restricted/payroll,1024,device-01,Finance")
    st.write("`timestamp`, `user_id`, `event_type`, `resource`, `bytes_transferred`, `device_id`, and `department` are required. The app processes uploads in memory and does not save them.")

st.caption("Prototype only. Tune thresholds with domain experts, validate on representative historical data, and keep a human review process.")
