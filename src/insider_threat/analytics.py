from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = {
    "timestamp",
    "user_id",
    "event_type",
    "resource",
    "bytes_transferred",
    "device_id",
    "department",
}

BEHAVIOR_FEATURES = [
    "after_hours_events",
    "external_email_events",
    "usb_copy_events",
    "privilege_change_events",
    "bytes_transferred",
    "distinct_devices",
    "sensitive_access_events",
]


@dataclass(frozen=True)
class Signal:
    feature: str
    label: str
    weight: int
    floor: float
    multiplier: float
    direct_when_positive: bool = False


SIGNALS = [
    Signal("usb_copy_events", "Removable media use", 30, 0, 3, True),
    Signal("privilege_change_events", "Privilege change", 25, 0, 3, True),
    Signal("bytes_transferred", "Unusual data movement", 20, 1_000_000, 4),
    Signal("external_email_events", "Unusual external email", 15, 3, 3),
    Signal("after_hours_events", "Unusual after-hours activity", 10, 3, 3),
    Signal("distinct_devices", "Unusual device activity", 10, 1, 3),
    Signal("sensitive_access_events", "Unusual sensitive-file access", 10, 5, 3),
]


def read_events(source: str | BinaryIO) -> pd.DataFrame:
    """Load and validate a CSV of audit events without retaining raw uploads."""
    events = pd.read_csv(source, low_memory=False)
    events.columns = events.columns.str.strip().str.lower()
    missing = sorted(REQUIRED_COLUMNS - set(events.columns))
    if missing:
        raise ValueError("CSV is missing required columns: " + ", ".join(missing))

    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce", utc=True)
    events["user_id"] = events["user_id"].astype("string").str.strip()
    events["event_type"] = events["event_type"].astype("string").str.strip().str.lower()
    events["resource"] = events["resource"].astype("string").fillna("").str.strip()
    events["device_id"] = events["device_id"].astype("string").fillna("").str.strip()
    events["department"] = events["department"].astype("string").fillna("Unknown").str.strip()
    events["bytes_transferred"] = pd.to_numeric(events["bytes_transferred"], errors="coerce")

    valid = (
        events["timestamp"].notna()
        & events["user_id"].notna()
        & events["user_id"].ne("")
        & events["event_type"].notna()
        & events["bytes_transferred"].notna()
        & events["bytes_transferred"].ge(0)
    )
    events = events.loc[valid].copy()
    if events.empty:
        raise ValueError("No valid audit events remain after checking timestamps, users, and byte counts.")
    events["bytes_transferred"] = events["bytes_transferred"].astype("int64")
    return events.sort_values("timestamp").reset_index(drop=True)


def daily_activity(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate raw events to per-user daily behavior features."""
    rows = events.copy()
    rows["activity_date"] = rows["timestamp"].dt.floor("D")
    local_hour = rows["timestamp"].dt.hour
    rows["is_after_hours"] = (local_hour < 7) | (local_hour >= 20)
    rows["is_sensitive"] = rows["resource"].str.contains(
        r"confidential|restricted|payroll|customer[-_ ]?data|source[-_ ]?code",
        case=False,
        regex=True,
        na=False,
    )

    grouped = rows.groupby(["user_id", "activity_date"], sort=True)
    daily = grouped.agg(
        department=("department", "last"),
        events_total=("event_type", "size"),
        after_hours_events=("is_after_hours", "sum"),
        external_email_events=("event_type", lambda s: s.eq("external_email").sum()),
        usb_copy_events=("event_type", lambda s: s.eq("usb_copy").sum()),
        privilege_change_events=("event_type", lambda s: s.eq("privilege_change").sum()),
        bytes_transferred=("bytes_transferred", "sum"),
        distinct_devices=("device_id", lambda s: s.replace("", pd.NA).nunique()),
        sensitive_access_events=("is_sensitive", "sum"),
    ).reset_index()
    return daily.sort_values(["user_id", "activity_date"]).reset_index(drop=True)


def _upper_limit(history: pd.Series, signal: Signal) -> float:
    values = pd.to_numeric(history, errors="coerce").dropna()
    if values.empty:
        return float("inf")
    median = float(values.median())
    mad = float((values - median).abs().median())
    robust_scale = max(1.4826 * mad, median * 0.25, signal.floor, 1.0)
    return median + signal.multiplier * robust_scale


def score_activity(daily: pd.DataFrame, min_history_days: int = 7, lookback_days: int = 28) -> pd.DataFrame:
    """Score each user-day against only their preceding activity days.

    A score is a triage aid. A missing baseline is marked explicitly and must
    not be interpreted as a low-risk determination.
    """
    if daily.empty:
        return daily.assign(risk_score=pd.Series(dtype="int64"), risk_level=pd.Series(dtype="string"), reasons=pd.Series(dtype="object"), baseline_days=pd.Series(dtype="int64"))

    ordered = daily.sort_values(["user_id", "activity_date"]).reset_index(drop=True)
    result = []
    for row in ordered.to_dict("records"):
        day = row["activity_date"]
        start = day - pd.Timedelta(days=lookback_days)
        history = ordered[
            (ordered["user_id"] == row["user_id"])
            & (ordered["activity_date"] < day)
            & (ordered["activity_date"] >= start)
        ]

        score = 0
        reasons = []
        for signal in SIGNALS:
            value = float(row[signal.feature])
            if signal.direct_when_positive and value > 0:
                reasons.append(signal.label)
                score += signal.weight
                continue
            if len(history) < min_history_days:
                continue
            limit = _upper_limit(history[signal.feature], signal)
            if value > limit:
                reasons.append(signal.label)
                score += signal.weight

        baseline_ready = len(history) >= min_history_days
        if not baseline_ready:
            level = "Insufficient history"
            reasons = [f"Baseline needs {min_history_days} prior active days; currently {len(history)}."]
            score = 0
        elif score >= 60:
            level = "High"
        elif score >= 30:
            level = "Moderate"
        else:
            level = "Low"

        row.update(
            risk_score=min(score, 100),
            risk_level=level,
            reasons=reasons,
            baseline_days=len(history),
        )
        result.append(row)
    return pd.DataFrame(result)


def analyze_events(events: pd.DataFrame) -> pd.DataFrame:
    return score_activity(daily_activity(events))
