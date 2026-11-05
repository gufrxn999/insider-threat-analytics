from io import StringIO
import unittest

import pandas as pd

from insider_threat.analytics import analyze_events, read_events


def event_rows(days: int) -> pd.DataFrame:
    rows = []
    start = pd.Timestamp("2025-01-01T12:00:00Z")
    for offset in range(days):
        rows.append({
            "timestamp": start + pd.Timedelta(days=offset),
            "user_id": "employee-01",
            "event_type": "file_access",
            "resource": "project/docs",
            "bytes_transferred": 100,
            "device_id": "device-01",
            "department": "Engineering",
        })
    return pd.DataFrame(rows)


class ReadEventsTests(unittest.TestCase):
    def test_normalizes_columns_and_drops_invalid_rows(self) -> None:
        source = StringIO(
            " Timestamp , USER_ID , event_type,resource,bytes_transferred,device_id,department\n"
            "2025-01-01T12:00:00Z, employee-01 , FILE_ACCESS,docs,4,d1,Engineering\n"
            "not-a-date,employee-02,file_access,docs,4,d2,Sales\n"
        )
        events = read_events(source)
        self.assertEqual(len(events), 1)
        self.assertEqual(events.loc[0, "user_id"], "employee-01")
        self.assertEqual(events.loc[0, "event_type"], "file_access")

    def test_missing_required_columns_raise_clear_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "CSV is missing required columns"):
            read_events(StringIO("timestamp,user_id\n2025-01-01,employee-01\n"))


class ScoringTests(unittest.TestCase):
    def test_requires_seven_prior_active_days(self) -> None:
        scored = analyze_events(event_rows(3))
        self.assertEqual(set(scored["risk_level"]), {"Insufficient history"})
        self.assertTrue(scored["reasons"].str[0].str.contains("needs 7 prior active days").all())

    def test_direct_signals_are_explained_after_baseline_is_ready(self) -> None:
        events = event_rows(8)
        events.loc[7, "event_type"] = "usb_copy"
        scored = analyze_events(events)
        anomaly = scored.iloc[-1]
        self.assertEqual(anomaly["baseline_days"], 7)
        self.assertIn("Removable media use", anomaly["reasons"])
        self.assertEqual(anomaly["risk_score"], 30)
        self.assertEqual(anomaly["risk_level"], "Moderate")


if __name__ == "__main__":
    unittest.main()
