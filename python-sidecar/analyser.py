import os
import math
import logging
import schedule
import time
from collections import defaultdict
from datetime import datetime, timezone
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
import requests
import numpy as np
from sklearn.ensemble import IsolationForest
from models.anomaly import AnomalyAlert

load_dotenv("../.env")
load_dotenv(".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("tunnelforge-analyser")

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
}

GATEWAY_URL = "http://gateway:8443/internal/anomaly"
ANALYSIS_WINDOW = 300
MIN_EVENTS = 3


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def fetch_audit_window(conn) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT username, action, resource, client_ip, status, occurred_at
            FROM audit_log
            WHERE occurred_at >= NOW() - INTERVAL '%s seconds'
            ORDER BY occurred_at ASC
            """,
            (ANALYSIS_WINDOW,)
        )
        return [dict(r) for r in cur.fetchall()]


def ua_entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    unique = set(values)
    total = len(values)
    return -sum((values.count(u) / total) * math.log2(values.count(u) / total) for u in unique)


def build_features(events: list[dict]) -> dict[str, list]:
    user_events = defaultdict(list)
    for e in events:
        if e["username"]:
            user_events[e["username"]].append(e)

    features = {}
    for username, evts in user_events.items():
        if len(evts) < MIN_EVENTS:
            continue
        total = len(evts)
        failures = sum(1 for e in evts if e["status"] == "FAILURE")
        denials = sum(1 for e in evts if e["status"] == "DENIED")
        logins = sum(1 for e in evts if e["action"] == "LOGIN")
        resources = {e["resource"] for e in evts if e["resource"]}
        ips = {e["client_ip"] for e in evts if e["client_ip"]}
        hour = evts[-1]["occurred_at"].hour if isinstance(evts[-1]["occurred_at"], datetime) else datetime.fromisoformat(str(evts[-1]["occurred_at"])).hour

        features[username] = [
            total / ANALYSIS_WINDOW,
            failures / total,
            denials / total,
            len(resources) / total,
            len(ips),
            logins / total,
            hour,
        ]
    return features


def notify_gateway(alert: AnomalyAlert):
    try:
        requests.post(
            GATEWAY_URL,
            json={"anomaly_type": alert.anomaly_type, "severity": alert.severity},
            timeout=2,
        )
    except Exception:
        pass


def write_alert(conn, alert: AnomalyAlert):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO audit_log (username, action, client_ip, status, detail)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (alert.username, "ANOMALY_DETECTED", "sidecar", alert.severity, alert.detail)
        )
        conn.commit()


def run_analysis():
    log.info("Running session analysis cycle")
    try:
        conn = get_connection()
        events = fetch_audit_window(conn)

        if not events:
            log.info("No audit log entries in analysis window")
            conn.close()
            return

        log.info(f"Analysing {len(events)} audit events across {ANALYSIS_WINDOW}s window")

        feature_map = build_features(events)
        if len(feature_map) < 2:
            log.info("Insufficient users for anomaly detection")
            conn.close()
            return

        usernames = list(feature_map.keys())
        X = np.array([feature_map[u] for u in usernames])

        clf = IsolationForest(contamination=0.1, random_state=42)
        preds = clf.fit_predict(X)

        alerts = []
        for i, username in enumerate(usernames):
            if preds[i] == -1:
                feats = feature_map[username]
                failure_rate = feats[1]
                severity = "CRITICAL" if failure_rate > 0.5 else "HIGH"
                anomaly_type = "CREDENTIAL_STUFFING" if failure_rate > 0.5 else "SESSION_ANOMALY"
                alert = AnomalyAlert(
                    anomaly_type=anomaly_type,
                    severity=severity,
                    username=username,
                    detail=f"Isolation Forest anomaly: event_rate={feats[0]:.3f} failure_rate={feats[1]:.3f} denial_rate={feats[2]:.3f}",
                    evidence={
                        "event_rate": feats[0],
                        "failure_rate": feats[1],
                        "denial_rate": feats[2],
                        "resource_diversity": feats[3],
                        "distinct_ips": feats[4],
                        "login_rate": feats[5],
                        "hour": feats[6],
                    }
                )
                alerts.append(alert)

        if not alerts:
            log.info("No anomalies detected")
        else:
            for alert in alerts:
                log.warning(f"ANOMALY [{alert.severity}] {alert.anomaly_type} — user: {alert.username}")
                write_alert(conn, alert)
                notify_gateway(alert)

        conn.close()

    except Exception as e:
        log.error(f"Analysis cycle failed: {e}")


def main():
    log.info("TunnelForge session analyser starting")
    log.info(f"Window: {ANALYSIS_WINDOW}s | Interval: 60s | Min events: {MIN_EVENTS}")
    run_analysis()
    schedule.every(60).seconds.do(run_analysis)
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()