"""Synthetic SOC alert generator. Local only, seeded, no network.

Vocabulary follows real schemas (STIX 2.1 field names like ``confidence``,
``pattern``-style technique refs, MISP-style ``category``/``value`` pairs,
MITRE ATT&CK technique IDs, CVE/CVSS rating bands) but every value is
synthesised locally from a seeded PRNG. Nothing here leaves the process.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pandas as pd

SEED_DEFAULT = 20261002

SEVERITIES = ("Low", "Medium", "High", "Critical")
SEV_WEIGHTS = (35, 30, 22, 13)
SEV_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEV_ICON = {
    "Critical": ":material/error:",
    "High": ":material/priority_high:",
    "Medium": ":material/warning:",
    "Low": ":material/info:",
}
CVSS_BY_SEV = {
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}
MTTR_MIN = {
    "Critical": (15, 45),
    "High": (45, 240),
    "Medium": (240, 1440),
    "Low": (1440, 4320),
}

# (technique_id, technique_name, tactic, attack_type, ports, cve_share)
TECHNIQUES = (
    ("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance", "Разведка", (80, 443, 53), 0.35),
    ("T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance", "Разведка", (80, 443, 53), 0.0),
    ("T1566.002", "Phishing: Spearphishing Link", "Initial Access", "Фишинг", (443,), 0.0),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "Эксплойт", (80, 443, 8080), 0.9),
    ("T1110.001", "Brute Force: Password Guessing", "Credential Access", "Брутфорс", (22, 3389), 0.0),
    ("T1078", "Valid Accounts", "Persistence", "Брутфорс", (22, 3389, 445), 0.0),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "C2", (443, 80), 0.0),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement", "Латеральное движение", (3389,), 0.1),
    ("T1021.004", "Remote Services: SSH", "Lateral Movement", "Латеральное движение", (22,), 0.1),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Эксфильтрация", (443, 53), 0.0),
    ("T1498", "Network Denial of Service", "Impact", "DDoS", (80, 443), 0.0),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "Эксплойт", (445,), 0.4),
)
TECH_W = (12, 10, 12, 10, 12, 6, 10, 6, 5, 6, 6, 5)

COUNTRIES = (
    ("DE", "EU"), ("NL", "EU"), ("PL", "EU"),
    ("US", "NA"), ("CA", "NA"),
    ("BR", "LATAM"),
    ("SG", "APAC"), ("JP", "APAC"), ("IN", "APAC"),
    ("AE", "MEA"),
)
VECTORS = tuple(dict.fromkeys(t[3] for t in TECHNIQUES))
REGIONS = ("EU", "NA", "APAC", "LATAM", "MEA")
STATUS_W = (("Open", 55), ("Triaging", 20), ("Contained", 12), ("Closed", 13))

COLUMNS = (
    "alert_id", "detected_at", "severity", "tactic", "technique_id",
    "technique_name", "attack_type", "src_ip", "src_asn", "country",
    "region", "dst_asset", "dst_port", "cve_id", "cvss", "confidence",
    "status", "resolved_min",
)


def generate_alerts(n: int = 600, seed: int = SEED_DEFAULT, hours: int = 48, now: datetime | None = None) -> pd.DataFrame:
    """Deterministic synthetic alert frame. Same (n, seed, hours, now) -> same frame."""
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    status_names = [s for s, _ in STATUS_W]
    status_w = [w for _, w in STATUS_W]
    rows: list[dict] = []
    for i in range(n):
        tech = rng.choices(TECHNIQUES, weights=TECH_W)[0]
        sev = rng.choices(SEVERITIES, weights=SEV_WEIGHTS)[0]
        lo, hi = CVSS_BY_SEV[sev]
        cvss = round(rng.uniform(lo, hi), 1)
        detected = now - timedelta(minutes=rng.randrange(0, hours * 60 + 1))
        src_net = rng.choice(("203.0.113.", "198.51.100."))
        cc, region = rng.choice(COUNTRIES)
        status = rng.choices(status_names, weights=status_w)[0]
        resolved = None
        if status == "Closed":
            a, b = MTTR_MIN[sev]
            resolved = rng.randrange(a, b + 1)
        rows.append(
            {
                "alert_id": f"SOC-2026-{seed % 1000:03d}-{i:04d}",
                "detected_at": detected,
                "severity": sev,
                "tactic": tech[2],
                "technique_id": tech[0],
                "technique_name": tech[1],
                "attack_type": tech[3],
                "src_ip": f"{src_net}{rng.randrange(1, 255)}",
                "src_asn": f"AS{rng.randrange(64496, 64512)}",
                "country": cc,
                "region": region,
                "dst_asset": f"10.42.{rng.randrange(1, 20)}.{rng.randrange(2, 254)}",
                "dst_port": rng.choice(tech[4]),
                "cve_id": f"CVE-2026-{rng.randrange(10000, 60000):05d}" if rng.random() < tech[5] else "",
                "cvss": cvss,
                "confidence": rng.randrange(55, 100),
                "status": status,
                "resolved_min": resolved,
            }
        )
    df = pd.DataFrame(rows, columns=list(COLUMNS))
    return df.sort_values("detected_at", ascending=False).reset_index(drop=True)


def apply_closed(df: pd.DataFrame, closed_ids: list[str]) -> pd.DataFrame:
    """Override status to Closed for ids confirmed in the dialog."""
    if not closed_ids:
        return df
    out = df.copy()
    mask = out["alert_id"].isin(closed_ids)
    out.loc[mask, "status"] = "Closed"
    missing = mask & out["resolved_min"].isna()
    for sev, grp in out[missing].groupby("severity"):
        a, b = MTTR_MIN.get(sev, (60, 240))
        out.loc[grp.index, "resolved_min"] = (a + b) // 2
    return out


def filter_alerts(
    df: pd.DataFrame,
    region: str = "Все",
    vector: str = "Все",
    sev_floor: str = "Low",
    search: str = "",
    window_h: int = 24,
    now: datetime | None = None,
) -> pd.DataFrame:
    """Pure filter used by UI and tests."""
    now = now or datetime.now(timezone.utc)
    out = df[df["detected_at"] >= now - timedelta(hours=window_h)]
    if region != "Все":
        out = out[out["region"] == region]
    if vector != "Все":
        out = out[out["attack_type"] == vector]
    floor = SEV_ORDER.get(sev_floor, 0)
    out = out[out["severity"].map(SEV_ORDER) >= floor]
    q = (search or "").strip().lower()
    if q:
        hay = (
            out["src_ip"].str.lower() + " " + out["cve_id"].str.lower() + " "
            + out["technique_id"].str.lower() + " " + out["country"].str.lower() + " "
            + out["alert_id"].str.lower()
        )
        out = out[hay.str.contains(q, regex=False)]
    return out.sort_values("detected_at", ascending=False).reset_index(drop=True)


def _spark(series: pd.Series, points: int = 12) -> list[float]:
    if series.empty:
        return [0.0] * points
    buckets = max(1, len(series) // points)
    vals = [float(series.iloc[i:i + buckets].sum()) for i in range(0, len(series), buckets)]
    return (vals + [0.0] * points)[:points]


def compute_kpis(df: pd.DataFrame, now: datetime | None = None) -> dict:
    """KPIs over the filtered view. All values are sample data."""
    now = now or datetime.now(timezone.utc)
    day = df[df["detected_at"] >= now - timedelta(hours=24)]
    open_df = df[df["status"].isin(("Open", "Triaging"))]
    crit = day[day["severity"] == "Critical"]
    closed = df[(df["status"] == "Closed") & df["resolved_min"].notna()]
    mttr = float(closed["resolved_min"].mean()) if len(closed) else 0.0
    hourly = day.set_index("detected_at").sort_index()
    sparks = {
        "open": _spark(open_df.set_index("detected_at").sort_index().assign(n=1)["n"].resample("2h").sum()) if len(open_df) else [0.0] * 12,
        "crit": _spark(crit.assign(n=1).set_index("detected_at").sort_index()["n"].resample("2h").sum()) if len(crit) else [0.0] * 12,
        "all": _spark(hourly.assign(n=1)["n"].resample("2h").sum()) if len(hourly) else [0.0] * 12,
        "src": _spark(hourly.assign(n=1)["n"].resample("2h").sum()) if len(hourly) else [0.0] * 12,
    }
    _ = hourly  # keep frame intent explicit
    return {
        "open": int(len(open_df)),
        "crit_24h": int(len(crit)),
        "mttr": round(mttr, 1),
        "sources": int(df["src_ip"].nunique()) if len(df) else 0,
        "new_24h": int(len(day)),
        "closed_n": int(len(closed)),
        "sparks": sparks,
    }


def trend_by_hour(df: pd.DataFrame, hours: int = 24, now: datetime | None = None) -> pd.DataFrame:
    """Hourly counts pivoted by severity, all four columns always present."""
    now = now or datetime.now(timezone.utc)
    start = (now - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    idx = pd.date_range(start=start, periods=hours + 1, freq="h", tz="UTC")
    frame = pd.DataFrame({"hour": idx})
    if not len(df):
        for sev in SEVERITIES:
            frame[sev] = 0
        return frame
    tmp = df[df["detected_at"] >= start].copy()
    tmp["hour"] = tmp["detected_at"].dt.floor("h")
    piv = tmp.pivot_table(index="hour", columns="severity", values="alert_id", aggfunc="count", fill_value=0)
    for sev in SEVERITIES:
        if sev not in piv.columns:
            piv[sev] = 0
    piv = piv[list(SEVERITIES)].reindex(idx, fill_value=0)
    out = piv.reset_index().rename(columns={"index": "hour"})
    return out


def breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """Counts per attack vector, heaviest first."""
    if not len(df):
        return pd.DataFrame({"attack_type": [], "count": []})
    out = df["attack_type"].value_counts().reset_index()
    out.columns = ["attack_type", "count"]
    return out
