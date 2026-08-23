import contextlib
import html
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from app.review_store import get_analyst_review, save_analyst_review
from app.quarantine_service import quarantine_scan, restore_quarantined_file
from app.soar_engine import execute_soar_action
from app.splunk_pipeline import main as run_live_pipeline
from app.splunk_search import run_splunk_search


PROJECT_DIR = Path.home() / "ai-soc-triage"
DATABASE_FILE = PROJECT_DIR / "data" / "incidents.db"

TELEMETRY_BASE = """
(index=windows OR index=linux OR index=web OR index=suricata OR
 index=ai_triage OR index=security_alerts)
"""


def clean_value(value, fallback: str = "—") -> str:
    """Return a safe display string for values coming from events/SQLite."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    text = str(value).strip()
    return fallback if text.lower() in {"", "nan", "none", "null"} else text


@st.cache_data(ttl=8, show_spinner=False)
def load_live_telemetry() -> tuple[pd.DataFrame, pd.DataFrame, str | None]:
    """Fetch a lightweight sensor matrix and redacted live event stream."""
    summary_query = TELEMETRY_BASE + r"""
| eval sensor=case(index="windows","WINDOWS / SYSMON",
                   index="linux","LINUX AUTH",
                   index="web","DVWA / APACHE",
                   index="suricata","SURICATA IDS",
                   index="ai_triage","AI TRIAGE",
                   index="security_alerts","SECURITY ALERTS",
                   true(),upper(index))
| stats count as events latest(_time) as last_seen by sensor host
| convert ctime(last_seen)
| sort 0 - events
"""
    feed_query = TELEMETRY_BASE + r"""
| eval sensor=case(index="windows","WINDOWS",
                   index="linux","LINUX",
                   index="web","WEB",
                   index="suricata","SURICATA",
                   index="ai_triage","AI",
                   true(),upper(index))
| eval event_preview=substr(replace(_raw,"[\r\n]+"," "),1,190)
| table _time sensor host sourcetype event_preview
| sort 0 - _time
| head 80
"""
    try:
        summary = pd.DataFrame(run_splunk_search(summary_query, earliest_time="-15m"))
        feed = pd.DataFrame(run_splunk_search(feed_query, earliest_time="-15m"))
        return summary, feed, None
    except Exception as error:
        return pd.DataFrame(), pd.DataFrame(), f"{type(error).__name__}: {error}"


@st.cache_data(ttl=10, show_spinner=False)
def load_detection_trend() -> pd.DataFrame:
    """Return the last 24 hours of triaged detections for the activity chart."""
    query = """
        SELECT timestamp, severity, detection_name
        FROM incidents AS i
        JOIN triage_results AS t ON i.alert_id = t.alert_id
        ORDER BY t.id DESC
        LIMIT 500
    """
    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            frame = pd.read_sql_query(query, connection)
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
        frame = frame.dropna(subset=["timestamp"])
        if frame.empty:
            return frame
        cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=24)
        frame = frame[frame["timestamp"] >= cutoff]
        frame["hour"] = frame["timestamp"].dt.floor("h")
        return frame.groupby(["hour", "severity"]).size().unstack(fill_value=0)
    except (sqlite3.Error, pd.errors.DatabaseError, KeyError):
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_incidents() -> pd.DataFrame:
    query = """
        SELECT
            i.alert_id,
            i.timestamp,
            i.detection_name,
            i.host,
            i.source_ip,
            i.destination_ip,
            i.raw_event,
            i.status,
            t.severity,
            t.verdict,
            t.confidence,
            t.summary,
            t.mitre_techniques,
            t.evidence,
            t.false_positive_indicators,
            t.recommended_actions,
            t.requires_human_review,
            t.created_at
        FROM incidents AS i
        JOIN triage_results AS t
            ON i.alert_id = t.alert_id
        ORDER BY t.id DESC
    """

    with sqlite3.connect(DATABASE_FILE) as connection:
        return pd.read_sql_query(query, connection)


@st.cache_data(ttl=5)
def load_yara_scans() -> pd.DataFrame:
    query = """
        SELECT
            id,
            alert_id,
            file_name,
            file_path,
            sha256,
            file_size,
            matched,
            match_count,
            matched_rules,
            scan_status,
            scanned_at
        FROM yara_scans
        ORDER BY id DESC
        LIMIT 100
    """

    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            return pd.read_sql_query(query, connection)
    except (sqlite3.Error, pd.errors.DatabaseError):
        return pd.DataFrame()


def get_latest_quarantine_action(scan_id: int) -> dict | None:
    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM quarantine_actions
                WHERE scan_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None
    except sqlite3.Error:
        return None


def parse_json_list(value: str) -> list:
    try:
        parsed_value = json.loads(value)
        return parsed_value if isinstance(parsed_value, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def show_list(items: list, empty_message: str) -> None:
    if not items:
        st.info(empty_message)
        return

    for item in items:
        st.markdown(f"- {item}")


st.set_page_config(
    page_title="AI SOC Triage Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @keyframes pulse {
        0%, 100% { opacity: 1; box-shadow: 0 0 8px rgba(101,214,105,.45); }
        50% { opacity: .55; box-shadow: 0 0 22px rgba(101,214,105,.95); }
    }
    @keyframes scan {
        0% { transform: translateY(-100px); opacity: 0; }
        20% { opacity: .45; }
        100% { transform: translateY(300px); opacity: 0; }
    }
    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(14px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes gridMove {
        from { background-position: 0 0, 0 0, 100% 0, 0 0; }
        to { background-position: 35px 35px, 35px 35px, 100% 0, 0 0; }
    }
    @keyframes titleGlow {
        0%, 100% { text-shadow: 0 0 8px rgba(127,202,69,.15); }
        50% { text-shadow: 0 0 22px rgba(127,202,69,.48); }
    }
    @keyframes radarSweep {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    @keyframes radarPing {
        0%, 100% { transform: scale(.7); opacity: .25; }
        50% { transform: scale(1.15); opacity: 1; }
    }
    @keyframes shimmer {
        0% { transform: translateX(-130%); }
        100% { transform: translateX(260%); }
    }
    @keyframes floatCard {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-3px); }
    }
    @keyframes borderFlow {
        0% { background-position: 0% 50%; }
        100% { background-position: 200% 50%; }
    }
    @keyframes tickerMove {
        from { transform: translateX(100%); }
        to { transform: translateX(-100%); }
    }
    @keyframes equalize {
        0%, 100% { transform: scaleY(.25); }
        50% { transform: scaleY(1); }
    }
    .stApp {
        background:
            linear-gradient(rgba(27,34,29,.22) 1px, transparent 1px),
            linear-gradient(90deg, rgba(27,34,29,.22) 1px, transparent 1px),
            radial-gradient(circle at top right, #18221b 0%, transparent 38%),
            #090b0a;
        background-size: 35px 35px, 35px 35px, auto, auto;
        color: #e8ece9;
        animation: gridMove 12s linear infinite;
    }
    .block-container {
        max-width: 1450px;
        padding-top: 1.5rem;
        padding-bottom: 4rem;
        animation: fadeUp .55s ease-out;
    }
    header[data-testid="stHeader"] {
        background: rgba(9,11,10,.88);
        border-bottom: 1px solid #263029;
        backdrop-filter: blur(12px);
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #111512 0%, #090b0a 100%);
        border-right: 1px solid #28312a;
    }
    .soc-hero {
        position: relative;
        overflow: hidden;
        padding: 2rem;
        margin-bottom: 1.5rem;
        background: linear-gradient(120deg, rgba(20,25,22,.98), rgba(9,12,10,.98));
        border: 1px solid #2e3b32;
        border-left: 5px solid #65a637;
        border-radius: 12px;
        box-shadow: 0 18px 45px rgba(0,0,0,.42), inset 0 0 25px rgba(101,166,55,.04);
    }
    .soc-hero::before {
        content: "";
        position: absolute;
        inset: 0;
        pointer-events: none;
        background: linear-gradient(
            110deg,
            transparent 20%,
            rgba(127,202,69,.045) 42%,
            rgba(127,202,69,.13) 50%,
            rgba(127,202,69,.045) 58%,
            transparent 80%
        );
        transform: translateX(-130%);
        animation: shimmer 7s ease-in-out infinite;
    }
    .soc-hero::after {
        content: "";
        position: absolute;
        left: 0;
        right: 0;
        top: -10px;
        height: 2px;
        background: linear-gradient(90deg, transparent, rgba(101,166,55,.9), transparent);
        animation: scan 4.5s linear infinite;
    }
    .soc-title {
        color: #fff;
        font-size: 2.5rem;
        font-weight: 760;
        letter-spacing: -.03em;
        margin: 0;
        animation: titleGlow 3s ease-in-out infinite;
    }
    .soc-accent { color: #7fca45; }
    .soc-subtitle { color: #9ba69e; margin: .65rem 0 1.2rem; }
    .status-row { display: flex; flex-wrap: wrap; gap: .7rem; }
    .status-chip {
        display: inline-flex;
        align-items: center;
        gap: .5rem;
        color: #cbd4cd;
        background: #121713;
        border: 1px solid #2b352d;
        border-radius: 6px;
        padding: .45rem .75rem;
        font-family: monospace;
        font-size: .78rem;
        position: relative;
        overflow: hidden;
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
    }
    .status-chip:hover {
        transform: translateY(-2px);
        border-color: #65a637;
        box-shadow: 0 0 18px rgba(101,166,55,.16);
    }
    .hero-content {
        position: relative;
        z-index: 2;
        max-width: calc(100% - 180px);
    }
    .threat-radar {
        position: absolute;
        z-index: 2;
        width: 126px;
        height: 126px;
        right: 2.2rem;
        top: 50%;
        transform: translateY(-50%);
        border: 1px solid rgba(127,202,69,.4);
        border-radius: 50%;
        background:
            linear-gradient(90deg, transparent 49.5%, rgba(127,202,69,.18) 50%, transparent 50.5%),
            linear-gradient(transparent 49.5%, rgba(127,202,69,.18) 50%, transparent 50.5%),
            radial-gradient(circle, transparent 29%, rgba(127,202,69,.15) 30%, transparent 31%),
            radial-gradient(circle, transparent 59%, rgba(127,202,69,.15) 60%, transparent 61%),
            rgba(9,18,11,.82);
        box-shadow: inset 0 0 28px rgba(101,166,55,.09), 0 0 24px rgba(101,166,55,.08);
    }
    .threat-radar::before {
        content: "";
        position: absolute;
        inset: 4px;
        border-radius: 50%;
        background: conic-gradient(from 0deg, rgba(127,202,69,.5), transparent 18%, transparent 100%);
        animation: radarSweep 3.6s linear infinite;
    }
    .threat-radar::after {
        content: "";
        position: absolute;
        width: 8px;
        height: 8px;
        top: 31px;
        right: 27px;
        border-radius: 50%;
        background: #8be04d;
        box-shadow: 0 0 12px #8be04d;
        animation: radarPing 1.8s ease-in-out infinite;
    }
    .live-dot {
        width: 8px;
        height: 8px;
        background: #65d669;
        border-radius: 50%;
        animation: pulse 1.8s infinite;
    }
    .section-label {
        color: #7fca45;
        font-family: monospace;
        font-size: .8rem;
        font-weight: 800;
        letter-spacing: .1em;
        text-transform: uppercase;
    }
    .live-ribbon {
        display:flex; align-items:center; gap:.8rem; margin:-.25rem 0 1.2rem;
        padding:.62rem .9rem; border:1px solid #263c2c; border-radius:8px;
        background:rgba(8,15,10,.92); overflow:hidden; position:relative;
    }
    .live-ribbon::before {
        content:""; position:absolute; inset:0; padding:1px; border-radius:8px;
        background:linear-gradient(90deg,transparent,#7fca45,transparent,#46d7ff,transparent);
        background-size:200% 100%; animation:borderFlow 4s linear infinite;
        -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
        -webkit-mask-composite:xor; mask-composite:exclude; pointer-events:none;
    }
    .ribbon-label { color:#7fca45; font:800 .72rem monospace; white-space:nowrap; }
    .ticker-window { overflow:hidden; flex:1; white-space:nowrap; }
    .ticker-text { display:inline-block; color:#aebbb1; font:.76rem monospace;
        animation:tickerMove 26s linear infinite; }
    .telemetry-panel {
        background:linear-gradient(145deg,rgba(16,23,19,.98),rgba(7,11,9,.98));
        border:1px solid #29382e; border-radius:12px; padding:1rem;
        box-shadow:inset 0 0 35px rgba(71,190,101,.035),0 18px 35px rgba(0,0,0,.24);
    }
    .sensor-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.65rem; }
    .sensor-card { position:relative; overflow:hidden; padding:.82rem; border-radius:8px;
        background:#0d130f; border:1px solid #24352a; min-height:76px; }
    .sensor-card::after { content:""; position:absolute; left:0; bottom:0; height:2px; width:100%;
        background:linear-gradient(90deg,transparent,#76d34b,transparent); animation:borderFlow 3s linear infinite; }
    .sensor-name { color:#c8d4ca; font:700 .72rem monospace; }
    .sensor-count { color:white; font-size:1.35rem; font-weight:800; margin-top:.25rem; }
    .sensor-time { color:#6f8274; font:.65rem monospace; }
    .equalizer { display:inline-flex; gap:2px; height:14px; align-items:flex-end; margin-left:.4rem; }
    .equalizer i { display:block; width:2px; height:12px; background:#79d94b;
        transform-origin:bottom; animation:equalize .8s ease-in-out infinite; }
    .equalizer i:nth-child(2){animation-delay:.14s}.equalizer i:nth-child(3){animation-delay:.28s}
    .feed-line { border-left:2px solid #65a637; padding:.55rem .75rem; margin:.4rem 0;
        background:rgba(16,22,18,.8); font:.72rem monospace; color:#aab5ac; }
    .incident-card {
        background: linear-gradient(145deg, rgba(20,25,22,.98), rgba(11,14,12,.98));
        border: 1px solid #2d382f;
        border-left: 4px solid #65a637;
        border-radius: 10px;
        padding: 1.25rem;
        margin: .8rem 0 1.2rem;
        box-shadow: 0 12px 28px rgba(0,0,0,.28);
        transition: transform .25s ease, border-color .25s ease, box-shadow .25s ease;
    }
    .incident-card:hover {
        transform: translateY(-3px);
        border-color: #65a637;
        box-shadow: 0 18px 40px rgba(0,0,0,.38), 0 0 22px rgba(101,166,55,.08);
    }
    .severity-low { color: #70d6ff; font-weight: 800; }
    .severity-medium { color: #e6b450; font-weight: 800; }
    .severity-high { color: #ff8c42; font-weight: 800; }
    .severity-critical { color: #ff4b5c; font-weight: 800; animation: pulse 1.5s infinite; }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, rgba(21,26,23,.98), rgba(12,15,13,.98));
        border: 1px solid #29332c;
        border-top: 3px solid #65a637;
        border-radius: 10px;
        padding: 1.15rem;
        box-shadow: 0 12px 28px rgba(0,0,0,.30);
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
        overflow: hidden;
        position: relative;
        animation: floatCard 5s ease-in-out infinite;
    }
    [data-testid="stMetric"]::after {
        content: "";
        position: absolute;
        inset: 0;
        pointer-events: none;
        background: linear-gradient(105deg, transparent 42%, rgba(127,202,69,.07) 50%, transparent 58%);
        transform: translateX(-130%);
        animation: shimmer 8s ease-in-out infinite;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-4px);
        border-color: #65a637;
        box-shadow: 0 14px 32px rgba(101,166,55,.12);
    }
    [data-testid="stMetricLabel"] {
        color: #99a49c;
        font-family: monospace;
        text-transform: uppercase;
        letter-spacing: .05em;
    }
    [data-testid="stMetricValue"] { color: #fff; }
    [data-testid="stDataFrame"] {
        border: 1px solid #2b352e;
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 12px 30px rgba(0,0,0,.24);
    }
    .stButton > button, [data-testid="stFormSubmitButton"] > button {
        color: #071007;
        background: #65a637;
        border: 1px solid #78bb49;
        border-radius: 6px;
        font-family: monospace;
        font-weight: 800;
        transition: all .2s ease;
    }
    .stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover {
        color: #fff;
        background: #4f892c;
        border-color: #91d75a;
        box-shadow: 0 0 20px rgba(101,166,55,.35);
        transform: translateY(-2px);
    }
    div[data-testid="stCode"] {
        border: 1px solid #2c382f;
        border-left: 4px solid #65a637;
        border-radius: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background: #111512;
        border: 1px solid #2b352d;
        border-radius: 6px;
        padding: .5rem 1rem;
    }
    .stTabs [aria-selected="true"] { color: #7fca45; border-color: #65a637; }
    h1, h2, h3 { color: #f3f7f4; }
    hr { border-color: #263029; }
    @media (max-width: 760px) {
        .hero-content { max-width: 100%; }
        .threat-radar { display: none; }
        .soc-title { font-size: 1.9rem; }
        .sensor-grid { grid-template-columns:1fr; }
    }
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            animation-duration: .01ms !important;
            animation-iteration-count: 1 !important;
            scroll-behavior: auto !important;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="soc-hero">
        <div class="hero-content">
            <p class="soc-title">AI <span class="soc-accent">SOC</span> Triage Assistant</p>
            <p class="soc-subtitle">
                Splunk-powered security analytics with private local AI,
                MITRE ATT&amp;CK validation and analyst-controlled response.
            </p>
            <div class="status-row">
                <div class="status-chip"><span class="live-dot"></span> AI ENGINE READY</div>
                <div class="status-chip"><span class="live-dot"></span> SPLUNK CONNECTED</div>
                <div class="status-chip"><span class="live-dot"></span> HUMAN REVIEW ENABLED</div>
                <div class="status-chip"><span class="live-dot"></span> YARA ACTIVE</div>
            </div>
        </div>
        <div class="threat-radar" aria-label="Animated threat radar"></div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown("## 🛡️ Analyst Console")
st.sidebar.caption("Local Tier-1 SOC investigation workspace")

auto_refresh = st.sidebar.selectbox(
    "Live screen refresh",
    ["Off", "10 seconds", "30 seconds", "60 seconds"],
    index=1,
    help="Refreshes telemetry visuals only. AI triage runs only when you click Collect.",
)
refresh_seconds = {"10 seconds": 10, "30 seconds": 30, "60 seconds": 60}.get(auto_refresh)

if st.sidebar.button("⚡ Collect + AI triage", type="primary", use_container_width=True):
    pipeline_output = io.StringIO()
    try:
        with st.spinner("Querying Splunk and running AI triage…"):
            with contextlib.redirect_stdout(pipeline_output):
                run_live_pipeline()
        st.session_state["pipeline_output"] = pipeline_output.getvalue()
        st.cache_data.clear()
        st.sidebar.success("Collection cycle completed")
    except Exception as error:
        st.sidebar.error(f"Collection failed: {type(error).__name__}: {error}")

if st.sidebar.button("↻ Refresh screen", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

if st.session_state.get("pipeline_output"):
    with st.sidebar.expander("Last collection log"):
        st.code(st.session_state["pipeline_output"], language="text")

st.sidebar.markdown("---")
st.sidebar.caption(f"UTC {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")

if refresh_seconds:
    components.html(
        f"<script>setTimeout(function(){{window.parent.location.reload();}}, {refresh_seconds * 1000});</script>",
        height=0,
    )

try:
    incidents = load_incidents()
except Exception as error:
    st.error(f"Unable to load incident database: {error}")
    st.stop()

if incidents.empty:
    st.warning("No triaged incidents are available.")
    st.stop()

available_severities = sorted(incidents["severity"].dropna().unique().tolist())
selected_severities = st.sidebar.multiselect(
    "Severity filter", available_severities, default=available_severities
)
search_text = st.sidebar.text_input(
    "Search alerts", placeholder="Alert ID, host or source IP"
)

filtered_incidents = incidents[
    incidents["severity"].isin(selected_severities)
].copy()

if search_text:
    search_mask = (
        filtered_incidents["alert_id"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_incidents["detection_name"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_incidents["host"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_incidents["source_ip"].astype(str).str.contains(search_text, case=False, na=False)
    )
    filtered_incidents = filtered_incidents[search_mask]

ticker_items = []
for _, row in incidents.head(8).iterrows():
    ticker_items.append(
        f"{clean_value(row['severity']).upper()}  •  "
        f"{clean_value(row['detection_name'])}  •  {clean_value(row['host'])}"
    )
ticker = "     ◆     ".join(ticker_items) or "Awaiting triaged security events"
st.markdown(
    f"""
    <div class="live-ribbon">
      <span class="live-dot"></span><span class="ribbon-label">LIVE INCIDENT WIRE</span>
      <div class="ticker-window"><span class="ticker-text">{html.escape(ticker)}</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

telemetry_summary, live_feed, telemetry_error = load_live_telemetry()
events_15m = (
    int(pd.to_numeric(telemetry_summary.get("events", pd.Series(dtype=float)), errors="coerce").fillna(0).sum())
    if not telemetry_summary.empty else 0
)
active_sensors = int(telemetry_summary["sensor"].nunique()) if "sensor" in telemetry_summary else 0

st.markdown('<p class="section-label">Security operations overview</p>', unsafe_allow_html=True)
metric1, metric2, metric3, metric4, metric5 = st.columns(5)
metric1.metric("Triaged alerts", len(filtered_incidents))
metric2.metric("Events / 15m", f"{events_15m:,}")
metric3.metric("Active sensors", active_sensors)
metric4.metric(
    "High / critical",
    int(filtered_incidents["severity"].isin(["high", "critical"]).sum()),
)
metric5.metric(
    "AI confidence",
    f"{filtered_incidents['confidence'].mean():.0%}" if not filtered_incidents.empty else "0%",
)

st.markdown("---")
st.markdown('<p class="section-label">Live monitoring fabric</p>', unsafe_allow_html=True)
monitor_left, monitor_right = st.columns([1.05, 1.45])

with monitor_left:
    st.markdown('<div class="telemetry-panel">', unsafe_allow_html=True)
    if telemetry_error:
        st.warning(f"Live Splunk telemetry unavailable: {telemetry_error}")
    elif telemetry_summary.empty:
        st.info("No telemetry was indexed during the last 15 minutes.")
    else:
        sensor_cards = []
        for _, sensor_row in telemetry_summary.head(9).iterrows():
            sensor_cards.append(
                '<div class="sensor-card">'
                f'<div class="sensor-name">{html.escape(clean_value(sensor_row.get("sensor")))}'
                '<span class="equalizer"><i></i><i></i><i></i></span></div>'
                f'<div class="sensor-count">{int(float(sensor_row.get("events", 0))):,}</div>'
                f'<div class="sensor-time">{html.escape(clean_value(sensor_row.get("host")))} · '
                f'{html.escape(clean_value(sensor_row.get("last_seen")))}</div></div>'
            )
        st.markdown(f'<div class="sensor-grid">{"".join(sensor_cards)}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with monitor_right:
    st.markdown("#### Detection pulse · last 24 hours")
    trend = load_detection_trend()
    if trend.empty:
        st.info("The detection trend will appear after triaged events are stored.")
    else:
        st.area_chart(trend, use_container_width=True, height=245)

st.markdown("#### Live security-event stream · last 15 minutes")
if not live_feed.empty:
    feed_columns = [column for column in ["_time", "sensor", "host", "sourcetype", "event_preview"] if column in live_feed]
    st.dataframe(live_feed[feed_columns], use_container_width=True, hide_index=True, height=260)
else:
    st.info("No live event rows are currently available from Splunk.")

st.markdown("---")
st.subheader("AI-prioritized incident queue")

if filtered_incidents.empty:
    st.info("No incidents match the selected filters.")
    st.stop()

queue_columns = [
    "alert_id",
    "timestamp",
    "detection_name",
    "host",
    "source_ip",
    "severity",
    "verdict",
    "confidence",
    "status",
]
st.dataframe(
    filtered_incidents[queue_columns],
    use_container_width=True,
    hide_index=True,
    height=260,
)

selected_alert = st.selectbox(
    "Select an incident for investigation",
    filtered_incidents["alert_id"].tolist(),
)
incident = filtered_incidents[
    filtered_incidents["alert_id"] == selected_alert
].iloc[0]

severity = str(incident["severity"]).lower()
if severity not in ["low", "medium", "high", "critical"]:
    severity = "medium"

st.markdown(
    f"""
    <div class="incident-card">
        <div class="section-label">Selected incident</div>
        <h3>{html.escape(clean_value(incident['detection_name']))}</h3>
        <p>
            <strong>Alert ID:</strong> {html.escape(clean_value(incident['alert_id']))} &nbsp; | &nbsp;
            <strong>Host:</strong> {html.escape(clean_value(incident['host']))} &nbsp; | &nbsp;
            <strong>Source:</strong> {html.escape(clean_value(incident['source_ip'], 'not reported'))}
        </p>
        <p>
            <strong>Severity:</strong>
            <span class="severity-{severity}">{severity.upper()}</span>
            &nbsp; | &nbsp; <strong>Verdict:</strong> {html.escape(clean_value(incident['verdict']))}
            &nbsp; | &nbsp; <strong>Confidence:</strong> {float(incident['confidence']):.0%}
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

overview_tab, evidence_tab, yara_tab, response_tab, raw_tab = st.tabs(
    [
        "AI Summary",
        "Evidence & MITRE",
        "YARA Analysis",
        "Recommended Response",
        "Raw Event",
    ]
)

with overview_tab:
    st.subheader("AI triage recommendation")
    st.write(incident["summary"])
    if bool(incident["requires_human_review"]):
        st.warning("Human analyst review is required before any response action.")
    else:
        st.success("The alert has completed analyst review.")

with evidence_tab:
    mitre_techniques = parse_json_list(incident["mitre_techniques"])
    evidence = parse_json_list(incident["evidence"])
    false_positive_indicators = parse_json_list(incident["false_positive_indicators"])

    st.markdown("### MITRE ATT&CK techniques")
    if mitre_techniques:
        st.dataframe(pd.DataFrame(mitre_techniques), use_container_width=True, hide_index=True)
    else:
        st.info("No MITRE ATT&CK technique was mapped.")

    evidence_column, false_positive_column = st.columns(2)
    with evidence_column:
        st.markdown("### Supporting evidence")
        show_list(evidence, "No supporting evidence was returned.")
    with false_positive_column:
        st.markdown("### False-positive indicators")
        show_list(false_positive_indicators, "No false-positive indicators were returned.")

with yara_tab:
    st.markdown("### YARA file-analysis results")
    st.caption(
        "Signature matches are stored in SQLite and forwarded to Splunk "
        "through HEC. A match requires human review."
    )

    yara_scans = load_yara_scans()

    if yara_scans.empty:
        st.info("No YARA scans are available yet.")
    else:
        total_scans = len(yara_scans)
        matched_scans = int(yara_scans["matched"].fillna(0).astype(int).sum())
        clean_scans = total_scans - matched_scans

        yara_metric_1, yara_metric_2, yara_metric_3 = st.columns(3)
        yara_metric_1.metric("Files scanned", total_scans)
        yara_metric_2.metric("Rule matches", matched_scans)
        yara_metric_3.metric("No match", clean_scans)

        st.dataframe(
            yara_scans[
                [
                    "scanned_at",
                    "file_name",
                    "scan_status",
                    "match_count",
                    "sha256",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

        selected_scan_id = st.selectbox(
            "Inspect YARA scan",
            yara_scans["id"].tolist(),
            format_func=lambda scan_id: (
                f"Scan {scan_id} — "
                f"{yara_scans.loc[yara_scans['id'] == scan_id, 'file_name'].iloc[0]}"
            ),
        )

        selected_scan = yara_scans[
            yara_scans["id"] == selected_scan_id
        ].iloc[0]
        selected_rules = parse_json_list(selected_scan["matched_rules"])

        st.markdown(f"**SHA-256:** `{selected_scan['sha256']}`")
        st.markdown(f"**File path:** `{selected_scan['file_path']}`")

        if selected_rules:
            st.markdown("#### Matched rules")
            st.dataframe(
                pd.DataFrame(selected_rules),
                use_container_width=True,
                hide_index=True,
            )
            st.warning(
                "YARA matched this file. An analyst must validate the "
                "finding before quarantine or containment."
            )

            st.markdown("#### Human-approved file quarantine")
            scan_alert_id = selected_scan.get("alert_id")
            scan_review = (
                get_analyst_review(scan_alert_id)
                if pd.notna(scan_alert_id) and scan_alert_id
                else None
            )
            quarantine_action = get_latest_quarantine_action(
                int(selected_scan_id)
            )

            if not scan_alert_id or pd.isna(scan_alert_id):
                st.info(
                    "This scan is not linked to an incident. Run the YARA "
                    "service with --alert-id before quarantine."
                )
            elif not scan_review or scan_review.get("decision") != "containment_approved":
                st.warning(
                    "Quarantine is locked until the linked incident receives "
                    "an ‘Approve containment’ analyst decision."
                )
            elif quarantine_action and quarantine_action.get("status") == "quarantined":
                st.error(
                    f"File quarantined by {quarantine_action['executed_by']}"
                )
                st.code(quarantine_action["quarantine_path"], language="text")

                if st.button(
                    "Restore quarantined file",
                    key=f"restore_yara_{quarantine_action['id']}",
                ):
                    try:
                        restore_result = restore_quarantined_file(
                            action_id=int(quarantine_action["id"]),
                            restored_by=scan_review["analyst"],
                        )
                        st.success("The file was restored and the action was audited.")
                        st.json(restore_result)
                        st.cache_data.clear()
                        st.rerun()
                    except (ValueError, FileNotFoundError, FileExistsError) as error:
                        st.error(str(error))
            else:
                if quarantine_action and quarantine_action.get("status") == "restored":
                    st.success("The latest quarantine action was safely restored.")

                if st.button(
                    "Quarantine matched file",
                    type="primary",
                    key=f"quarantine_yara_{selected_scan_id}",
                ):
                    try:
                        quarantine_result = quarantine_scan(
                            scan_id=int(selected_scan_id),
                            executed_by=scan_review["analyst"],
                        )
                        st.success("The matched file was quarantined and audited.")
                        st.json(quarantine_result)
                        st.cache_data.clear()
                        st.rerun()
                    except (
                        PermissionError,
                        ValueError,
                        FileNotFoundError,
                    ) as error:
                        st.error(str(error))
        else:
            st.success("No YARA rule matched this file.")

with response_tab:
    recommended_actions = parse_json_list(incident["recommended_actions"])
    st.markdown("### Recommended analyst actions")
    show_list(recommended_actions, "No recommended actions were returned.")
    st.error("Containment is disabled until a human analyst approves the action.")

    st.markdown("---")
    st.markdown("### Human analyst decision")
    current_review = get_analyst_review(incident["alert_id"])

    if current_review:
        st.success(
            f"Reviewed by {current_review['analyst']} — {current_review['decision']}"
        )
        if current_review["notes"]:
            st.write(f"**Analyst notes:** {current_review['notes']}")
        st.caption(f"Reviewed at: {current_review['reviewed_at']}")

    decision_options = {
        "Escalate to Tier 2": "escalated",
        "Mark as false positive": "false_positive",
        "Approve containment": "containment_approved",
        "Close after investigation": "closed",
    }

    with st.form("analyst_review_form"):
        analyst_name = st.text_input("Analyst name", value="Parakh Shinde")
        decision_label = st.selectbox("Decision", list(decision_options.keys()))
        analyst_notes = st.text_area(
            "Investigation notes",
            placeholder="Document the evidence and reason for this decision.",
        )
        submit_review = st.form_submit_button("Submit analyst decision")

        if submit_review:
            if not analyst_name.strip():
                st.error("Analyst name is required.")
            elif not analyst_notes.strip():
                st.error("Investigation notes are required.")
            else:
                save_analyst_review(
                    alert_id=incident["alert_id"],
                    decision=decision_options[decision_label],
                    analyst=analyst_name.strip(),
                    notes=analyst_notes.strip(),
                )
                st.cache_data.clear()
                st.success("Analyst decision recorded.")
                st.rerun()

    st.markdown("---")
    st.markdown("### SOAR response simulation")
    st.caption(
        "This lab records a simulated response action. It does not change "
        "the firewall, endpoint, user account, or network."
    )

    current_review = get_analyst_review(incident["alert_id"])

    soar_action_options = {
        "Block source IP": "block_source_ip",
        "Isolate affected host": "isolate_host",
        "Disable suspected user": "disable_user",
        "Collect forensic data": "collect_forensic_data",
    }

    selected_soar_label = st.selectbox(
        "Response action",
        list(soar_action_options.keys()),
        key=f"soar_action_{incident['alert_id']}",
    )

    containment_approved = bool(
        current_review
        and current_review.get("decision") == "containment_approved"
    )

    if not containment_approved:
        st.warning(
            "Select ‘Approve containment’ in the analyst decision form "
            "before running a SOAR simulation."
        )

    if st.button(
        "Run approved simulation",
        disabled=not containment_approved,
        type="primary",
        key=f"run_soar_{incident['alert_id']}",
    ):
        try:
            soar_result = execute_soar_action(
                alert_id=incident["alert_id"],
                action=soar_action_options[selected_soar_label],
                executed_by=current_review["analyst"],
                simulation=True,
            )
            st.success("SOAR response was simulated and added to the audit log.")
            st.json(soar_result)
        except (PermissionError, ValueError) as error:
            st.error(str(error))

with raw_tab:
    st.markdown("### Redacted security event")
    st.code(incident["raw_event"], language="text")
    st.caption("Sensitive values are redacted before local LLM processing.")

st.markdown("---")
st.caption(
    "AI SOC Triage Assistant • Splunk SIEM • MITRE ATT&CK • YARA • Human-in-the-loop • SOAR simulation"
)
