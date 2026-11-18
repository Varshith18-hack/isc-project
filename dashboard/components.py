"""
Streamlit Dashboard Components & Visualization Utilities
========================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Provides modular visual and data helper functions for the Streamlit dashboard:
1. Data loading and caching for simulated medical device telemetry.
2. Interactive Plotly charts for clinical vitals and device network telemetry.
3. Styled HTML metric cards, alert badges, and security status indicators.
4. Anomaly score gauges and threshold visualization.
5. Audit blockchain explorer visualizers.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import database.database as db
from audit.audit_logger import load_audit_chain, get_audit_chain_summary


@st.cache_data(show_spinner=False)
def load_telemetry_dataset() -> pd.DataFrame:
    """Load and cache the simulated medical device dataset (10,000 records)."""
    if not config.DATA_FILE_PATH.exists():
        return pd.DataFrame()
    df = pd.read_csv(config.DATA_FILE_PATH)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def get_device_summary(device_id: str, df: pd.DataFrame) -> dict:
    """Compute summary statistics for a specific connected medical device."""
    if df.empty or device_id not in df["device_id"].values:
        return {}
    dev_df = df[df["device_id"] == device_id]
    latest = dev_df.iloc[-1]
    anomalies = dev_df[dev_df["is_anomaly"] == 1]

    profile = config.DEVICE_PROFILES.get(device_id, {"type": "Medical Device", "location": "ICU"})

    return {
        "device_id": device_id,
        "type": profile["type"],
        "location": profile["location"],
        "total_records": len(dev_df),
        "anomaly_count": len(anomalies),
        "anomaly_rate": (len(anomalies) / len(dev_df)) * 100,
        "latest_vitals": {
            "heart_rate": latest["heart_rate"],
            "systolic_bp": latest["systolic_bp"],
            "diastolic_bp": latest["diastolic_bp"],
            "oxygen_saturation": latest["oxygen_saturation"],
            "body_temperature": latest["body_temperature"],
            "device_activity_level": latest["device_activity_level"],
            "battery_level": latest.get("battery_level", 100.0),
        },
        "latest_timestamp": str(latest["timestamp"]),
    }


def create_vitals_time_series_chart(dev_df: pd.DataFrame, window: int = 150) -> go.Figure:
    """Create an interactive multi-axis Plotly time-series chart of patient vitals."""
    sub_df = dev_df.tail(window).copy()

    fig = go.Figure()

    # Heart Rate trace
    fig.add_trace(go.Scatter(
        x=sub_df["timestamp"],
        y=sub_df["heart_rate"],
        mode="lines",
        name="Heart Rate (bpm)",
        line=dict(color="#FF4B4B", width=2),
        hovertemplate="Time: %{x}<br>Heart Rate: %{y:.1f} bpm<extra></extra>",
    ))

    # Blood Pressure traces
    fig.add_trace(go.Scatter(
        x=sub_df["timestamp"],
        y=sub_df["systolic_bp"],
        mode="lines",
        name="Systolic BP (mmHg)",
        line=dict(color="#1E88E5", width=1.5),
        hovertemplate="Systolic: %{y:.1f} mmHg<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=sub_df["timestamp"],
        y=sub_df["diastolic_bp"],
        mode="lines",
        name="Diastolic BP (mmHg)",
        line=dict(color="#64B5F6", width=1.5, dash="dot"),
        hovertemplate="Diastolic: %{y:.1f} mmHg<extra></extra>",
    ))

    # SpO2 Trace (Secondary Y Axis)
    fig.add_trace(go.Scatter(
        x=sub_df["timestamp"],
        y=sub_df["oxygen_saturation"],
        mode="lines",
        name="SpO2 (%)",
        yaxis="y2",
        line=dict(color="#00C853", width=2),
        hovertemplate="Oxygen: %{y:.1f}%<extra></extra>",
    ))

    # Highlight Anomalies with Scatter Markers
    anom_sub = sub_df[sub_df["is_anomaly"] == 1]
    if not anom_sub.empty:
        fig.add_trace(go.Scatter(
            x=anom_sub["timestamp"],
            y=anom_sub["heart_rate"],
            mode="markers",
            name="Anomaly Detected",
            marker=dict(color="#FF0000", size=10, symbol="x", line=dict(width=2, color="#000000")),
            hovertemplate="ANOMALY DETECTED<br>Time: %{x}<br>Type: %{text}<extra></extra>",
            text=anom_sub.get("anomaly_type", "Anomaly"),
        ))

    fig.update_layout(
        title=dict(text="<b>Clinical Physiological Telemetry Stream</b>", font=dict(size=16)),
        xaxis=dict(title="Timestamp", showgrid=True, gridcolor="#E0E0E0"),
        yaxis=dict(title="Heart Rate (bpm) / BP (mmHg)", showgrid=True, gridcolor="#E0E0E0"),
        yaxis2=dict(
            title="SpO2 (%)",
            overlaying="y",
            side="right",
            range=[70, 105],
            showgrid=False,
        ),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode="x unified",
        margin=dict(l=40, r=40, t=50, b=40),
        height=380,
    )

    return fig


def create_network_activity_chart(dev_df: pd.DataFrame, window: int = 150) -> go.Figure:
    """Create an interactive Plotly chart for device activity level & network bursts."""
    sub_df = dev_df.tail(window).copy()

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=sub_df["timestamp"],
        y=sub_df["device_activity_level"],
        mode="lines+markers",
        name="Packets / Min",
        line=dict(color="#FF9800", width=2),
        marker=dict(size=4),
        hovertemplate="Activity: %{y:.1f} pkts/min<extra></extra>",
    ))

    # Upper Normal Baseline threshold line
    fig.add_hline(
        y=config.NORMAL_RANGES["device_activity_level"][1],
        line_dash="dash",
        line_color="#F44336",
        annotation_text="Normal Activity Upper Bound (60 pkts/min)",
        annotation_position="top right",
    )

    fig.update_layout(
        title=dict(text="<b>IoMT Device Network Activity & Traffic Load</b>", font=dict(size=16)),
        xaxis=dict(title="Timestamp", showgrid=True),
        yaxis=dict(title="Telemetry Packets per Minute", showgrid=True),
        hovermode="x",
        margin=dict(l=40, r=40, t=50, b=40),
        height=300,
    )

    return fig


def create_anomaly_score_gauge(score: float, threshold: float = 0.5809) -> go.Figure:
    """Create a high-impact Plotly gauge displaying the Isolation Forest anomaly score."""
    is_anomaly = score >= threshold

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        delta={
            "reference": threshold,
            "increasing": {"color": "#FF1744"},
            "decreasing": {"color": "#00E676"},
        },
        number={"font": {"size": 36, "color": "#D50000" if is_anomaly else "#00C853"}},
        gauge={
            "axis": {"range": [0, 1], "tickwidth": 1, "tickcolor": "#424242"},
            "bar": {"color": "#D50000" if is_anomaly else "#2E7D32", "thickness": 0.3},
            "bgcolor": "white",
            "borderwidth": 2,
            "bordercolor": "#BDBDBD",
            "steps": [
                {"range": [0, threshold], "color": "#E8F5E9"},
                {"range": [threshold, 1.0], "color": "#FFEBEE"},
            ],
            "threshold": {
                "line": {"color": "#D50000", "width": 4},
                "thickness": 0.8,
                "value": threshold,
            },
        },
    ))

    fig.update_layout(
        title={"text": "<b>Isolation Forest Anomaly Score</b><br><span style='font-size:12px;color:gray'>Threshold τ = 0.5809</span>", "x": 0.5},
        height=260,
        margin=dict(l=20, r=20, t=50, b=20),
    )

    return fig


def render_kpi_card(title: str, value: str, subtext: str = "", status: str = "normal"):
    """Render a styled HTML KPI card."""
    color_map = {
        "normal": "#1E88E5",
        "success": "#2E7D32",
        "warning": "#F57C00",
        "danger": "#D32F2F",
    }
    accent_color = color_map.get(status, "#1E88E5")

    st.markdown(
        f"""
        <div style="
            background: #FFFFFF;
            border-left: 5px solid {accent_color};
            border-radius: 8px;
            padding: 16px 20px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.06);
            margin-bottom: 12px;
        ">
            <div style="font-size: 13px; font-weight: 600; color: #757575; text-transform: uppercase; letter-spacing: 0.5px;">{title}</div>
            <div style="font-size: 28px; font-weight: 700; color: #212121; margin: 4px 0;">{value}</div>
            <div style="font-size: 12px; color: #616161;">{subtext}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_threat_badge(threat_type: str) -> str:
    """Return styled HTML badge distinguishing medical anomalies from cyber attacks."""
    cyber_threats = {"Network_Traffic_Burst", "Device_Telemetry_Spoofing", "Rapid_Battery_Drain"}
    is_cyber = threat_type in cyber_threats

    bg_color = "#FFF3E0" if is_cyber else "#FFEBEE"
    text_color = "#E65100" if is_cyber else "#C62828"
    icon = "🛡️ Cyber Attack" if is_cyber else "🩺 Medical Anomaly"

    return f"""
    <span style="
        background-color: {bg_color};
        color: {text_color};
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 12px;
        border: 1px solid {text_color};
    ">
        {icon}: {threat_type}
    </span>
    """

