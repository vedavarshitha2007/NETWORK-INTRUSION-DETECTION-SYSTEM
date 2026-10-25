
import streamlit as st
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
import base64

# Project folder
BASE_DIR = Path(__file__).resolve().parent

# Background image
BG_IMAGE = BASE_DIR / r"C:\Users\vedav\Desktop\networkintrusion project\730996ef-3b9e-41cf-b61d-1480c2e99e9a.png"

# Convert image to Base64
with open(BG_IMAGE, "rb") as img_file:
    encoded_image = base64.b64encode(img_file.read()).decode()

# Page configuration
st.set_page_config(
    page_title="SENTINEL AI | Network Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown(
    f"""
    <style>
    [data-testid="stAppViewContainer"] {{
        background:
            linear-gradient(
                rgba(0, 10, 25, 0.45),
                rgba(0, 10, 25, 0.45)
            ),
            url("data:image/png;base64,{encoded_image}");

        background-size: cover !important;
        background-position: center !important;
        background-repeat: no-repeat !important;
        background-attachment: fixed !important;
    }}

    [data-testid="stHeader"] {{
        background: transparent !important;
    }}

    </style>
    """,
    unsafe_allow_html=True)
# ==========================================================
# SENTINEL AI - 19 INPUT FEATURES
# ==========================================================

st.set_page_config(
    page_title="SENTINEL AI | Network Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "network_intrusion_best_model.joblib"

st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top right,#052451 0%,#00132e 42%,#000817 100%);
    color:#f4f8ff;
}
header[data-testid="stHeader"] {background:transparent;}
#MainMenu,footer {visibility:hidden;}
.block-container {max-width:1500px;padding-top:1rem;padding-bottom:.5rem;}
.hero {
    background:linear-gradient(110deg,#031632,#063d78);
    border:2px solid #009dff;border-radius:16px;
    padding:15px 25px;display:flex;align-items:center;gap:20px;margin-bottom:12px;
}
.hero-icon {font-size:52px;}
.hero-title {color:white;font-size:38px;font-weight:800;line-height:1.2;}
.hero-subtitle {color:#b9d9ff;font-size:15px;margin-top:3px;}
.intro {background:rgba(3,28,61,.85);border:1px solid #007bd5;
    border-radius:13px;padding:11px 17px;margin-bottom:11px;}
.intro h3 {color:white;margin:0;font-size:21px;}
.intro p {color:#d1e5ff;margin:3px 0 0;font-size:14px;}
div[data-testid="stVerticalBlockBorderWrapper"] {
    background:rgba(2,22,49,.82);border:1px solid #007bd5;
    border-radius:13px;padding:10px 12px;
}
.section-heading {font-size:17px;font-weight:750;color:white;
    padding-bottom:6px;border-bottom:2px solid #00c8ef;margin-bottom:9px;}
.stNumberInput label,.stSelectbox label {color:#dceaff !important;font-size:12px !important;}
.stNumberInput input,.stSelectbox div[data-baseweb="select"] > div {
    background-color:#001e46 !important;color:white !important;
    border:1px solid #006cc4 !important;border-radius:7px !important;
}
.stFormSubmitButton button {
    width:100%;min-height:62px;background:linear-gradient(110deg,#008cc9,#1748ef);
    color:white !important;border:1px solid #00d8ff;border-radius:9px;
    font-size:16px;font-weight:800;
}
.stFormSubmitButton button:hover {box-shadow:0 0 15px #007fff;border-color:#00eaff;}
.result-card {background:rgba(2,22,49,.95);border:1px solid #007bd5;
    border-radius:13px;padding:13px 16px;margin-top:10px;}
.result-normal {background:linear-gradient(110deg,#003e36,#002a30);
    border:1px solid #00db91;border-radius:9px;padding:13px;color:#50ffc0;min-height:88px;}
.result-attack {background:linear-gradient(110deg,#50151c,#29101e);
    border:1px solid #ff425b;border-radius:9px;padding:13px;color:#ff7587;min-height:88px;}
.result-label {color:#b8d9ff;font-size:13px;}
.result-value {color:#19dfff;font-size:20px;font-weight:800;margin-top:4px;}
.footer {text-align:center;color:#a8c8ed;font-size:11px;margin-top:10px;line-height:1.7;}
div[data-testid="stVerticalBlock"] {gap:.55rem;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <div class="hero-icon">🛡️</div>
  <div>
    <div class="hero-title">NETWORK INTRUSION DETECTION SYSTEM</div>
    <div class="hero-subtitle">Machine Learning-Based Traffic Classification and Threat Analysis</div>
  </div>
</div>
<div class="intro">
  <h3>Analyze Network Traffic</h3>
  <p>Provide key connection and host statistics to classify network activity as normal or anomalous.</p>
</div>
""", unsafe_allow_html=True)


# ==========================================================
# LOAD MODEL
# ==========================================================

@st.cache_resource
def load_model():
    saved = joblib.load(MODEL_PATH)
    if isinstance(saved, dict):
        return saved["pipeline"], saved.get("model_name", "Random Forest"), saved.get("feature_count", 25)
    return saved, "Random Forest", 25

model = None
model_name = "Random Forest"
feature_count = 25

try:
    if MODEL_PATH.exists():
        model, model_name, feature_count = load_model()
    else:
        st.error("Model file not found. Put network_intrusion_best_model.joblib beside app.py.")
except Exception as e:
    st.error(f"Model loading failed: {e}")


# ==========================================================
# INPUT HELPER FUNCTIONS
# ==========================================================

def num(label, key, default=0, maximum=100000000, is_rate=False):
    if is_rate:
        return st.number_input(
            label,
            min_value=0.0,
            max_value=1.0,
            value=float(default),
            step=0.01,
            format="%.2f",
            key=key
        )

    return st.number_input(
        label,
        min_value=0,
        max_value=maximum,
        value=int(default),
        step=1,
        key=key
    )


def choose(label, options, key, default):
    return st.selectbox(label, options, index=options.index(default), key=key)


# ==========================================================
# 19 INPUT FEATURES - ORIGINAL LAYOUT RETAINED
# ==========================================================

v = {}

with st.form("sentinel_19_input_form"):

    c1, c2, c3 = st.columns([1.05, 1.05, 1.05])

    # ------------------------------------------------------
    # CONNECTION PROFILE
    # ------------------------------------------------------

    with c1:
        with st.container(border=True):

            st.markdown(
                '<div class="section-heading">1 · Connection Profile</div>',
                unsafe_allow_html=True
            )

            v["protocol_type"] = choose(
                "Protocol Type",
                ["tcp", "udp", "icmp"],
                "protocol_type",
                "tcp"
            )

            v["service"] = choose(
                "Service",
                [
                    "http", "private", "domain_u", "smtp",
                    "ftp_data", "eco_i", "other", "ecr_i",
                    "telnet", "finger", "ftp", "auth",
                    "Z39_50", "uucp", "courier", "bgp",
                    "ldap", "imap4", "pop_3", "domain",
                    "ssh", "time", "whois", "gopher",
                    "IRC", "ntp_u", "remote_job", "red_i",
                    "X11", "urh_i", "tftp_u"
                ],
                "service",
                "http"
            )

            v["flag"] = choose(
                "Flag",
                [
                    "SF", "S0", "REJ", "RSTR", "RSTO",
                    "SH", "S1", "S2", "S3", "OTH", "RSTOS0"
                ],
                "flag",
                "SF"
            )

    # ------------------------------------------------------
    # CONNECTION DETAILS
    # ------------------------------------------------------

    with c2:
        with st.container(border=True):

            st.markdown(
                '<div class="section-heading">2 · Connection Details</div>',
                unsafe_allow_html=True
            )

            v["count"] = num("Count", "count", 2)

            v["srv_count"] = num("Srv Count", "srv_count", 2)

            v["same_srv_rate"] = num(
                "Same Srv Rate",
                "same_srv_rate",
                1,
                is_rate=True
            )

    # ------------------------------------------------------
    # LOGIN & ACCESS
    # ------------------------------------------------------

    with c3:
        with st.container(border=True):

            st.markdown(
                '<div class="section-heading">3 · Login & Access</div>',
                unsafe_allow_html=True
            )

            v["logged_in"] = num(
                "Logged In",
                "logged_in",
                1,
                maximum=1
            )

    # ------------------------------------------------------
    # TRAFFIC BEHAVIOUR
    # ------------------------------------------------------

    c4, c5, c6 = st.columns([1.15, 1.0, 1.05])

    with c4:
        with st.container(border=True):

            st.markdown(
                '<div class="section-heading">4 · Traffic Behaviour</div>',
                unsafe_allow_html=True
            )

            v["serror_rate"] = num(
                "Serror Rate",
                "serror_rate",
                0,
                is_rate=True
            )

            v["srv_serror_rate"] = num(
                "Srv Serror Rate",
                "srv_serror_rate",
                0,
                is_rate=True
            )

            v["rerror_rate"] = num(
                "Rerror Rate",
                "rerror_rate",
                0,
                is_rate=True
            )

            v["srv_rerror_rate"] = num(
                "Srv Rerror Rate",
                "srv_rerror_rate",
                0,
                is_rate=True
            )

    # ------------------------------------------------------
    # HOST STATISTICS
    # ------------------------------------------------------

    with c5:
        with st.container(border=True):

            st.markdown(
                '<div class="section-heading">5 · Host Statistics</div>',
                unsafe_allow_html=True
            )

            v["dst_host_count"] = num(
                "Dst Host Count",
                "dst_host_count",
                10
            )

            v["dst_host_srv_count"] = num(
                "Dst Host Srv Count",
                "dst_host_srv_count",
                10
            )

            v["dst_host_same_srv_rate"] = num(
                "Dst Host Same Srv Rate",
                "dst_host_same_srv_rate",
                1,
                is_rate=True
            )

            v["dst_host_diff_srv_rate"] = num(
                "Dst Host Diff Srv Rate",
                "dst_host_diff_srv_rate",
                0,
                is_rate=True
            )

    with c6:
        with st.container(border=True):

            st.markdown("""
<div class="info-card">
<h4>Automatic Processing</h4>
<ul>
<li>Accepts network traffic parameters.</li>
<li>Performs automatic feature processing.</li>
<li>Generates predictions using the trained machine learning model.</li>
</ul>
</div>
""", unsafe_allow_html=True)
            submitted = st.form_submit_button(
                "🛡️  RUN THREAT ANALYSIS   ➜",
                use_container_width=True
                )

    # ------------------------------------------------------
    # ADDITIONAL HOST STATISTICS
    # Displayed in the same Host Statistics section below
    # ------------------------------------------------------

    st.markdown(
        '<div class="section-heading">Additional Host Statistics</div>',
        unsafe_allow_html=True
    )

    h1, h2, h3, h4 = st.columns(4)

    with h1:
        v["dst_host_serror_rate"] = num(
            "Dst Host Serror Rate",
            "dst_host_serror_rate",
            0,
            is_rate=True
        )

    with h2:
        v["dst_host_srv_serror_rate"] = num(
            "Dst Host Srv Serror Rate",
            "dst_host_srv_serror_rate",
            0,
            is_rate=True
        )

    with h3:
        v["dst_host_rerror_rate"] = num(
            "Dst Host Rerror Rate",
            "dst_host_rerror_rate",
            0,
            is_rate=True
        )

    with h4:
        v["dst_host_srv_rerror_rate"] = num(
            "Dst Host Srv Rerror Rate",
            "dst_host_srv_rerror_rate",
            0,
            is_rate=True
        )


# ==========================================================
# FULL SOURCE FEATURE STRUCTURE
# ==========================================================

RAW_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]


# ==========================================================
# FEATURE ENGINEERING
# ==========================================================

def make_model_row(user_values):

    row = {col: np.nan for col in RAW_COLUMNS}
    row.update(user_values)

    # Total bytes
    if pd.notna(row["src_bytes"]) and pd.notna(row["dst_bytes"]):
        row["total_bytes"] = row["src_bytes"] + row["dst_bytes"]
    else:
        row["total_bytes"] = np.nan

    # Byte ratio
    if pd.notna(row["src_bytes"]) and pd.notna(row["dst_bytes"]):
        row["byte_ratio"] = (
            (row["src_bytes"] + 1) /
            (row["dst_bytes"] + 1)
        )
    else:
        row["byte_ratio"] = np.nan

    # Average error rate
    error_cols = [
        "serror_rate",
        "rerror_rate",
        "srv_serror_rate",
        "srv_rerror_rate"
    ]

    row["avg_error_rate"] = (
        np.mean([row[x] for x in error_cols])
        if all(pd.notna(row[x]) for x in error_cols)
        else np.nan
    )

    # Host error rate
    host_error_cols = [
        "dst_host_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_srv_rerror_rate"
    ]

    row["host_error_rate"] = (
        np.mean([row[x] for x in host_error_cols])
        if all(pd.notna(row[x]) for x in host_error_cols)
        else np.nan
    )

    # Connection count ratio
    row["connection_count_ratio"] = (
        (row["count"] + 1) / (row["srv_count"] + 1)
    )

    df = pd.DataFrame([row])

    return df.drop(
        columns=["urgent", "num_outbound_cmds", "is_host_login"],
        errors="ignore"
    )


# ==========================================================
# PREDICTION
# ==========================================================

if submitted:

    if model is None:

        st.error(
            "The trained model could not be loaded. "
            "Check the model file and scikit-learn version."
        )

    else:

        try:

            model_input = make_model_row(v)

            prediction = int(model.predict(model_input)[0])

            probs = model.predict_proba(model_input)[0]

            classes = list(model.classes_)

            confidence = float(np.max(probs)) * 100

            if 1 in classes:
                anomaly_idx = classes.index(1)
                anomaly_probability = float(probs[anomaly_idx]) * 100
            else:
                anomaly_probability = 0.0

            is_normal = prediction == 0

            st.session_state["pred_label"] = (
                "Normal" if is_normal else "Anomaly"
            )

            st.session_state["is_normal"] = is_normal
            st.session_state["confidence"] = confidence
            st.session_state["anomaly_probability"] = anomaly_probability

        except Exception as e:

            st.error(f"Prediction failed: {e}")


# ==========================================================
# DISPLAY RESULTS
# ==========================================================

if "pred_label" in st.session_state:

    label = st.session_state["pred_label"]
    confidence = st.session_state["confidence"]
    anomaly_probability = st.session_state["anomaly_probability"]

    st.markdown('<div class="result-card">', unsafe_allow_html=True)

    st.markdown("### Prediction Result")

    r1, r2, r3, r4 = st.columns([2.1, 1, 1, 1.45])

    with r1:

        if st.session_state["is_normal"]:

            st.markdown(
                '<div class="result-normal"><h4>🟢 NORMAL TRAFFIC</h4>The connection was classified as normal by the trained model.</div>',
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                '<div class="result-attack"><h4>🚨 ANOMALOUS TRAFFIC</h4>The connection was classified as anomalous by the trained model.</div>',
                unsafe_allow_html=True
            )

    with r2:

        st.markdown(
            f'<div class="result-card"><div class="result-label">Prediction</div><div class="result-value">{label}</div></div>',
            unsafe_allow_html=True
        )

    with r3:

        st.markdown(
            f'<div class="result-card"><div class="result-label">Model</div><div class="result-value">{model_name}</div></div>',
            unsafe_allow_html=True
        )

    with r4:

        st.markdown(
            f'<div class="result-card"><div class="result-label">Confidence</div><div class="result-value">{confidence:.2f}%</div></div>',
            unsafe_allow_html=True
        )

    st.markdown(
    f"""
    <div style="
        margin-top: 5px;
        margin-left: 0px;
        color: #b8cce5;
        font-size: 12px;
        font-weight: 500;
        letter-spacing: 0.2px;
    ">
        <span style="color: #55d6ff;">●</span>
        Anomaly Probability: <b>{anomaly_probability:.2f}%</b>
    </div>
    """,
    unsafe_allow_html=True
)

    st.markdown("</div>", unsafe_allow_html=True)


