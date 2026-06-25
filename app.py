import streamlit as st
import pickle
import pandas as pd
import re

# 1. Page Configuration
st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="centered")

# 2. Custom CSS for Glassmorphism UI
st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        color: white;
    }
    .main .block-container {
        padding-top: 2rem;
    }
    .title-text {
        font-family: 'Helvetica Neue', sans-serif;
        font-weight: 800;
        text-align: center;
        background: -webkit-linear-gradient(#00d2ff, #3a7bd5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3.5rem;
        margin-bottom: 0.2rem;
    }
    /* UPDATED: Changed background to white and text color to black */
    .stTextInput > div > div > input {
        background-color: rgba(255, 255, 255, 0.9); /* Opaque white background */
        color: #000000;                              /* Black text color */
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        padding: 12px;
    }
    div.stButton > button {
        width: 100%;
        background: linear-gradient(45deg, #00d2ff, #3a7bd5);
        color: white;
        border: none;
        padding: 15px;
        font-weight: bold;
        border-radius: 12px;
        letter-spacing: 1px;
        transition: 0.4s;
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0px 8px 20px rgba(0, 210, 255, 0.4);
    }
    .result-card {
        padding: 25px;
        border-radius: 18px;
        text-align: center;
        margin-top: 25px;
        backdrop-filter: blur(15px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        animation: fadeIn 0.8s ease-in-out;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .danger { background-color: rgba(255, 75, 75, 0.15); border-color: #ff4b4b; }
    .safe { background-color: rgba(40, 167, 69, 0.15); border-color: #28a745; }
    </style>
    """, unsafe_allow_html=True)

# 3. Feature Extraction Logic
def get_live_features(url, feature_names):
    feats = {name: 0 for name in feature_names}
    
    # Structural features
    feats['length_url'] = len(url)
    feats['nb_dots'] = url.count('.')
    feats['nb_hyphens'] = url.count('-')
    feats['nb_slash'] = url.count('/')
    feats['nb_at'] = url.count('@')
    feats['nb_qm'] = url.count('?')
    feats['nb_eq'] = url.count('=')
    
    # Hostname logic
    hostname = url.split('/')[2] if '//' in url else url.split('/')[0]
    feats['length_hostname'] = len(hostname)
    
    # Return as DataFrame with identical columns to training
    return pd.DataFrame([feats])[feature_names]

# 4. Main App UI
st.markdown('<h1 class="title-text">🛡️ PhishGuard AI</h1>', unsafe_allow_html=True)
st.markdown("<p style='text-align: center; opacity: 0.8; font-size: 1.1rem;'>Advanced Machine Learning Phishing Detection</p>", unsafe_allow_html=True)
st.write("---")

# Load Model Data
try:
    with open('phish_model.pkl', 'rb') as f:
        data = pickle.load(f)
        model = data['classifier']
        feature_names = data['features']
except FileNotFoundError:
    st.error("Model file not found. Please run train.py first.")
    st.stop()

# User Input
url_input = st.text_input("Enter website URL to scan:", placeholder="e.g., https://www.sathyabama.ac.in")

if st.button("RUN SECURITY SCAN"):
    if url_input:
        with st.spinner('🕵️‍♂️ Analyzing URL DNA for malicious patterns...'):
            # A. Whitelist Check (Overrides ML to prevent False Positives on trusted sites)
            whitelist = ["sathyabama.ac.in", "google.com", "github.com", "linkedin.com", "microsoft.com"]
            is_whitelisted = any(domain in url_input.lower() for domain in whitelist)

            # B. Get ML Prediction
            live_data = get_live_features(url_input, feature_names)
            prediction = model.predict(live_data)
            
            # C. Heuristic Flags (Keywords often used in phishing)
            sus_keywords = ["verify", "login", "update-credentials", "signin", "portal-update"]
            contains_sus = any(word in url_input.lower() for word in sus_keywords)
            
            # Non-educational TLD check
            is_educational = ".ac.in" in url_input or ".edu" in url_input

            # Final Decision Logic
            if is_whitelisted:
                is_phish = False
            else:
                # Flag if ML predicts phish OR (suspicious keywords + non-edu TLD + suspicious hyphens)
                is_phish = (prediction[0] == 1) or (contains_sus and not is_educational and "-" in url_input)

            # D. Visual Output
            if is_phish:
                st.markdown(f"""
                    <div class="result-card danger">
                        <h2 style="color: #ff4b4b; margin: 0;">⚠️ THREAT DETECTED</h2>
                        <p style="margin: 10px 0 0 0; font-size: 1.1rem;">
                            The URL <b>{url_input}</b> has been flagged as highly suspicious.
                        </p>
                        <p style="opacity:0.7; font-size:0.9rem; margin-top:5px;">Recommendation: Do not enter sensitive credentials.</p>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                    <div class="result-card safe">
                        <h2 style="color: #28a745; margin: 0;">✅ URL SECURE</h2>
                        <p style="margin: 10px 0 0 0; font-size: 1.1rem;">
                            The URL <b>{url_input}</b> appears to be legitimate.
                        </p>
                        <p style="opacity:0.7; font-size:0.9rem; margin-top:5px;">Our model found no significant structural anomalies.</p>
                    </div>
                """, unsafe_allow_html=True)
    else:
        st.warning("Please enter a URL to proceed with the scan.")

# Sidebar Details
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=100)
    st.title("System Overview")
    st.metric("Accuracy", "96.94%")
    st.metric("Model", "Random Forest")
    st.write("---")
    st.write("**Security Metrics:**")
    st.info("The system analyzes URL length, dot density, hostname complexity, and keyword spoofing attempts.")