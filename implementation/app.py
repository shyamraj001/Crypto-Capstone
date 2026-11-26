"""
Innovative Hybrid Cryptographic File Protection and Integrity Verification
Main Streamlit Application
"""

import sys
import os
import socket
import streamlit as st
import pandas as pd

# Ensure current project directory is on path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

import database
import crypto_engine
from modules.module1_auth import render_module1
from modules.module2_encryption import render_send_file
from modules.module4_transfer import render_receive_file
from modules.module3_integrity import render_security_monitoring
from modules.manual import render_user_manual


def get_lan_ip() -> str:
    """Returns the local network IPv4 address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


# Initialize Database Schema & Seed Data
database.init_db()

# Streamlit Page Configuration
st.set_page_config(
    page_title="Innovative Hybrid Cryptographic File Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def inject_theme_css(is_dark: bool):
    """Injects comprehensive, pixel-perfect CSS for both Dark and Light themes."""
    if is_dark:
        # =====================================================================
        # DARK MODE STYLES
        # =====================================================================
        css = """
        <style>
            /* 1. App Body & Main Canvas */
            .stApp, [data-testid="stAppViewContainer"], .main {
                background-color: #0b0f19 !important;
                color: #f1f5f9 !important;
                font-family: 'Inter', system-ui, -apple-system, sans-serif;
            }
            .stApp p, .stApp span, .stApp div, .stApp label, .stApp li {
                color: #f1f5f9;
            }

            /* 2. Top Streamlit Header Bar (Fixes the light/white bar at the top) */
            header[data-testid="stHeader"], [data-testid="stHeader"], .stAppHeader {
                background-color: #0b0f19 !important;
                background: #0b0f19 !important;
                color: #f1f5f9 !important;
                border-bottom: 1px solid #1e293b !important;
            }
            header[data-testid="stHeader"] *, [data-testid="stHeader"] * {
                color: #f1f5f9 !important;
                fill: #f1f5f9 !important;
            }
            [data-testid="stDecoration"] {
                display: none !important;
            }

            /* 3. Sidebar (Fixes the light/white sidebar completely) */
            section[data-testid="stSidebar"], 
            [data-testid="stSidebar"], 
            [data-testid="stSidebarContent"], 
            [data-testid="stSidebarUserContent"], 
            section[data-testid="stSidebar"] > div,
            .stSidebar, 
            div[data-testid="stSidebar"] {
                background-color: #0d1322 !important;
                background: #0d1322 !important;
                border-right: 1px solid #1e293b !important;
            }
            section[data-testid="stSidebar"] *, 
            [data-testid="stSidebar"] * {
                color: #f1f5f9 !important;
            }
            section[data-testid="stSidebar"] p, 
            [data-testid="stSidebar"] p,
            section[data-testid="stSidebar"] span, 
            [data-testid="stSidebar"] span {
                color: #cbd5e1 !important;
            }
            section[data-testid="stSidebar"] h1, 
            section[data-testid="stSidebar"] h2, 
            section[data-testid="stSidebar"] h3, 
            section[data-testid="stSidebar"] h4 {
                color: #ffffff !important;
            }

            /* Sidebar Radio Labels & Text */
            section[data-testid="stSidebar"] div[role="radiogroup"] label span,
            section[data-testid="stSidebar"] label[data-baseweb="radio"] span,
            section[data-testid="stSidebar"] label p,
            section[data-testid="stSidebar"] label span,
            section[data-testid="stSidebar"] div[data-testid="stRadio"] * {
                color: #f1f5f9 !important;
                font-weight: 500 !important;
            }
            section[data-testid="stSidebar"] button * {
                color: #f1f5f9 !important;
                fill: #f1f5f9 !important;
            }

            /* 4. Top Main Header Banner */
            .main-header {
                background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%) !important;
                border: 1px solid #1e293b !important;
                padding: 1.4rem 1.8rem;
                border-radius: 12px;
                box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
                margin-bottom: 1.5rem;
            }
            .main-title {
                font-weight: 800;
                font-size: 1.7rem;
                letter-spacing: -0.02em;
                margin: 0;
                background: linear-gradient(90deg, #60a5fa, #a78bfa, #34d399) !important;
                -webkit-background-clip: text !important;
                -webkit-text-fill-color: transparent !important;
            }
            .sub-title {
                color: #94a3b8 !important;
                font-size: 0.92rem;
                margin-top: 0.3rem;
            }

            /* 5. Metrics Cards (Fixes invisible labels in dark mode) */
            [data-testid="stMetric"] {
                background: #111827 !important;
                border: 1px solid #1f2937 !important;
                border-radius: 10px !important;
                padding: 0.9rem 1.1rem !important;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
            }
            [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] * {
                color: #94a3b8 !important;
                font-size: 0.85rem !important;
                font-weight: 600 !important;
                text-transform: uppercase !important;
                letter-spacing: 0.04em !important;
            }
            [data-testid="stMetricValue"], [data-testid="stMetricValue"] * {
                color: #38bdf8 !important;
                font-size: 1.8rem !important;
                font-weight: 700 !important;
                font-family: monospace !important;
            }

            /* 6. Badges */
            .badge-container {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                margin-top: 8px;
            }
            .crypto-badge {
                display: inline-block;
                font-size: 0.72rem;
                font-weight: 600;
                padding: 3px 9px;
                border-radius: 6px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }
            .badge-aes { background: rgba(59, 130, 246, 0.2) !important; color: #60a5fa !important; border: 1px solid rgba(59, 130, 246, 0.4) !important; }
            .badge-rsa { background: rgba(139, 92, 246, 0.2) !important; color: #a78bfa !important; border: 1px solid rgba(139, 92, 246, 0.4) !important; }
            .badge-sha { background: rgba(16, 185, 129, 0.2) !important; color: #34d399 !important; border: 1px solid rgba(16, 185, 129, 0.4) !important; }
            .badge-db  { background: rgba(245, 158, 11, 0.2) !important; color: #fbbf24 !important; border: 1px solid rgba(245, 158, 11, 0.4) !important; }

            /* 7. Universal Content Cards */
            .crypto-card {
                background: #111827 !important;
                border: 1px solid #1f2937 !important;
                border-radius: 10px !important;
                padding: 1.2rem;
                color: #f8fafc !important;
            }
            .crypto-card h4 {
                color: #60a5fa !important;
                margin: 0 0 0.4rem 0;
            }
            .crypto-card p {
                color: #94a3b8 !important;
                font-size: 0.88rem;
                line-height: 1.5;
            }
            .crypto-card-secondary {
                background: #1e293b !important;
                border: 1px solid #334155 !important;
                border-radius: 8px !important;
                padding: 0.9rem;
                color: #f1f5f9 !important;
                font-size: 0.88rem;
                line-height: 1.6;
            }
            .crypto-card-secondary b {
                color: #f8fafc !important;
            }

            /* 8. Banners */
            .crypto-banner {
                padding: 1.4rem;
                border-radius: 12px;
                margin-bottom: 1.5rem;
            }
            .crypto-banner h2 {
                margin: 0;
                color: #f8fafc !important;
                font-size: 1.5rem;
            }
            .crypto-banner p {
                margin: 0.3rem 0 0 0;
                color: #94a3b8 !important;
                font-size: 0.95rem;
            }
            .crypto-banner-home {
                background: linear-gradient(135deg, #1e293b, #0f172a) !important;
                border-left: 5px solid #3b82f6 !important;
            }
            .crypto-banner-auth {
                background: linear-gradient(135deg, #1e293b, #0f172a) !important;
                border-left: 5px solid #3b82f6 !important;
            }
            .crypto-banner-send {
                background: linear-gradient(135deg, #1e1b4b, #0f172a) !important;
                border-left: 5px solid #8b5cf6 !important;
            }
            .crypto-banner-send p { color: #cbd5e1 !important; }
            .crypto-banner-recv {
                background: linear-gradient(135deg, #1e3a8a, #0f172a) !important;
                border-left: 5px solid #2563eb !important;
            }
            .crypto-banner-recv p { color: #bfdbfe !important; }
            .crypto-banner-sec {
                background: linear-gradient(135deg, #064e3b, #0f172a) !important;
                border-left: 5px solid #10b981 !important;
            }
            .crypto-banner-sec p { color: #a7f3d0 !important; }
            .crypto-banner-manual {
                background: linear-gradient(135deg, #0f172a, #1e293b) !important;
                border-left: 5px solid #06b6d4 !important;
            }

            /* 9. Sidebar User Card & Access Points */
            .crypto-sidebar-user {
                background: #111827 !important;
                border-radius: 8px !important;
                padding: 0.75rem !important;
                margin-bottom: 0.8rem !important;
                border: 1px solid #1f2937 !important;
            }
            .crypto-sidebar-user .user-warning-title {
                color: #f59e0b !important;
                font-weight: bold;
                font-size: 0.75rem;
                margin-bottom: 3px;
            }
            .crypto-sidebar-user .user-warning-sub {
                color: #cbd5e1 !important;
                font-size: 0.78rem;
                line-height: 1.4;
            }
            .crypto-sidebar-user .user-active-label {
                font-size: 0.72rem;
                color: #94a3b8 !important;
                text-transform: uppercase;
            }
            .crypto-sidebar-user .user-active-name {
                font-weight: bold;
                font-size: 0.95rem;
                color: #f8fafc !important;
            }
            .crypto-sidebar-user .user-active-uname {
                font-size: 0.82rem;
                color: #38bdf8 !important;
                font-weight: 600;
            }

            .crypto-sidebar-access {
                background: rgba(16, 185, 129, 0.1) !important;
                border: 1px solid rgba(16, 185, 129, 0.3) !important;
                border-radius: 8px !important;
                padding: 0.65rem !important;
                margin-top: 1rem !important;
            }
            .crypto-sidebar-access * {
                color: #a7f3d0 !important;
            }
            .crypto-sidebar-access code {
                background: #0f172a !important;
                color: #34d399 !important;
                border: 1px solid rgba(16, 185, 129, 0.3) !important;
            }

            /* 10. Alerts */
            .crypto-alert-red {
                background: #450a0a !important;
                color: #fecaca !important;
                border: 3px solid #ef4444 !important;
                border-radius: 12px !important;
                padding: 1.8rem !important;
                margin: 1.5rem 0 !important;
                box-shadow: 0 10px 25px rgba(239, 68, 68, 0.35) !important;
            }
            .crypto-alert-red h2 { color: #f87171 !important; }
            .crypto-alert-red h4 { color: #fca5a5 !important; }
            .crypto-alert-red p, .crypto-alert-red li, .crypto-alert-red b { color: #fecaca !important; }
            .crypto-alert-red-inner {
                background: rgba(0, 0, 0, 0.5) !important;
                border-left: 5px solid #ef4444 !important;
                color: #fee2e2 !important;
                padding: 1rem !important;
                border-radius: 8px !important;
                margin: 1rem 0 !important;
            }

            .crypto-alert-green {
                background: #064e3b !important;
                color: #ecfdf5 !important;
                border: 3px solid #10b981 !important;
                border-radius: 12px !important;
                padding: 1.8rem !important;
                margin: 1.5rem 0 !important;
                box-shadow: 0 10px 25px rgba(16, 185, 129, 0.25) !important;
            }
            .crypto-alert-green h2 { color: #34d499 !important; }
            .crypto-alert-green h4 { color: #6ee7b7 !important; }
            .crypto-alert-green p, .crypto-alert-green li, .crypto-alert-green b { color: #d1fae5 !important; }

            /* 11. Code & Inputs */
            code {
                background: rgba(15, 23, 42, 0.8) !important;
                color: #38bdf8 !important;
                padding: 2px 6px !important;
                border-radius: 4px !important;
                border: 1px solid #334155 !important;
            }
            .sidebar-brand-title {
                color: #ffffff !important;
                font-size: 1.15rem;
                margin: 0.3rem 0 0 0;
                font-weight: 700;
            }
            .sidebar-brand-sub {
                color: #94a3b8 !important;
                font-size: 0.78rem;
                margin: 0;
            }
        </style>
        """
    else:
        # =====================================================================
        # LIGHT MODE STYLES
        # =====================================================================
        css = """
        <style>
            /* 1. App Body & Main Canvas */
            .stApp, [data-testid="stAppViewContainer"], .main {
                background-color: #f8fafc !important;
                color: #0f172a !important;
                font-family: 'Inter', system-ui, -apple-system, sans-serif;
            }
            .stApp p, .stApp span, .stApp div, .stApp label, .stApp li {
                color: #0f172a;
            }

            /* 2. Top Streamlit Header Bar */
            header[data-testid="stHeader"], [data-testid="stHeader"], .stAppHeader {
                background-color: #f8fafc !important;
                background: #f8fafc !important;
                color: #0f172a !important;
                border-bottom: 1px solid #e2e8f0 !important;
            }
            header[data-testid="stHeader"] *, [data-testid="stHeader"] * {
                color: #0f172a !important;
                fill: #0f172a !important;
            }
            [data-testid="stDecoration"] {
                display: none !important;
            }

            /* 3. Sidebar */
            section[data-testid="stSidebar"], 
            [data-testid="stSidebar"], 
            [data-testid="stSidebarContent"], 
            [data-testid="stSidebarUserContent"], 
            section[data-testid="stSidebar"] > div,
            .stSidebar, 
            div[data-testid="stSidebar"] {
                background-color: #ffffff !important;
                background: #ffffff !important;
                border-right: 1px solid #e2e8f0 !important;
            }
            section[data-testid="stSidebar"] *, 
            [data-testid="stSidebar"] * {
                color: #0f172a !important;
            }
            section[data-testid="stSidebar"] p, 
            [data-testid="stSidebar"] p,
            section[data-testid="stSidebar"] span, 
            [data-testid="stSidebar"] span {
                color: #334155 !important;
            }
            section[data-testid="stSidebar"] h1, 
            section[data-testid="stSidebar"] h2, 
            section[data-testid="stSidebar"] h3, 
            section[data-testid="stSidebar"] h4 {
                color: #0f172a !important;
            }

            /* Sidebar Radio Labels & Text in Light Mode */
            section[data-testid="stSidebar"] div[role="radiogroup"] label span,
            section[data-testid="stSidebar"] label[data-baseweb="radio"] span,
            section[data-testid="stSidebar"] label p,
            section[data-testid="stSidebar"] label span,
            section[data-testid="stSidebar"] div[data-testid="stRadio"] * {
                color: #0f172a !important;
                font-weight: 600 !important;
            }
            section[data-testid="stSidebar"] button * {
                color: #0f172a !important;
                fill: #0f172a !important;
            }

            /* 4. Top Main Header Banner */
            .main-header {
                background: linear-gradient(135deg, #ffffff 0%, #f0fdf4 40%, #eff6ff 100%) !important;
                border: 1px solid #cbd5e1 !important;
                padding: 1.4rem 1.8rem;
                border-radius: 12px;
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.05);
                margin-bottom: 1.5rem;
            }
            .main-title {
                font-weight: 800;
                font-size: 1.7rem;
                letter-spacing: -0.02em;
                margin: 0;
                background: linear-gradient(90deg, #1d4ed8, #6d28d9, #047857) !important;
                -webkit-background-clip: text !important;
                -webkit-text-fill-color: transparent !important;
            }
            .sub-title {
                color: #475569 !important;
                font-size: 0.92rem;
                margin-top: 0.3rem;
                font-weight: 500;
            }

            /* 5. Metrics Cards */
            [data-testid="stMetric"] {
                background: #ffffff !important;
                border: 1px solid #e2e8f0 !important;
                border-radius: 10px !important;
                padding: 0.9rem 1.1rem !important;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04) !important;
            }
            [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] * {
                color: #475569 !important;
                font-size: 0.85rem !important;
                font-weight: 700 !important;
                text-transform: uppercase !important;
                letter-spacing: 0.04em !important;
            }
            [data-testid="stMetricValue"], [data-testid="stMetricValue"] * {
                color: #0284c7 !important;
                font-size: 1.8rem !important;
                font-weight: 700 !important;
                font-family: monospace !important;
            }

            /* 6. Badges */
            .badge-container {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                margin-top: 8px;
            }
            .crypto-badge {
                display: inline-block;
                font-size: 0.72rem;
                font-weight: 700;
                padding: 3px 9px;
                border-radius: 6px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }
            .badge-aes { background: #dbeafe !important; color: #1e40af !important; border: 1px solid #93c5fd !important; }
            .badge-rsa { background: #f3e8ff !important; color: #6b21a8 !important; border: 1px solid #d8b4fe !important; }
            .badge-sha { background: #dcfce7 !important; color: #15803d !important; border: 1px solid #86efac !important; }
            .badge-db  { background: #fef3c7 !important; color: #92400e !important; border: 1px solid #fcd34d !important; }

            /* 7. Universal Content Cards */
            .crypto-card {
                background: #ffffff !important;
                border: 1px solid #e2e8f0 !important;
                border-radius: 10px !important;
                padding: 1.2rem;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.04);
                color: #0f172a !important;
            }
            .crypto-card h4 {
                color: #1d4ed8 !important;
                margin: 0 0 0.4rem 0;
                font-weight: 700;
            }
            .crypto-card p {
                color: #334155 !important;
                font-size: 0.88rem;
                line-height: 1.5;
            }
            .crypto-card-secondary {
                background: #f8fafc !important;
                border: 1px solid #cbd5e1 !important;
                border-radius: 8px !important;
                padding: 0.9rem;
                color: #0f172a !important;
                font-size: 0.88rem;
                line-height: 1.6;
            }
            .crypto-card-secondary b {
                color: #0f172a !important;
            }

            /* 8. Banners */
            .crypto-banner {
                padding: 1.4rem;
                border-radius: 12px;
                margin-bottom: 1.5rem;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.03);
            }
            .crypto-banner h2 {
                margin: 0;
                font-size: 1.5rem;
                font-weight: 700;
            }
            .crypto-banner p {
                margin: 0.3rem 0 0 0;
                font-size: 0.95rem;
                font-weight: 500;
            }
            .crypto-banner-home {
                background: linear-gradient(135deg, #eff6ff, #f8fafc) !important;
                border: 1px solid #dbeafe !important;
                border-left: 6px solid #2563eb !important;
            }
            .crypto-banner-home h2 { color: #1e3a8a !important; }
            .crypto-banner-home p { color: #2563eb !important; }
            .crypto-banner-auth {
                background: linear-gradient(135deg, #eff6ff, #f8fafc) !important;
                border: 1px solid #dbeafe !important;
                border-left: 6px solid #2563eb !important;
            }
            .crypto-banner-auth h2 { color: #1e3a8a !important; }
            .crypto-banner-auth p { color: #2563eb !important; }
            .crypto-banner-send {
                background: linear-gradient(135deg, #faf5ff, #f8fafc) !important;
                border: 1px solid #ede9fe !important;
                border-left: 6px solid #7c3aed !important;
            }
            .crypto-banner-send h2 { color: #581c87 !important; }
            .crypto-banner-send p { color: #6b21a8 !important; }
            .crypto-banner-recv {
                background: linear-gradient(135deg, #f0f9ff, #f8fafc) !important;
                border: 1px solid #e0f2fe !important;
                border-left: 6px solid #0284c7 !important;
            }
            .crypto-banner-recv h2 { color: #075985 !important; }
            .crypto-banner-recv p { color: #0284c7 !important; }
            .crypto-banner-sec {
                background: linear-gradient(135deg, #f0fdf4, #f8fafc) !important;
                border: 1px solid #d1fae5 !important;
                border-left: 6px solid #059669 !important;
            }
            .crypto-banner-sec h2 { color: #065f46 !important; }
            .crypto-banner-sec p { color: #047857 !important; }
            .crypto-banner-manual {
                background: linear-gradient(135deg, #ecfeff, #f8fafc) !important;
                border: 1px solid #cffafe !important;
                border-left: 6px solid #0891b2 !important;
            }
            .crypto-banner-manual h2 { color: #155e75 !important; }
            .crypto-banner-manual p { color: #0e7490 !important; }

            /* 9. Sidebar User Card & Access Points */
            .crypto-sidebar-user {
                background: #f8fafc !important;
                border-radius: 8px !important;
                padding: 0.75rem !important;
                margin-bottom: 0.8rem !important;
                border: 1px solid #cbd5e1 !important;
            }
            .crypto-sidebar-user .user-warning-title {
                color: #b45309 !important;
                font-weight: bold;
                font-size: 0.75rem;
                margin-bottom: 3px;
            }
            .crypto-sidebar-user .user-warning-sub {
                color: #475569 !important;
                font-size: 0.78rem;
                line-height: 1.4;
            }
            .crypto-sidebar-user .user-active-label {
                font-size: 0.72rem;
                color: #475569 !important;
                text-transform: uppercase;
            }
            .crypto-sidebar-user .user-active-name {
                font-weight: bold;
                font-size: 0.95rem;
                color: #0f172a !important;
            }
            .crypto-sidebar-user .user-active-uname {
                font-size: 0.82rem;
                color: #0284c7 !important;
                font-weight: 600;
            }

            .crypto-sidebar-access {
                background: #f0fdf4 !important;
                border: 1px solid #86efac !important;
                border-radius: 8px !important;
                padding: 0.65rem !important;
                margin-top: 1rem !important;
            }
            .crypto-sidebar-access * {
                color: #166534 !important;
            }
            .crypto-sidebar-access code {
                background: #ffffff !important;
                color: #15803d !important;
                border: 1px solid #86efac !important;
            }

            /* 10. Alerts */
            .crypto-alert-red {
                background: #fff1f2 !important;
                color: #881337 !important;
                border: 3px solid #e11d48 !important;
                border-radius: 12px !important;
                padding: 1.8rem !important;
                margin: 1.5rem 0 !important;
                box-shadow: 0 8px 24px rgba(225, 29, 72, 0.12) !important;
            }
            .crypto-alert-red h2 { color: #be123c !important; }
            .crypto-alert-red h4 { color: #9f1239 !important; }
            .crypto-alert-red p, .crypto-alert-red li, .crypto-alert-red b { color: #881337 !important; }
            .crypto-alert-red-inner {
                background: #ffe4e6 !important;
                border-left: 5px solid #e11d48 !important;
                color: #881337 !important;
                padding: 1rem !important;
                border-radius: 8px !important;
                margin: 1rem 0 !important;
            }

            .crypto-alert-green {
                background: #f0fdf4 !important;
                color: #14532d !important;
                border: 3px solid #16a34a !important;
                border-radius: 12px !important;
                padding: 1.8rem !important;
                margin: 1.5rem 0 !important;
                box-shadow: 0 8px 24px rgba(22, 163, 74, 0.12) !important;
            }
            .crypto-alert-green h2 { color: #15803d !important; }
            .crypto-alert-green h4 { color: #166534 !important; }
            .crypto-alert-green p, .crypto-alert-green li, .crypto-alert-green b { color: #14532d !important; }

            /* 11. Code & Inputs */
            code {
                background: #f1f5f9 !important;
                color: #0369a1 !important;
                padding: 2px 6px !important;
                border-radius: 4px !important;
                border: 1px solid #cbd5e1 !important;
            }
            .stTextInput input, .stTextArea textarea, div[data-baseweb="select"] {
                background-color: #ffffff !important;
                color: #0f172a !important;
                border: 1px solid #cbd5e1 !important;
            }
            div[data-testid="stExpander"] {
                background-color: #ffffff !important;
                border: 1px solid #e2e8f0 !important;
                border-radius: 8px !important;
            }
            .sidebar-brand-title {
                color: #0f172a !important;
                font-size: 1.15rem;
                margin: 0.3rem 0 0 0;
                font-weight: 700;
            }
            .sidebar-brand-sub {
                color: #475569 !important;
                font-size: 0.78rem;
                margin: 0;
            }
        </style>
        """
    st.markdown(css, unsafe_allow_html=True)


def render_sidebar():
    st.sidebar.markdown("""
    <div style="text-align: center; padding: 0.8rem 0;">
        <span style="font-size: 2.8rem;">🛡️</span>
        <h3 class="sidebar-brand-title">Hybrid Cryptosystem</h3>
        <p class="sidebar-brand-sub">File Protection & Integrity Verification</p>
    </div>
    """, unsafe_allow_html=True)

    # 🌓 Theme Switcher
    if "theme_mode" not in st.session_state:
        st.session_state["theme_mode"] = "🌙 Dark Mode"

    st.sidebar.markdown("<div style='font-size: 0.78rem; font-weight: bold; margin-bottom: 4px;'>🌓 DISPLAY THEME:</div>", unsafe_allow_html=True)
    selected_theme = st.sidebar.radio(
        "Display Theme",
        options=["🌙 Dark Mode", "☀️ Light Mode"],
        index=0 if st.session_state.get("theme_mode", "🌙 Dark Mode") == "🌙 Dark Mode" else 1,
        horizontal=True,
        label_visibility="collapsed",
        key="app_theme_switcher"
    )
    if selected_theme != st.session_state["theme_mode"]:
        st.session_state["theme_mode"] = selected_theme
        st.rerun()

    st.sidebar.markdown("---")

    # Active User Status
    if "user" in st.session_state and st.session_state["user"] is not None:
        u = st.session_state["user"]
        st.sidebar.markdown(f"""
        <div class="crypto-sidebar-user">
            <div class="user-active-label">Active User</div>
            <div class="user-active-name">{u['fullname']}</div>
            <div class="user-active-uname">@{u['username']}</div>
        </div>
        """, unsafe_allow_html=True)
        if st.sidebar.button("🚪 Logout Session", use_container_width=True):
            st.session_state["user"] = None
            st.rerun()
    else:
        st.sidebar.markdown("""
        <div class="crypto-sidebar-user">
            <div class="user-warning-title">⚠️ NO USER SIGNED IN</div>
            <div class="user-warning-sub">Log in under User Authentication to send or receive files.</div>
        </div>
        """, unsafe_allow_html=True)

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🧭 Main Navigation")

    # Strict 6 Navigation Options
    navigation_options = [
        "🏠 Home / Dashboard",
        "🔐 User Authentication",
        "📤 Send File",
        "📥 Receive File",
        "🛡️ Security Monitoring",
        "📖 User Manual"
    ]

    selected_nav = st.sidebar.radio(
        "Go to page:",
        options=navigation_options,
        index=0
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚙️ Cryptographic Specifications")
    st.sidebar.markdown("""
    <div class="badge-container">
        <span class="crypto-badge badge-aes">AES-256-GCM</span>
        <span class="crypto-badge badge-rsa">RSA-2048-OAEP</span>
        <span class="crypto-badge badge-rsa">RSA-2048-PSS</span>
        <span class="crypto-badge badge-sha">SHA-256</span>
        <span class="crypto-badge badge-db">SQLite 3</span>
    </div>
    <div style="margin-top: 0.8rem; font-size: 0.75rem; opacity: 0.85;">
        <b>File Encryption:</b> AES-256-GCM<br>
        <b>Key Encapsulation:</b> RSA-2048-OAEP<br>
        <b>Digital Signatures:</b> RSA-2048-PSS<br>
        <b>Integrity Check:</b> SHA-256 Hash
    </div>
    """, unsafe_allow_html=True)

    lan_ip = get_lan_ip()
    st.sidebar.markdown(f"""
    <div class="crypto-sidebar-access">
        <div style="font-size: 0.72rem; font-weight: bold; text-transform: uppercase;">🌐 Access Points</div>
        <div style="font-size: 0.76rem; margin-top: 4px; line-height: 1.4;">
            <b>Local:</b> <code>http://localhost:8501</code><br>
            <b>Wi-Fi/LAN:</b> <code>http://{lan_ip}:8501</code>
        </div>
        <div style="font-size: 0.68rem; margin-top: 5px; opacity: 0.85;">
            Open on other devices on your Wi-Fi or launch <code>start_public_server.bat</code> for worldwide access.
        </div>
    </div>
    """, unsafe_allow_html=True)

    return selected_nav


def render_home_dashboard():
    st.markdown("""
    <div class="crypto-banner crypto-banner-home">
        <h2>🏠 System Overview & Workflow Dashboard</h2>
        <p>
            Securely Send Files &rarr; Receive Files &rarr; Verify Integrity &rarr; Detect Unauthorized Modifications &rarr; Notify Users.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Top-Level Telemetry Cards
    stats = database.get_system_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registered Accounts", stats["total_users"])
    c2.metric("Total Transfers", stats["total_transfers"])
    c3.metric("Verified Deliveries", stats["verified_count"])
    c4.metric("Attacks Detected", stats["attacks_detected"], delta="Protected" if stats["attacks_detected"] > 0 else None, delta_color="inverse")

    st.markdown("---")

    # Workflow Cards
    st.markdown("### 🔄 3-Step Operating Workflow")
    w1, w2, w3 = st.columns(3)

    with w1:
        st.markdown("""
        <div class="crypto-card" style="height: 100%;">
            <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">🔐</div>
            <h4>1. Authenticate Identity</h4>
            <p>
                Log in as a sender or recipient. Each user receives a 2048-bit RSA keypair, with passwords secured via PBKDF2-HMAC-SHA256.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with w2:
        st.markdown("""
        <div class="crypto-card" style="height: 100%;">
            <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">📤</div>
            <h4>2. Encrypt & Send</h4>
            <p>
                Upload any file. The payload is encrypted with <b>AES-256-GCM</b>, the AES key is protected with <b>RSA-OAEP</b>, and signed with <b>RSA-PSS</b>.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with w3:
        st.markdown("""
        <div class="crypto-card" style="height: 100%;">
            <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">📥</div>
            <h4>3. Receive & Verify</h4>
            <p>
                Recipient decrypts with their private key. If modified, a <b>RED SECURITY ALERT</b> blocks access; if clean, a <b>GREEN VERIFIED</b> notification grants download.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Quick Testing Helper
    st.markdown("### ⚡ Quick Testing Instructions for Evaluators")
    st.markdown("""
    1. **Log in as Sender**: Go to **🔐 User Authentication** and click **👩 Alice (Sender)**.
    2. **Dispatch a File**: Go to **📤 Send File**, upload any file, select recipient **`@bob`**, and click **🚀 Encrypt and Send File**.
    3. **Verify as Recipient**: Switch user to **👨 Bob (Recipient)**, go to **📥 Receive File**, and click **🔑 Decrypt and Verify File**.  
       *Observe the **GREEN VERIFIED** alert and download the recovered file.*
    4. **Simulate an Attack**: Send another file from Alice to Bob, but select **`🔴 Simulate In-Transit Attack`**.  
       *Observe the recipient's screen triggering the prominent **RED SECURITY ALERT** with download permanently blocked.*
    5. **Read the Full Manual**: Open **📖 User Manual** from the sidebar for complete documentation.
    """)

    # Public & Remote Network Access Card
    lan_ip = get_lan_ip()
    with st.expander("🌐 How to Access this Web Application from Other Devices / Across the Internet", expanded=True):
        st.markdown(f"""
        <div class="crypto-card">
            <h4 style="margin: 0 0 0.8rem 0;">🌍 Multi-Device & Public Internet Access</h4>
            <p style="font-size: 0.9rem; line-height: 1.6;">
                This application is running on <b><code>0.0.0.0</code></b>, which allows anyone across your local network or the global internet to access the portal, register their own cryptographic keys, and exchange encrypted files with you.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-top: 1rem;">
                <div class="crypto-card-secondary" style="border-left: 4px solid #3b82f6;">
                    <div style="font-weight: bold; font-size: 0.9rem;">💻 Local Access</div>
                    <div style="font-family: monospace; font-size: 0.85rem; margin-top: 4px;">http://localhost:8501</div>
                    <div style="font-size: 0.78rem; margin-top: 4px; opacity: 0.8;">Use this on your current machine.</div>
                </div>
                <div class="crypto-card-secondary" style="border-left: 4px solid #10b981;">
                    <div style="font-weight: bold; font-size: 0.9rem;">📶 Wi-Fi / Local Network (LAN)</div>
                    <div style="font-family: monospace; font-size: 0.85rem; margin-top: 4px;">http://{lan_ip}:8501</div>
                    <div style="font-size: 0.78rem; margin-top: 4px; opacity: 0.8;">Share with any phone, tablet, or PC on your Wi-Fi!</div>
                </div>
                <div class="crypto-card-secondary" style="border-left: 4px solid #8b5cf6;">
                    <div style="font-weight: bold; font-size: 0.9rem;">🌐 Worldwide Public Tunnel</div>
                    <div style="font-family: monospace; font-size: 0.85rem; margin-top: 4px;">start_public_server.bat</div>
                    <div style="font-size: 0.78rem; margin-top: 4px; opacity: 0.8;">Run <code>python run_app.py --public</code> or double-click <code>start_public_server.bat</code> for an instant worldwide link.</div>
                </div>
            </div>
            <div style="margin-top: 1rem; font-size: 0.82rem; opacity: 0.85;">
                💡 <i>For complete step-by-step guidance on public sharing and free permanent 24/7 cloud hosting, open the <b>📖 User Manual</b> &rarr; <b>Section I</b>.</i>
            </div>
        </div>
        """, unsafe_allow_html=True)


def main():
    # Detect active theme mode (Dark vs Light)
    is_dark = st.session_state.get("theme_mode", "🌙 Dark Mode") == "🌙 Dark Mode"
    inject_theme_css(is_dark)

    # Top Banner Header
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">🛡️ Innovative Hybrid Cryptographic File Protection and Integrity Verification</h1>
        <div class="sub-title">
            Enterprise-Grade Multi-Module Cryptosystem (AES-256-GCM • RSA-2048 • SHA-256 • SQLite)
        </div>
        <div class="badge-container">
            <span class="crypto-badge badge-aes">AES-256-GCM Encryption</span>
            <span class="crypto-badge badge-rsa">RSA-2048-OAEP Key Protection</span>
            <span class="crypto-badge badge-rsa">RSA-2048-PSS Digital Signatures</span>
            <span class="crypto-badge badge-sha">SHA-256 Integrity Verification</span>
            <span class="crypto-badge badge-db">SQLite Audit Logging</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar Navigation
    selected_nav = render_sidebar()

    # Route to Selected Page
    if selected_nav == "🏠 Home / Dashboard":
        render_home_dashboard()
    elif selected_nav == "🔐 User Authentication":
        render_module1()
    elif selected_nav == "📤 Send File":
        render_send_file()
    elif selected_nav == "📥 Receive File":
        render_receive_file()
    elif selected_nav == "🛡️ Security Monitoring":
        render_security_monitoring()
    elif selected_nav == "📖 User Manual":
        render_user_manual()


if __name__ == "__main__":
    main()
