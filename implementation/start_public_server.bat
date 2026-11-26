@echo off
title Innovative Hybrid Cryptographic File Vault (Public Server)
echo ===========================================================================
echo   INNOVATIVE HYBRID CRYPTOGRAPHIC FILE PROTECTION & INTEGRITY VERIFICATION
echo                  STARTING PUBLIC ACCESSIBLE SERVER
echo ===========================================================================
echo.
echo [*] Launching Streamlit on 0.0.0.0:8501 and generating Public Internet Tunnel...
python run_app.py --public
pause
