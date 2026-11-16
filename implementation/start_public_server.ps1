Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "  INNOVATIVE HYBRID CRYPTOGRAPHIC FILE PROTECTION & INTEGRITY VERIFICATION" -ForegroundColor Cyan
Write-Host "                 STARTING PUBLIC ACCESSIBLE SERVER" -ForegroundColor Green
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "[*] Launching Streamlit on 0.0.0.0:8501 and generating Public Internet Tunnel..." -ForegroundColor Yellow
python run_app.py --public
