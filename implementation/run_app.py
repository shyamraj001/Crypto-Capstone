"""
Innovative Hybrid Cryptographic File Protection and Integrity Verification
Enhanced Server Launcher:
- Starts Streamlit on port 8501 bound to 0.0.0.0 (Accessible to all devices on LAN & Internet)
- Detects and displays:
    1. Localhost URL: http://localhost:8501
    2. Local Area Network (LAN) URL: http://<LAN_IP>:8501 (Access from phones/PCs on same Wi-Fi)
    3. Public Internet Tunnel (localtunnel / cloudflared / ngrok / SSH)
- Automatically launches public tunnel when --public flag is used or via start_public_server.bat
- Opens Google Chrome to the web app
"""

import sys
import os
import time
import subprocess
import webbrowser
import socket
import re
import argparse

PORT = 8501
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_FILE = os.path.join(BASE_DIR, "app.py")


def is_port_in_use(port: int) -> bool:
    """Checks if a local port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def get_lan_ip() -> str:
    """Detects host's local network (LAN) IP address."""
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


def find_chrome_path():
    """Locates Google Chrome executable on Windows."""
    potential_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe")
    ]
    for p in potential_paths:
        if os.path.exists(p):
            return p
    return None


def open_in_chrome(url: str):
    """Opens the specified URL in Chrome or default browser."""
    chrome_path = find_chrome_path()
    if chrome_path:
        print(f"[*] Opening Google Chrome at {url}...")
        try:
            subprocess.Popen([chrome_path, url])
            return True
        except Exception as e:
            print(f"[!] Error launching Chrome directly: {e}")

    print(f"[*] Opening default browser at {url}...")
    webbrowser.open(url)
    return False


def start_localtunnel(port: int = 8501):
    """Starts a public internet tunnel using npx localtunnel and prints public URL."""
    print("\n[*] Initializing Public Internet Tunnel via localtunnel...")
    npx_cmd = "npx.cmd" if os.name == 'nt' else "npx"

    try:
        proc = subprocess.Popen(
            [npx_cmd, "localtunnel", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        public_url = None
        for _ in range(30):
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.3)
                continue
            line_str = line.strip()
            print(f"    [Tunnel] {line_str}")
            match = re.search(r"https://[a-zA-Z0-9-]+\.loca\.lt", line_str)
            if match:
                public_url = match.group(0)
                break

        if public_url:
            print("\n" + "=" * 75)
            print(f"  🌐 PUBLIC INTERNET URL: {public_url}")
            print("  (Anyone worldwide can access your application with this link!)")
            print("=" * 75 + "\n")
        return proc, public_url
    except Exception as e:
        print(f"[!] Could not start localtunnel: {e}")
        return None, None


def main():
    parser = argparse.ArgumentParser(description="Innovative Hybrid Cryptosystem Launcher")
    parser.add_argument("--public", "-p", action="store_true", help="Launch a public internet tunnel so anyone online can access the app")
    parser.add_argument("--port", type=int, default=PORT, help=f"Server port (default: {PORT})")
    args = parser.parse_args()

    port = args.port
    lan_ip = get_lan_ip()
    local_url = f"http://localhost:{port}"
    network_url = f"http://{lan_ip}:{port}"

    print("=" * 75)
    print("  INNOVATIVE HYBRID CRYPTOGRAPHIC FILE PROTECTION & INTEGRITY VERIFICATION")
    print("=" * 75)
    print(f"[*] Project Directory : {BASE_DIR}")
    print(f"[*] Target Application : {APP_FILE}")
    print(f"[*] Network Interface  : 0.0.0.0 (All Interfaces Enabled)")
    print("-" * 75)
    print("[*] ACCESS POINTS:")
    print(f"    1. Localhost URL   : {local_url}")
    print(f"    2. Local Wi-Fi/LAN : {network_url}")
    print(f"       (Accessible from any phone, laptop, or tablet on your Wi-Fi)")
    if args.public:
        print(f"    3. Public Internet : Activating Public Tunnel...")
    else:
        print(f"    3. Public Internet : Pass --public or run start_public_server.bat")
    print("=" * 75)

    tunnel_proc = None
    public_url = None

    # Start Streamlit server if not already running
    if not is_port_in_use(port):
        streamlit_cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            APP_FILE,
            f"--server.port={port}",
            "--server.address=0.0.0.0",
            "--server.headless=true",
            "--server.enableCORS=false",
            "--server.enableXsrfProtection=false"
        ]

        print("\n[*] Starting Streamlit server on 0.0.0.0:8501...")
        server_process = subprocess.Popen(
            streamlit_cmd,
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        print("[*] Waiting for server initialization...")
        connected = False
        for attempt in range(15):
            time.sleep(1)
            if is_port_in_use(port):
                connected = True
                break
            print(f"    ... waiting (attempt {attempt + 1}/15)")

        if connected:
            print(f"[+] Server is live at {local_url} and {network_url}!")
        else:
            print("[!] Server startup in progress...")
    else:
        print(f"[+] Server is already active on port {port}!")
        server_process = None

    # Handle Public Tunnel
    if args.public:
        tunnel_proc, public_url = start_localtunnel(port)

    # Open in browser
    target_browser_url = public_url if public_url else local_url
    time.sleep(0.5)
    open_in_chrome(target_browser_url)

    print("\n[+] Web Application is running!")
    print(f"    Local URL    : {local_url}")
    print(f"    LAN URL      : {network_url}")
    if public_url:
        print(f"    Public Link  : {public_url}")
    print("\nPress Ctrl+C in this terminal to stop the application.")

    try:
        if server_process:
            for line in server_process.stdout:
                print(line, end="")
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down application...")
        if tunnel_proc:
            try:
                tunnel_proc.terminate()
            except Exception:
                pass
        if server_process:
            try:
                server_process.terminate()
                server_process.wait()
            except Exception:
                pass
        print("[+] Application stopped cleanly.")


if __name__ == "__main__":
    main()
