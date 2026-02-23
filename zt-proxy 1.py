#!/usr/bin/env python3
import os, sys, json
import logging
import socket
import traceback
import subprocess
import winreg
import time
import getpass

# Force standalone edition for this build (set before any imports that check ZT_EDITION)
if not os.environ.get('ZT_EDITION'):
    os.environ['ZT_EDITION'] = 'standalone'

__version__ = "v1.00001"  # Update this for each release

# Wizard mode (console prompts) enabled by default when interactive unless disabled via env
WIZARD_ENABLED = (os.getenv("ZT_WIZARD", "1") != "0") and sys.stdin.isatty()

LOG_FILE = os.path.join(os.getenv("APPDATA") or os.path.expanduser("~"), "ZTProxy", "install.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Hint PyInstaller to include mitmproxy in the bundle even if lazy-import below fails on some builds
try:
    import mitmproxy  # type: ignore
    import mitmproxy.tools.main as _mitm_main  # type: ignore
except Exception:
    # It's okay if this import fails at runtime; we try again later and have a fallback path.
    pass

def prompt_yes_no(question: str, default: str = 'y') -> bool:
    """Simple Y/N prompt returning boolean. default in ['y','n']"""
    default = default.lower()
    suffix = " [Y/n]: " if default == 'y' else " [y/N]: "
    while True:
        try:
            ans = input(question + suffix).strip().lower()
        except EOFError:
            ans = ''
        if not ans:
            return default == 'y'
        if ans in ('y','yes'): return True
        if ans in ('n','no'): return False
        print("Please enter y or n.")

def prompt_input(prompt_text: str, required: bool = True, secret: bool = False) -> str:
    while True:
        try:
            if secret:
                val = getpass.getpass(prompt_text + (": " if not prompt_text.endswith(':') else ' '))
            else:
                val = input(prompt_text + (": " if not prompt_text.endswith(':') else ' '))
        except EOFError:
            val = ''
        if val or not required:
            return val.strip()
        print("Value required.")

def get_api_key(provided_api_key: str | None = None):
    # Check if running in standalone mode
    edition = os.getenv('ZT_EDITION', 'standalone').lower()
    is_standalone = (edition == 'standalone')
    
    # Use same config path as interceptor (matches file_store.py)
    cfg_dir = os.getenv("APPDATA") or os.path.expanduser("~")
    cfg_dir = os.path.join(cfg_dir, "ZeroTrusted", "ZTProxy")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_file = os.path.join(cfg_dir, "ztproxy_config.json")

    # 1. Check config file
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, "r") as f:
                data = json.load(f)
                # Use "proxy_api_key" field to match interceptor
                if data.get("proxy_api_key"):
                    print(f"Fetched API key from {cfg_file}\n")
                    return data["proxy_api_key"]
        except Exception:
            pass

    # 2. Check environment variable
    env_key = os.getenv("ZT_PROXY_API_KEY")
    if env_key:
        print("Fetched API key from environment variable ZT_PROXY_API_KEY\n")
        # Save to config for persistence across restarts
        try:
            existing = {}
            if os.path.exists(cfg_file):
                with open(cfg_file, "r") as f:
                    existing = json.load(f)
        except Exception:
            pass
        existing["proxy_api_key"] = env_key
        with open(cfg_file, "w") as f:
            json.dump(existing, f, indent=2)
        return env_key

    # 3. Standalone mode: API key not required, return placeholder
    if is_standalone:
        print("Standalone mode: API key not required\n")
        return "STANDALONE"

    # 4. Enterprise mode: Prompt user only if not found
    key = provided_api_key
    if not key and WIZARD_ENABLED:
        key = prompt_input("Enter your ZT_PROXY_API_KEY", secret=True)
    if not key:
        try:
            import tkinter as tk
            from tkinter import simpledialog
            root = tk.Tk(); root.withdraw()
            key = simpledialog.askstring("ZTProxy", "Enter your ZT_PROXY_API_KEY:")
            root.destroy()
        except Exception:
            pass
    if not key:
        print("No API key provided; exiting...")
        sys.exit(1)
    # Save to config with correct field name
    try:
        existing = {}
        if os.path.exists(cfg_file):
            with open(cfg_file, "r") as f:
                existing = json.load(f)
    except Exception:
        pass
    existing["proxy_api_key"] = key
    with open(cfg_file, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"API key saved to {cfg_file}\n")
    return key

def find_available_port(start_port=8080, max_port=8090):
    for port in range(start_port, max_port + 1):
        # Check if port is available by attempting to bind
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                s.close()
                return port
            except OSError:
                continue
    print("No available ports found in range.")
    logging.error("No available ports found in range.")
    sys.exit(1)

def check_existing_install(uninstall_choice: bool | None = None):
    cfg_dir = os.getenv("APPDATA") or os.path.expanduser("~")
    cfg_dir = os.path.join(cfg_dir, "ZTProxy")
    cfg_file = os.path.join(cfg_dir, "config.json")
    exe_name = f"zt-proxy-{__version__}.exe"
    exe_path = os.path.join(os.path.dirname(__file__), "dist", exe_name)
    found = False
    if os.path.exists(cfg_file):
        found = True
    if os.path.exists(exe_path):
        found = True
    if found:
        print("Existing installation detected.")
        logging.info("Existing installation detected.")
        if uninstall_choice is None:
            if WIZARD_ENABLED:
                uninstall_choice = prompt_yes_no("Uninstall previous version?", 'n')
            else:
                # GUI fallback
                resp = None
                try:
                    import tkinter as tk
                    from tkinter import messagebox
                    root = tk.Tk(); root.withdraw(); resp = messagebox.askyesno("ZTProxy", "Uninstall previous version?"); root.destroy()
                except Exception:
                    resp = False
                uninstall_choice = resp
        if uninstall_choice:
            try:
                if os.path.exists(cfg_file):
                    os.remove(cfg_file)
                if os.path.exists(exe_path):
                    os.remove(exe_path)
                print("Previous version uninstalled.")
                logging.info("Previous version uninstalled.")
            except Exception as e:
                print(f"Error during uninstall: {e}")
                logging.error(f"Error during uninstall: {e}")
        else:
            print("Continuing with installation.")
            logging.info("User chose not to uninstall previous version.")

def install_pyinstaller():
    """Install pyinstaller in the virtual environment."""
    venv_path = ".\\venv312\\Scripts\\pip"
    try:
        # Upgrade pip to the latest version
        subprocess.check_call([venv_path, "install", "--upgrade", "pip"])
        # Install pyinstaller
        subprocess.check_call([venv_path, "install", "pyinstaller"])
        print("Pyinstaller installed successfully.")
        logging.info("Pyinstaller installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing pyinstaller: {e}")
        logging.error(f"Error installing pyinstaller: {e}")
        sys.exit(1)

def create_pac_file(port):
    """Create PAC file for automatic proxy configuration."""
    user_docs = os.path.expanduser("~/Documents")
    pac_path = os.path.join(user_docs, "zt-proxy.pac")
    
    pac_content = f"""function FindProxyForURL(url, host) {{
    // Enhanced PAC file with debugging for ZTProxy
    
    // Always allow direct access to mitm.it for certificate installation
    if (host.toLowerCase() === "mitm.it") {{
        console.log("ZTProxy PAC: Direct connection for mitm.it");
        return "DIRECT";
    }}
    
    // Domain routing is server-managed via ZTProxy (/routing); this static PAC keeps no hardcoded domains.
    // Prefer using the Chrome/Edge extension which fetches domains dynamically.
    var aiDomains = [];

    // Normalize host (remove port if present)
    var cleanHost = host.split(':')[0].toLowerCase();
    
    // Check each AI domain
    for (var i = 0; i < aiDomains.length; i++) {{
        var domain = aiDomains[i].toLowerCase();
        
        // Exact match or subdomain match
        if (cleanHost === domain || 
            cleanHost.endsWith('.' + domain) ||
            dnsDomainIs(cleanHost, domain) || 
            shExpMatch(cleanHost, "*." + domain)) {{
            
            // Log to console (visible in browser dev tools)
            console.log("ZTProxy PAC: Routing " + host + " through proxy 0.0.0.0:{port}");
            
            // Send to your local zt-proxy
            return "PROXY 0.0.0.0:{port}";
        }}
    }}

    // Log direct connections for debugging
    console.log("ZTProxy PAC: Direct connection for " + host);
    
    // Default: direct connection for everything else
    return "DIRECT";
}}"""
    
    try:
        with open(pac_path, 'w') as f:
            f.write(pac_content)
        print(f"PAC file created at: {pac_path}")
        logging.info(f"PAC file created at: {pac_path}")
        return pac_path
    except Exception as e:
        print(f"Error creating PAC file: {e}")
        logging.error(f"Error creating PAC file: {e}")
        return None

def configure_windows_proxy(pac_path, port):
    """Configure Windows to use the PAC file for automatic proxy setup."""
    try:
        # Open the Internet Settings registry key
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        
        # Convert file path to file:// URL
        pac_url = f"file:///{pac_path.replace(os.sep, '/')}"
        
        # Disable manual proxy
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        
        # Enable automatic configuration script
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        
        winreg.CloseKey(key)
        
        print(f"Windows proxy configured to use PAC file: {pac_url}")
        logging.info(f"Windows proxy configured to use PAC file: {pac_url}")
        
        # Notify user about the configuration
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
         
            # messagebox.showinfo("ZTProxy Setup", 
            print(f"Proxy configuration completed!")
            print(f"PAC file: {pac_path}\n")
            print(f"Windows proxy settings updated automatically.\n\n")
            print("Managed domains will route through ZTProxy on port {port}.")
            root.destroy()
        except Exception:
            pass
            
        return True
    except Exception as e:
        print(f"Error configuring Windows proxy: {e}")
        logging.error(f"Error configuring Windows proxy: {e}")
        
        # Show manual configuration instructions
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning("ZTProxy Setup", 
                f"Automatic proxy configuration failed.\n\n"
                f"Please configure manually:\n"
                f"1. Open Settings → Network & Internet → Proxy\n"
                f"2. Turn Manual proxy setup OFF\n"
                f"3. Turn 'Use setup script' ON\n"
                f"4. Enter script address: file:///{pac_path.replace(os.sep, '/')}\n\n"
                f"PAC file saved to: {pac_path}")
            root.destroy()
        except Exception:
            print(f"Manual configuration required:")
            print(f"1. Open Settings → Network & Internet → Proxy")
            print(f"2. Turn Manual proxy setup OFF")
            print(f"3. Turn 'Use setup script' ON")
            print(f"4. Enter script address: file:///{pac_path.replace(os.sep, '/')}")
        
        return False

def install_mitmproxy_certificate():
    """Install mitmproxy CA certificate for SSL interception"""
    print("Installing mitmproxy certificate...")
    logging.info("Installing mitmproxy certificate...")
    
    try:
        # Get the user's home directory (where mitmproxy actually stores certificates)
        cert_dir = os.path.expanduser("~/.mitmproxy")
        cert_file = os.path.join(cert_dir, "mitmproxy-ca-cert.pem")
        
        print(f"Looking for certificate at: {cert_file}")
        
        # Wait for certificate to be generated by the running proxy
        max_wait = 30  # Wait up to 30 seconds
        wait_interval = 1
        waited = 0
        
        while not os.path.exists(cert_file) and waited < max_wait:
            print(f"Waiting for certificate generation... ({waited}s)")
            time.sleep(wait_interval)
            waited += wait_interval
        
        if os.path.exists(cert_file):
            # Install certificate to user's Trusted Root store (no admin required)
            try:
                print("Installing certificate to user's Trusted Root Certification Authorities...")
                result = subprocess.run([
                    "certutil", "-user", "-addstore", "-f", "Root", cert_file
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print("✅ mitmproxy certificate installed to Trusted Root Certification Authorities.")
                    logging.info("mitmproxy certificate installed to Trusted Root Certification Authorities.")
                    
                    print("SSL Certificate installed successfully!")
                    print("The proxy can now intercept HTTPS traffic.\n")
                    print("You may need to restart your browser for changes to take effect.")                   
                    
                    return True
                else:
                    print(f"Certificate installation failed: {result.stderr}")
                    logging.error(f"Certificate installation failed: {result.stderr}")
                    return False
                    
            except Exception as e:
                print(f"Error installing certificate: {e}")
                logging.error(f"Error installing certificate: {e}")
                return False
        else:
            print("❌ Certificate file not found after waiting!")
            return False
        
    except Exception as e:
        print(f"Error in certificate installation: {e}")
        logging.error(f"Error in certificate installation: {e}")
        return False

def main():
    # Check if running in standalone mode
    edition = os.getenv('ZT_EDITION', 'standalone').lower()
    is_standalone = (edition == 'standalone')
    
    print(f"ZTProxy {__version__} ({edition.upper()} mode)")
    logging.info(f"Starting version {__version__} in {edition} mode")
    
    # STANDALONE MODE: Skip wizard, go straight to proxy startup
    if is_standalone:
        print("Standalone mode: Starting proxy without setup wizard...")
        api_key = "STANDALONE"  # Not needed for standalone
        os.environ["ZT_PROXY_API_KEY"] = api_key
        
        # Auto-assign port
        port = find_available_port()
        print(f"Using port {port}")
        logging.info(f"Using port {port}")
        
        # Find addon
        if getattr(sys, 'frozen', False):
            base = sys._MEIPASS
        else:
            base = os.path.dirname(__file__)
        
        addon = os.path.join(base, "interceptor", "interceptor_addon.py")
        if not os.path.exists(addon):
            print(f"ERROR: Addon file not found at {addon}")
            print(f"Base path: {base}")
            print(f"sys.frozen: {getattr(sys, 'frozen', False)}")
            if hasattr(sys, '_MEIPASS'):
                print(f"sys._MEIPASS: {sys._MEIPASS}")
            logging.error(f"Addon file not found at {addon}")
            print("\nPress Enter to exit...")
            input()
            return
        
        # Import and start mitmdump
        try:
            from mitmproxy.tools.main import mitmdump  # type: ignore
        except Exception as e:
            logging.error(f"Failed to import mitmproxy: {e}")
            print(f"ERROR: Failed to import mitmproxy: {e}")
            print("\nPress Enter to exit...")
            input()
            return
        
        print(f"Starting proxy server on 0.0.0.0:{port}...")
        logging.info(f"Starting proxy server on 0.0.0.0:{port}")
        
        try:
            # Build mitmdump arguments
            mitmdump_args = [
                "--mode", "regular",
                "--listen-host", "0.0.0.0",
                "--listen-port", str(port),
                "--set", "console_log_level=warn",
                "--set", "block_outside_url_exclude_patterns=.*",
                "--ignore-hosts", r"(^|\.)dev-gliner\.zerotrusted\.ai$|(^|\.)dev-history\.zerotrusted\.ai$",
                "-s", addon
            ]
            
            print(f"Proxy is running. Configure your browser extension to use localhost:{port}")
            mitmdump(mitmdump_args)
            
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
            if code != 0:
                print(f"\nProxy exited with code {code}")
                logging.error(f"Proxy exited with code {code}")
                print("Press Enter to exit...")
                input()
        except Exception as e:
            print(f"\nProxy error: {e}")
            logging.error(f"Proxy error: {e}")
            traceback.print_exc()
            print("\nPress Enter to exit...")
            input()
        
        return
    
    # ENTERPRISE MODE: Full wizard with setup
    print(f"ZTProxy Installer {__version__}")
    logging.info(f"Starting installer version {__version__}")

    # Wizard interaction simplified per user request: single confirmation with defaults
    uninstall_prev = True
    provided_api_key = None
    manual_port = None  # always auto-assign unless future override env set
    create_pac = True
    # Allow disabling Windows proxy configuration via environment variable
    # When using Chrome extension, set ZT_CONFIGURE_PROXY=0 to prevent conflicts
    configure_proxy = os.environ.get('ZT_CONFIGURE_PROXY', '1').lower() not in ('0', 'false', 'no')
    install_cert = True
    if WIZARD_ENABLED:
        print("\n--- Interactive Setup Wizard (set ZT_WIZARD=0 to disable) ---")
        print("\nThe following configurations will be set up:")
        print("-  Auto Port assignment")
        print("-  Create PAC")
        print("-  Configure Windows Proxy")
        print("-  Install mitmproxy cert")
        # print("\nYou will be prompted for an API key only if it is not already present in config or environment.")
        # if not prompt_yes_no("Proceed with installation?", 'y'):
        #     print("Aborted by user.")
        #     return
    else:
        print("Wizard disabled (non-interactive or ZT_WIZARD=0). Using default automated setup.")

    check_existing_install(uninstall_prev)
    api_key = get_api_key(provided_api_key)
    os.environ["ZT_PROXY_API_KEY"] = api_key

    if manual_port is not None:
        port = manual_port
    else:
        port = find_available_port()
    print(f"Using port {port}")
    logging.info(f"Using port {port}")

    pac_path = None
    if create_pac:
        print("Setting up automatic proxy configuration (PAC file)...")
        logging.info("Setting up automatic proxy configuration...")
        pac_path = create_pac_file(port)
        if pac_path and configure_proxy:
            configure_windows_proxy(pac_path, port)
        elif pac_path and not configure_proxy:
            print("Windows proxy configuration disabled (ZT_CONFIGURE_PROXY=0)")
            print("Use Chrome extension to manage proxy settings")
            logging.info("Windows proxy configuration skipped - using Chrome extension")

    print("Checking for mitmproxy certificate...")
    time.sleep(2)

    if install_cert:
        import threading
        def install_cert_after_start():
            time.sleep(5)
            install_mitmproxy_certificate()
        threading.Thread(target=install_cert_after_start, daemon=True).start()

    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:

        base = os.path.dirname(__file__)

    addon = os.path.join(base, "interceptor", "interceptor_addon.py")
    if not os.path.exists(addon):
        print(f"ERROR: Addon file not found at {addon}")
        logging.error(f"Addon file not found at {addon}")
        return

    # Lazy import mitmproxy so missing dependency doesn't prevent showing error/pause
    try:
        from mitmproxy.tools.main import mitmdump  # type: ignore
    except Exception as e:
        # Fallback: try to locate a mitmdump.exe on disk (e.g., dev venv) and spawn it
        logging.error(f"Failed to import mitmproxy in-bundle: {e}")
        print("Failed to import mitmproxy: No module named 'mitmproxy'")
        candidates = []
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            candidates.append(os.path.join(here, 'venv312', 'Scripts', 'mitmdump.exe'))
        except Exception:
            pass
        try:
            # If running from a bundled EXE, sys.executable points to the EXE. Check sibling Scripts.
            exe_dir = os.path.dirname(sys.executable)
            candidates.append(os.path.join(exe_dir, 'mitmdump.exe'))
        except Exception:
            pass
        # Also try CWD venv
        candidates.append(os.path.join(os.getcwd(), 'venv312', 'Scripts', 'mitmdump.exe'))

        ext = next((p for p in candidates if os.path.exists(p)), None)
        if ext:
            print(f"Falling back to external mitmdump: {ext}")
            cmd = [ext,
                   "--mode", "regular",
                   "--listen-host", "0.0.0.0",
                   "--listen-port", str(port),
                   "--set", "console_log_level=warn",
                   "--set", "block_outside_url_exclude_patterns=.*",
                   "--ignore-hosts", r"(^|\.)dev-gliner\.zerotrusted\.ai$|(^|\.)dev-history\.zerotrusted\.ai$",
                   "-s", addon]
            try:
                subprocess.run(cmd, check=False)
            except Exception as se:
                print(f"External mitmdump failed: {se}")
                logging.error(f"External mitmdump failed: {se}")
            # Only prompt in non-standalone mode
            if os.getenv('ZT_EDITION', 'standalone').lower() != 'standalone':
                print("Press Enter to close this window...")
                input()
            return
        else:
            msg = (
                "Did you install it inside this build? (pip install mitmproxy before PyInstaller)\n"
                "Tip: Use build.ps1 to build with Python 3.12 venv so mitmproxy is bundled.\n"
                f"EXE path: {sys.executable}"
            )
            print(msg)
            logging.error(msg)
            # Only prompt in non-standalone mode
            if os.getenv('ZT_EDITION', 'standalone').lower() != 'standalone':
                print("Press Enter to exit...")
                input()
            return

    try:
        logging.info("About to call mitmdump")
        print("About to call mitmdump")
        
        # Build mitmdump arguments
        mitmdump_args = [
            "--mode", "regular",
            "--listen-host", "0.0.0.0",
            "--listen-port", str(port),
            "--set", "console_log_level=warn",
            "--set", "block_outside_url_exclude_patterns=.*", # Disable caching
            "--ignore-hosts", r"(^|\.)dev-gliner\.zerotrusted\.ai$|(^|\.)dev-history\.zerotrusted\.ai$",
            "-s", addon
        ]
        
        # Add TLS certificate if provided (for remote deployments)
        # Expected format: /path/to/cert.pem (contains both cert and private key)
        # Or separate files: /path/to/cert.pem and /path/to/key.pem
        tls_cert = os.environ.get('ZT_TLS_CERT')
        tls_key = os.environ.get('ZT_TLS_KEY')
        
        if tls_cert:
            if tls_key:
                # Separate cert and key files
                mitmdump_args.extend(["--set", f"certs={tls_cert}:{tls_key}"])
                logging.info(f"Using TLS certificate: {tls_cert} with key: {tls_key}")
                print(f"Using TLS certificate: {tls_cert} with key: {tls_key}")
            else:
                # Combined cert+key file
                mitmdump_args.extend(["--set", f"certs={tls_cert}"])
                logging.info(f"Using TLS certificate: {tls_cert}")
                print(f"Using TLS certificate: {tls_cert}")
        
        mitmdump(mitmdump_args)
        logging.info("mitmdump call returned (unexpected)")
        print("mitmdump call returned (unexpected)")
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        msg = f"mitmdump exited with code {code}"
        if code != 0:
            print(f"\n{msg}")
            logging.error(msg)
            # Only prompt on actual errors in standalone mode
            if os.getenv('ZT_EDITION', 'standalone').lower() != 'standalone':
                print("Press Enter to close this window...")
                input()
        else:
            logging.info(msg)
        return
    except Exception:
        print("\nUnhandled exception:")
        logging.error("Unhandled exception:")
        tb_str = traceback.format_exc()
        print(tb_str)
        logging.error(tb_str)
        import logging as _logging
        _logging.shutdown()
        # Only prompt on errors in non-standalone mode
        if os.getenv('ZT_EDITION', 'standalone').lower() != 'standalone':
            print("Press Enter to exit...")
            input()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"FATAL ERROR:")
        print(f"{'='*60}")
        print(f"{e}")
        print(f"\nFull traceback:")
        import traceback
        traceback.print_exc()
        print(f"\n{'='*60}")
        print("Press Enter to exit...")
        input()