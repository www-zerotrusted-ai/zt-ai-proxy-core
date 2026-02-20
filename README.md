# ZeroTrusted AI Proxy - Core (Open Source)

This repository provides everything you need to run the ZeroTrusted AI Proxy as a standalone open-source solution.

## 🚀 Quick Start for Open Source Users

### 1. Clone the Repository
```
git clone https://github.com/www-zerotrusted-ai/zt-ai-proxy-core.git
cd zt-ai-proxy-core
```

### 2. Build the Standalone Proxy Executable
Ensure you have Python 3.12+ and PowerShell 5.1+ installed on Windows.

Run the build script:
```
./build_standalone_exe.ps1
```
This will generate the standalone executable in the `dist/` folder.

### 3. Load the Chrome Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `browser_extension` folder in this repo

### 4. Run the Proxy
Run the generated executable from the `dist/` folder:
```
./dist/ZTProxy-Standalone.exe
```

### 5. Configure Your Browser to Use the Proxy
Set your browser to use the proxy at `127.0.0.1:8081` (or as configured).

### 6. Block Sensitive Data (PII) in AI Requests
When you use ChatGPT or other AI services, the proxy will block requests containing sensitive information (PII) such as emails, phone numbers, credit cards, etc. The Chrome extension will show a block page if a request is blocked.

---
For more details, see the documentation or open an issue on GitHub.