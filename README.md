# ZeroTrusted AI Proxy - Core (Open Source)

🛡️ **Open-source AI proxy with local PII detection** - Protect sensitive data from being sent to AI services like ChatGPT, Claude, and other LLMs.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)]()

## 🚀 Features

### ✅ Core (Open Source)
- **Local PII Detection**: Regex-based detection of sensitive information (emails, phone numbers, credit cards, SSN, names)
- **Real-time Blocking**: Intercepts AI requests containing sensitive data before they leave your network
- **ChatGPT Support**: Works with ChatGPT, OpenAI API, and other AI services
- **Browser Extension**: Chrome extension for seamless integration
- **Standalone Mode**: No authentication or remote services required
- **Simple Configuration**: Easy setup with localhost proxy
- **Custom Block Page**: User-friendly UI when requests are blocked

### 🎯 What Gets Blocked?
- Email addresses
- Phone numbers (US and international formats)
- Credit card numbers
- CVV codes
- Social Security Numbers
- Personal names (in sensitive contexts)

## 📦 Installation

### Prerequisites
- Windows 10/11
- Python 3.12+ (for building from source)
- Chrome browser

### Quick Start (Pre-built Executable)

1. **Download** the latest release from [Releases](https://github.com/www-zerotrusted-ai/zt-ai-proxy-core/releases)
2. **Run** `ZTProxy-Standalone.exe`
3. **Install Certificate** (first-time setup):
   ```powershell
   # Run as Administrator
   cd cert_installer
   .\ZTProxy_Install_Cert.exe
   ```
4. **Install Browser Extension**:
   - Open Chrome → `chrome://extensions`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select `browser_extension` folder
5. **Configure Extension**:
   - Click extension icon
   - Set Host: `localhost`
   - Set Port: `8080`
   - Click "Save Config"

### Build from Source

```powershell
# Clone repository
git clone https://github.com/www-zerotrusted-ai/zt-ai-proxy-core.git
cd zt-ai-proxy-core

# Create virtual environment
python -m venv venv312
.\venv312\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Build executable
python -m PyInstaller --clean ZTProxy-Standalone.spec

# Output: dist\ZTProxy-Standalone.exe
```

## 🎮 Usage

### Testing PII Detection

Once setup is complete, try these tests in ChatGPT:

**✅ Should work (no PII):**
```
Hey, can you help me write a Python script?
```

**❌ Should block (contains PII):**
```
My email is john.doe@example.com and phone is 555-123-4567
```

You'll see a friendly block page explaining the sensitive information was detected.

## 🏗️ Architecture

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ HTTP/HTTPS
       ↓
┌─────────────┐
│ ZTProxy     │ ← Intercepts requests
│ (localhost: │   Checks for PII
│    8080)    │   Blocks if detected
└──────┬──────┘
       │
       ↓
┌─────────────┐
│   ChatGPT   │
│   OpenAI    │
│   etc.      │
└─────────────┘
```

## ⚙️ Configuration

Edit `config/proxy_config.json` or use the extension UI:

```json
{
  "mode": "post-chat-pii",
  "pii_threshold": 1,
  "port": 8080,
  "disable_auth": true
}
```

### PII Detection Modes
- `all` - Route all traffic (no filtering)
- `post-only` - Only POST requests
- `post-chat` - Only chat/conversation endpoints
- `post-chat-pii` - Chat endpoints with PII detection (recommended)

## 🔧 Advanced Usage

### Custom PII Patterns

Edit `interceptor/services/pii_fast.py` to add custom regex patterns:

```python
PATTERNS = {
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'PHONE': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    # Add your custom patterns here
}
```

### Logs

View blocked requests in `interceptor/intercepted_requests.log`:

```
[2026-02-18 12:34:56] [CONVERSATION BLOCKED] PII detected: 3 items
  - email: user@example.com
  - phone: 555-123-4567
```

## 🆚 Enterprise Edition

Need more advanced features? Check out **[ZeroTrusted AI Enterprise](https://zerotrusted.ai/enterprise)**:

| Feature | Core (Open Source) | Enterprise |
|---------|-------------------|------------|
| Local PII Detection | ✅ | ✅ |
| Browser Extension | ✅ | ✅ |
| Custom Patterns | ✅ | ✅ |
| SSO Authentication | ❌ | ✅ |
| Remote Blocklists | ❌ | ✅ |
| Audit Logs with Masking | ❌ | ✅ |
| Team Management | ❌ | ✅ |
| Policy Engine | ❌ | ✅ |
| API Access | ❌ | ✅ |
| Priority Support | ❌ | ✅ |
| Multi-tenant | ❌ | ✅ |

**[Learn More →](https://zerotrusted.ai/enterprise)**

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

```powershell
# Clone and setup
git clone https://github.com/www-zerotrusted-ai/zt-ai-proxy-core.git
cd zt-ai-proxy-core

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run proxy in dev mode
mitmdump -s interceptor/interceptor_addon.py --listen-port 8080
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Troubleshooting

### Certificate Errors
If you see SSL certificate errors:
1. Run `cert_installer\ZTProxy_Install_Cert.exe` as Administrator
2. Restart your browser

### Extension Not Working
1. Check extension is enabled in `chrome://extensions`
2. Verify configuration: Host=`localhost`, Port=`8080`
3. Reload the extension
4. Hard refresh ChatGPT (Ctrl+Shift+R)

### Requests Not Blocked
1. Check proxy is running (exe is open)
2. Verify PII threshold in config (should be 1)
3. Check logs in `interceptor/intercepted_requests.log`

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [API Reference](docs/API.md)
- [Development Guide](docs/DEVELOPMENT.md)

## 🔗 Links

- **Website**: https://zerotrusted.ai
- **Enterprise Edition**: https://zerotrusted.ai/enterprise
- **Documentation**: https://docs.zerotrusted.ai
- **Issues**: https://github.com/www-zerotrusted-ai/zt-ai-proxy-core/issues

## 💬 Community

- **Discord**: [Join our community](https://discord.gg/zerotrusted)
- **Twitter**: [@ZeroTrustedAI](https://twitter.com/ZeroTrustedAI)
- **Blog**: https://zerotrusted.ai/blog

## ⭐ Star History

If you find this project useful, please consider giving it a star! It helps others discover the project.

---

**Made with ❤️ by the ZeroTrusted.ai team**

*Protecting your privacy, one AI request at a time.*
