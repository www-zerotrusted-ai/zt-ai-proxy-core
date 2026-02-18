# Contributing to ZeroTrusted AI Proxy - Core

Thank you for your interest in contributing! 🎉

## Ways to Contribute

- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the repository

## Getting Started

1. **Fork the repository**
2. **Clone your fork**:
   ```powershell
   git clone https://github.com/YOUR-USERNAME/zt-ai-proxy-core.git
   cd zt-ai-proxy-core
   ```
3. **Create a branch**:
   ```powershell
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes**
5. **Test your changes**
6. **Commit with clear messages**:
   ```powershell
   git commit -m "Add: Description of your change"
   ```
7. **Push to your fork**:
   ```powershell
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request**

## Code Guidelines

### Python Code Style
- Follow PEP 8
- Use type hints where possible
- Add docstrings to functions
- Keep functions small and focused

### JavaScript Code Style
- Use ES6+ features
- Add comments for complex logic
- Follow existing code patterns in browser extension

### Commit Message Format
```
Type: Short description

Longer description if needed

Fixes #issue_number
```

**Types:**
- `Add:` New feature
- `Fix:` Bug fix
- `Update:` Update existing feature
- `Remove:` Remove code/feature
- `Docs:` Documentation changes
- `Refactor:` Code refactoring

## Testing

Before submitting a PR:

1. **Test the proxy**:
   ```powershell
   mitmdump -s interceptor/interceptor_addon.py --listen-port 8080
   ```

2. **Test PII detection**:
   - Try sending messages with PII to ChatGPT
   - Verify they are blocked
   - Check logs in `interceptor/intercepted_requests.log`

3. **Test browser extension**:
   - Load extension in Chrome
   - Verify configuration works
   - Test toast notifications

## Pull Request Guidelines

### Before Submitting
- ✅ Code follows style guidelines
- ✅ All tests pass
- ✅ Documentation is updated
- ✅ Commit messages are clear
- ✅ PR description explains changes

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Steps to test your changes

## Screenshots (if applicable)
Add screenshots for UI changes

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Added comments where needed
- [ ] Updated documentation
- [ ] No new warnings
- [ ] Added tests if applicable
```

## Reporting Bugs

Use the [GitHub Issues](https://github.com/www-zerotrusted-ai/zt-ai-proxy-core/issues) page.

**Bug Report Template:**
```markdown
**Describe the bug**
Clear description of what's wrong

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected behavior**
What you expected to happen

**Screenshots**
If applicable

**Environment:**
- OS: [e.g., Windows 11]
- Python version: [e.g., 3.12]
- Browser: [e.g., Chrome 120]

**Logs**
Relevant logs from `intercepted_requests.log`
```

## Feature Requests

We love new ideas! Open an issue with:
- Clear description of the feature
- Use case / why it's needed
- Example implementation (if you have ideas)

## Development Setup

### Prerequisites
- Python 3.12+
- Git
- Chrome

### Setup
```powershell
# Clone repository
git clone https://github.com/www-zerotrusted-ai/zt-ai-proxy-core.git
cd zt-ai-proxy-core

# Create virtual environment
python -m venv venv312
.\venv312\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks (if available)
pre-commit install
```

### Project Structure
```
zt-ai-proxy-core/
├── interceptor/
│   ├── interceptor_addon.py   # Main proxy logic
│   ├── internal_api.py         # Internal endpoints
│   ├── services/
│   │   └── pii_fast.py        # PII detection
│   ├── tools/
│   │   ├── request_filters.py # Request filtering
│   │   └── provider_openai.py # OpenAI-specific logic
│   └── ui/
│       └── ui.html            # Internal UI
├── browser_extension/          # Chrome extension
├── cert_installer/             # Certificate installer
└── tests/                      # Tests
```

## Questions?

- **Discord**: [Join our community](https://discord.gg/zerotrusted)
- **Email**: opensource@zerotrusted.ai
- **Twitter**: [@ZeroTrustedAI](https://twitter.com/ZeroTrustedAI)

## Code of Conduct

Please be respectful and constructive in all interactions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for making ZeroTrusted AI Proxy better!** 🙏
