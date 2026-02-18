# ZTProxy Chrome Extension Installation Guide

> **🎉 Now with Microsoft Edge Support!** See [Edge Support Guide](EDGE_SUPPORT.md) for Edge-specific instructions.

## Supported Browsers

- ✅ **Google Chrome** (Recommended)
- ✅ **Microsoft Edge** (Chromium-based)
- ⚠️ **Other Chromium browsers** (Brave, Opera, Vivaldi) - May work but not officially tested

## Automatic Installation (Recommended)
The ZTProxy installer will automatically install this Chrome extension when you run the main installer. No manual steps required.

## Manual Installation (if needed)

### Step 1: Enable Developer Mode
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" toggle in the top right corner

### Step 2: Install Extension
1. Click "Load unpacked" button
2. Navigate to your ZTProxy installation folder
3. Select the `chrome_extension` folder
4. Click "Select Folder"

### Step 3: Configure Proxy Settings
1. Click the ZTProxy extension icon in Chrome toolbar
2. In the popup, set your proxy configuration:
   - **Host**: localhost (default)
   - **Port**: 8081 (or your ZTProxy port)
3. Click "Save Configuration"
4. Click "Test Connection" to verify

## Verification
- Visit an AI website like chat.openai.com
- Check that requests appear in ZTProxy logs
- Extension icon should show "ON" badge on AI domains

## Troubleshooting

### Extension not working?
1. Verify ZTProxy is running on the configured port
2. Check extension permissions in `chrome://extensions/`
3. Look for errors in Chrome DevTools console

### Wrong port configured?
1. Click the ZTProxy extension icon
2. Update the port number in the configuration
3. Save and test the new configuration

### Permission denied?
- Make sure ZTProxy certificate is installed
- The installer should handle this automatically

## Supported AI Domains
- OpenAI (openai.com, chat.openai.com, api.openai.com)
- ChatGPT (chatgpt.com)
- Claude (claude.ai, anthropic.com)
- Cohere (cohere.com)
- Mistral (mistral.ai)

## Need Help?
Check the ZTProxy logs for detailed information about intercepted requests.
