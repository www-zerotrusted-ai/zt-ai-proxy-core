# Native Messaging Host Setup (Windows)

If you plan to integrate a native helper app, keep the extension manifest clean (no top-level `nativeMessaging` key). MV3 only needs the `nativeMessaging` permission. The native host is registered via a separate JSON + registry entry.

1) Create the host manifest JSON
- Path (example): `C:\\Program Files\\ZTProxy\\native_host\\com.zerotrusted.proxy.json`
- Contents:
```
{
  "name": "com.zerotrusted.proxy",
  "description": "ZTProxy Native Host",
  "path": "C:\\Program Files\\ZTProxy\\native_host\\ztproxy-native-host.exe",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://<YOUR_EXTENSION_ID>/"
  ]
}
```

2) Register in Windows Registry (Chrome per-user)
- Key: `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.zerotrusted.proxy`
- Default value: Full path to the JSON above

For Microsoft Edge
- Key: `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.zerotrusted.proxy`

3) Restart the browser

4) From the extension, connect via:
```
const port = chrome.runtime.connectNative('com.zerotrusted.proxy');
```

Notes
- Ensure your native executable is signed if deploying in enterprise.
- Use the same host name in both the JSON and connectNative().
