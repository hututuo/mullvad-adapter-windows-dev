# Windows Clash connection page

Add a current-profile one-click connection page to replace handwritten SOCKS
configuration. Preserve subscriptions, unrelated rules, DNS/TUN and tunnel owner
lifetime. This change targets the existing Windows Tauri client; it does not
replace the Mac production client or implement an independent system VPN.

Requirements and design: [spec](specs/clash-connect/spec.md), [design](design.md).
Implementation evidence and installed-version status live in private CONTEXT.
