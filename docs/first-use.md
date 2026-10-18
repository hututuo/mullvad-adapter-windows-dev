# First-use feature behavior (developer reference)

This describes the product's setup-page behavior for maintenance and regression
review. It is not a recipient Agent installation or report-return procedure;
developer work starts in [development.md](development.md).

The **使用引导** page shows the actual local setup state. A computer without a
configured tunnel identity opens it automatically; existing users keep their city
workspace and can revisit the guide from the sidebar.

1. **Prepare Clash.** Detection reads the local `clash:` protocol registration,
   checks the registered executable and standard install locations, and separately
   checks for supported configuration indexes. A failed read is “unconfirmed”,
   not “not installed”. The installation button opens the
   [official Clash Verge Rev downloads](https://github.com/clash-verge-rev/clash-verge-rev/releases/latest).
   Complete the vendor installer and open Clash once, then detect again. The
   adapter does not silently install a second client or change an existing one.
   Portable installs can specify their local configuration directory on the
   Clash connection page.
2. **Account and device.** Log in using an existing Mullvad account. Device names,
   public keys and addresses come from its official API; private keys remain in
   the local protected store. Create a device, then explicitly use it as the local
   identity. An existing identity does not need to be recreated merely to log in
   to account management. The current
   [official device limit](https://mullvad.net/en/help/using-mullvad-vpn-app)
   is five; when full, identify and explicitly revoke an unused device before
   creating another. Never remove a device automatically or reuse another
   computer's active key. A pending registration must be reconciled first.
3. **City and tunnel.** Keep one to three favorite cities. Select one and connect.
   ICMP latency is not tunnel readiness; IP, inner DNS and HTTPS observations are
   shown separately. Recovery waits for local attachment, verifies the original
   path, then rebuilds it before trying alternatives within the selected city.
4. **Clash profile.** Once the tunnel is connected, one-click import creates a
   separate complete profile. Select it in Clash; old subscriptions remain.
   Enable the desired system proxy/TUN mode in Clash. Import does not toggle
   those OS-facing settings. AI and ordinary traffic default to Mullvad and can
   independently use eligible existing nodes; domestic/LAN rules stay direct.

Saved file, registered subscription, selected profile, live routing and actual
exit are different checks. The guide does not infer working system traffic
from a profile's presence. If connectivity fails, open diagnostics and export
its bounded, redacted report for local investigation. Do not delete identity
backups or repeat an uncertain device-registration request.
