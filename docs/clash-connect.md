# 独立分流配置

新版接入默认生成一份独立配置，不要求原订阅有扩展脚本、策略组或节点。
AI出口、普通外网出口均默认 Mullvad，也可分别选择已有独立节点或订阅组。
国内与局域网直连，Drive 优先走普通出口。规则源于已核实的 Mac 策略，
移除了个人进程路径、指定网卡、个人域名和 public-IP 特例，不复制账号或密钥。

先连接城市，再点击“一键写入 Clash”。适配器自动交给 Clash 导入并等待读回，
不需要用户去 Clash 手动选择文件或填写订阅地址。现有订阅保持当前选择，
用户只需在 Clash 选中新配置。也可“保存完整配置文件”留作备份。有当前订阅时保持其选择；
空客户端首次导入可能被 Verge 自动选择，因此一键导入要求隧道已连接。

使用 Verge 官方 URL 导入协议，建立本机订阅；不修改其内部 profiles.yaml。
订阅服务只在 loopback 上运行，随机访问凭据和完整配置仅保存在本机私有目录。
关闭窗口继续托盘运行；退出界面进程后 Clash 继续使用已下载副本，重新打开
界面会恢复同一订阅地址。整份配置更新需要界面/托盘运行，节点供应器独立刷新。
账号/目录和供应器下载有独立出口，不能指向适配器，避免自举循环。
Tailscale、UU 的已知进程及 Tailscale 控制域名优先使用独立“远程控制出口”，
默认 DIRECT；受限网络下可在 Clash 改选已有独立节点，不能指向适配器。
这些是系统路由上的直连规则，不绑定个人网卡，也不保证未识别进程自动绕过。

界面区分“已保存”“已发送导入”“已在客户端读回”“客户端已选择”；这些状态
均不能替代实际流量验收。配置使用客户端提供的 CN GEOIP/GEOSITE 数据，缺失或
验证失败不会发送导入。当前自动接入范围为 Windows Clash Verge Rev；provider
只复用 HTTPS HTTP 源，文件源、链式节点和本机入口会明确列为未复用。

Public candidate scope is recorded in SOURCE_BASELINE.json and the Release manifest. Recipient installation/egress remains a separate local verification; private maintainer evidence is not required.
实现与要求见 openspec/changes/clash-portable-profile/。

---

以下为旧版当前订阅增量接入，保留用于已有接入的撤销和兼容。

# Windows Clash connection

The **Clash 接入** page integrates the current Clash Verge Rev profile. It requires an independent current-profile extension script (shared/global
scripts are refused). It detects
the standard current-user configuration directory or accepts an explicit local
directory for portable installs. It uses the client's existing Windows named
pipe controller first, or an enabled loopback HTTP controller when no pipe is
configured. It does not require opening an extra HTTP port or enable a controller,
system proxy or TUN. Rule mode is required for applying the integration.
Other clients can copy the displayed SOCKS5 YAML instead.

Only local `\\.\pipe\<name>` endpoints are accepted; remote/ambiguous pipe paths
are refused. Pipe requests reuse the pinned HTTP parser over a bounded byte stream,
without a TCP forwarding listener, environment proxy or redirects. Mihomo's pipe
API relies on Windows pipe access control and does not validate the HTTP secret,
so the adapter never sends that secret over the pipe. This does not attest the
external core's binary/signature. A configured but unavailable pipe reports failure
instead of silently trying another controller. A blank HTTP address without a
pipe reports a missing interface, separately from an unsafe nonlocal address.

Choose an existing manual selector for application traffic and a concrete,
independent ordinary proxy for `api.mullvad.net`. **一键接入配置** takes a fresh
preview, saves private backups, validates the transformed runtime with the pinned
Mihomo `-t`, appends a managed wrapper to the current profile extension script,
and reloads/selects through the local controller. Existing subscription data,
other rules, group options and DNS are retained. The ordinary API rule is placed
first to prevent bootstrap traffic returning to the adapter. A reserved-name or
identical-rule collision is refused rather than adopted without ownership.
The adapter must be connected before apply or re-enable can select its local
ingress, so an idle REJECT front cannot replace working Clash traffic. Detection,
preview, export and undo remain available while disconnected.
For first use, **先用于账号与节点目录** independently saves the detected Clash
mixed port as the adapter's bootstrap proxy. This does not alter Clash files or
selectors and is available before account login or tunnel connection. Then log
in, connect a city and enable the selected traffic group.

Three separate indicators show saved configuration, live selector state and
adapter tunnel state. A successful config write alone never reports activation.
The controller must confirm the selector; actual application egress is a further
acceptance check. The persistent extension adds the node after subscription
updates. Verge may restore an older selector choice; use **重新启用接入** to reselect the managed node
if that happens. This only changes the selector, without rewriting or reloading the config. The feature does not change global selection-persistence policy.

**撤销本次接入** restores the exact original script only when the current script
matches the installed wrapper (or a partially completed undo). A newer external
edit blocks automatic restoration. Undo reloads a fresh runtime with the managed
delta removed, restores the old target choice if still managed, and preserves a
later user choice. Backups remain in a separate private application directory;
they can include subscription credentials and must not be attached to reports,
Git or public issues. The small preview/export contains no account/private key.
The optional adapter bootstrap-port setting is independent and is not undone by
the Clash removal action.

Live rule and selector membership divergence from Verge's generated file blocks
reload: reapply the current subscription in Verge first. GeoIP country-code case
is ignored because Mihomo normalizes it; rule targets and order still match
exactly. Controller-only injected
configs, provider-only profiles, unsupported rule serialization or nonstandard
script entrypoints require manual integration. This is optimistic file conflict
detection, not a shared lock with an uncooperative external writer. Profile
switching is explicit: the page lists other recorded profiles; switch back in
Verge before removing an old profile's extension.

Implementation: `core/crates/clash-integration` owns the portable transformation,
private transaction/undo and bounded controller requests; Tauri commands run on a
separate blocking worker without holding the connection owner's lock. The native
host supplies the authoritative front port and pinned runtime, and uses a private
directory separate from the active tunnel host's exclusive storage lease.

Validation:

```sh
cargo test --manifest-path core/Cargo.toml -p adapter-clash-integration --locked
node scripts/test-clash-extension.mjs
# Explicit isolated core fixture; never supply a real user's config directory:
cargo run --manifest-path core/Cargo.toml -p adapter-clash-integration --example isolated_mihomo -- /absolute/pinned/mihomo /absolute/new/test-directory
# Windows only: the same synthetic apply/readback/undo through a named pipe
cargo run --manifest-path core/Cargo.toml -p adapter-clash-integration --example isolated_mihomo -- C:/absolute/pinned/mihomo.exe C:/absolute/new/test-directory --pipe
```

Reference contracts: [Verge extension order](https://www.clashverge.dev/guide/extend.html),
[Mihomo config/selector API](https://wiki.metacubex.one/en/api/), and the pinned
[Mihomo reload implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/route/configs.go).
The [pinned pipe server](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/route/server.go)
serves the same routes over the local pipe, with Windows access control.
The reload uses the documented payload form; it does not weaken the engine's
configuration-path safety check. CI/build/isolated fixtures and a real installed
Clash GUI remain separate evidence gates, listed in SOURCE_BASELINE.json; recipient-machine acceptance must be recorded locally.
