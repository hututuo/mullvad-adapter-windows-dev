# Mullvad Adapter UI

macOS SwiftUI client for the local Mullvad Adapter control API.

- Control API: `http://127.0.0.1:17891`
- Stable ingress: `socks5://127.0.0.1:17890`
- Main Clash only decides whether a request enters `Mullvad节点`; Relay / SS inlet / transport failover is owned by the Adapter.
- The UI does not rewrite or reload the production Clash profile.
- The installed app is a menu-bar utility (`LSUIElement`), hides its Dock icon, and may start at login without opening a window.

## Development

```bash
xcrun swift run MullvadAdapterUI
```

## Install release app

```bash
chmod +x install-app.sh
./install-app.sh
```

## Runtime semantics

- Different healthy Relay: candidate first, then front selector commit; new connections use the new Worker while established connections drain on the old Worker.
- Same Relay reconnect / transport / SS-inlet rebuild: break-before-make, because the same WireGuard identity must never be active twice.
- Failed active path: replacement is made ready first when possible, then the broken old path is retired instead of being kept alive for the normal drain timeout.
- Repeated switch with only two Worker slots: preserve the active path; if the standby slot contains an older drain, that oldest drain may be preempted. A manual switch is deferred instead when the old connection count is unknown.
- Auto recovery uses persistent Relay history, short quarantine after failed candidates, SS last-good inlet history, and stale-generation guards so automatic recovery cannot override a newer user choice.
- `Ping` in the UI is ICMP RTT to the actual outer endpoint. DNS / HTTPS / controller probes are separate health signals.

## 日常使用与排查资料

- 1.4 起，测速、错误与导出结果统一显示在固定高度的底部状态栏；“详情”显示完整文本，“停止测速”支持单次和批量测速。提示不再插入节点列表上方，批量进度与节点结果区也保留固定高度。
- 测速点击立即锁定，避免连续点击重复提交；短暂断连仅重试读取操作状态，不重复发起测速或切换。取消时等待操作编号并确认后台清理，未确认时明确提示，不能把“请求取消”当作“已停止”。
- 1.6 默认进入「常用城市」：保存 1–3 个城市，点击整张卡片连接。显示主节点及两个同城备用候选，自动恢复不跨城；「全部节点」位于倒数第二页。遇到异常也可在「连接概览」点「检查并恢复」。
- 「网络诊断 → 检查网络」只检查，不主动切换节点。结果带检测时间和范围，不等同于所有网站、TUN 和应用都正常。
- 「复制排查资料」在概览、诊断页和菜单栏中都有入口。点击后生成 Markdown 文件，并将文件的绝对路径复制到剪贴板，直接贴给本地 Agent 即可。
- 文件保存在 `~/Library/Logs/MullvadLocalAdapter/Reports/`，包含本次 API 状态、累计指标、明确标注的界面缓存、读取错误，以及每个日志最近 64 KiB。即使后台服务不可达，也能导出日志与缓存。
- 持续事件日志：`~/Library/Logs/MullvadLocalAdapter/events.jsonl`。每行一个 JSON 事件，写入前按容量轮转到 `.1`，单份最多 10 MB，两份总计不超过 20 MB（十进制）。不按日期删除，容量允许时保留多天；异常事件量超过容量时淘汰最旧记录，不能同时保证任意故障下完整 24 小时。含时间、路由动作、探针、操作结局与错误。2026-09-20 的约 13 分钟样本推算约 0.7 MB/天，非故障高峰保证值；诊断导出仍只摘录每份末尾 64 KiB，完整历史可按报告中的路径读取。
- 报告不会额外切换节点、重启网络或上传文件。配置及密钥文件不被收集；日志对常见凭据模式脱敏。报告仍可能含本地路径、节点地址、错误细节，仅限当前用户读取。

## Daemon 更新与回滚

从本源码仓库根目录运行；安装或回滚需要单独授权：

```bash
ruby install-daemon.rb --check
ruby verify-candidate.rb --relay UNUSED_RELAY --output LOCAL_CANARY_DIRECTORY
ruby install-daemon.rb --install --canary-report LOCAL_CANARY_DIRECTORY/acceptance.json --backup-dir LOCAL_BACKUP_DIRECTORY
ruby install-daemon.rb --rollback LOCAL_BACKUP_DIRECTORY
```

候选节点必须没有被当前服务占用。安装器核对 canary 对应的源码 SHA，保留旧版本，在服务恢复且真实 HTTPS 通过后才算成功；失败自动回滚。更新会短暂中断适配器上的连接。

## Test

```bash
# 从本目录运行 UI 测试（包含 release 构建）
xcrun swift test -c release
# 从源码根目录运行后端与 watchdog 回归
ruby -I . -I daemon -e 'ARGV.each { |f| require File.expand_path(f) }' daemon/test_*.rb
```

## 1.5 两种测速

日常只需要点“快速检查本市”：它最多并发 4 路，只做入口 ICMP 粗筛，不切换节点。需要真正判断能不能用时，点单个节点的“完整测速（验证可用性）”；它会验证隧道、内层 DNS 和 HTTPS。国家级快速检查、批量完整验证和每节点额外等待 3 秒的慢速模式都放在“更多测速”里，默认不需要使用。

快速测速的目标地址、目标类型和传输方式由 daemon `/relays` 的已校验快测字段提供，SwiftUI 不再直接读取本地 `relays-cache.json`。当前节点在自动模式下优先使用实际 worker 入口，并绑定活动 worker 的物理接口，避免探测包被系统路由送进 Clash TUN。每条结果保留目标 IP、目标类型、接口、耗时、Ping 退出码及命令输出；右下角“详情”显示最近一轮逐节点结果并可复制。没有 ICMP 回复只表示该地址未回应 Ping，不表示节点连接不可用。完整测速仍按安全顺序逐个验证；切换节点继续完整验证。

1.5.2（build 8）扩大国家、城市整行及常用操作控件的矩形点击区域；快速 Ping 的城市统计明确显示 ICMP 回复数，和完整可用性结果分开。

## 1.6 城市维护

常用城市由 daemon 保存，首次运行从实际提交的节点迁移当前城市。选择城市使用自动传输，近期完整可用记录优先；显式 SS/IPv6/IPv4 偏好仍在全部节点页保留。选定城市每 30 秒、其他常用城市每 3 分钟对少量候选进行外层探测。完整成功记录超过 10 分钟会标为需要重新验证；候选并非已经连接的热备用，切换前仍验证隧道、DNS 和 HTTPS。诊断导出包含城市边界、备用候选和探测时间。
