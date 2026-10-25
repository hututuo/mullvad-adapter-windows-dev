# Mac 维护与构建

本仓库的Mac维护源码同步自`784f2fd9ef83d44aa4ad62441144f8ac1145bde3`（1.9.1/build13），不是Windows迁移时的旧参考。源码、候选和实际安装版本分别记录于[SOURCE_BASELINE.json](../SOURCE_BASELINE.json)。Windows的Rust/Tauri实现继续保留，不能以旧Mac分支整树覆盖它。

## 模块与边界

- `ui/`：SwiftUI主窗/菜单栏、常用城市、账号设备、诊断与保护页面；主窗存在时Dock显示，菜单栏模式隐藏Dock。
- `daemon/`：Ruby HTTP控制、账号/目录、设备草稿、首次身份安装、front/worker、同城恢复与分层canary。
- `helpers/pq-negotiator/`：固定官方配置客户端的Rust helper与独立许可；单跳PQ通过候选通道协商，多跳/PQ组合不支持。
- `install-daemon.rb`、`verify-candidate.rb`：有真实副作用的受控升级/canary工具，不是普通测试入口。
- `scripts/stage-daemon-payload.rb`：只复制显式源码/fixture清单并运行假引擎回归，不安装服务。

现有身份不因账号登录而替换；无身份首次启动可只管理账号。未知注册要先核对，首次身份安装须保留官方地址回执并显式确认。替换现有身份、旋转密钥和Mac独立Clash配置仍有未完成项，见[Mac差距清单](mac-parity.md)。Windows支持独立Clash配置不能当作Mac已接通。

## 本地检查

Swift package声明macOS 13+；当前Mac候选目标arm64，Intel和干净新机仍需单独验收。Ruby回归需Ruby 3.1+与Minitest 5.27.0，关闭外部Minitest插件，不能把零测试当PASS。工具版本以workflow及实际运行输出为准；不要为了源码同步升级用户全局工具链。

在已有匹配工具的环境中，从仓库根目录运行：

```sh
ruby -c daemon/mullvad_adapter.rb
ruby -I . -I daemon -e 'ARGV.each { |f| require File.expand_path(f) }' daemon/test_*.rb
ruby scripts/test-shared-contract.rb
cd ui
swift test -c release --skip MainWindowDockPresenceTests
```

缺少Minitest时可在本任务独立gem目录安装固定5.27.0，并用GEM_HOME/GEM_PATH仅为测试进程加载，不改用户的默认gem。完整Swift测试会触发真实AppKit窗口排序，**在用户工作桌面必须跳过MainWindowDockPresenceTests**；仅在专用隔离GUI会话或CI主机运行它。跳过的3项须标NOT_RUN，不开应用、preview、菜单或循环切窗口代替单测。

`swift build -c release --arch arm64`只编译，不运行应用。PQ helper用`scripts/build-pq-helper.sh`，涉及固定Rust/protoc及依赖下载；一般账号/UI修改不必每次重编helper。源码、锁文件、许可和上游来源应随组件保留。

## 云端候选

Actions手动运行`checks-and-candidate`：先Ruby/Swift/PQ组件检查，再assemble arm64候选，Artifacts名称包含完整Git SHA，manifest记录版本、运行号、平台/架构、大小/SHA256、helper来源和未签名状态。Windows workflow中的Mac兼容job也安装固定Minitest后运行回归。

候选含编译UI、Ruby daemon源码及PQ helper，不是已验收的独立干净安装器。当前运行要求和升级/回退约束见[candidate-install.md](candidate-install.md)：仍依赖可用Ruby、Mihomo/Clash和对应服务/身份配置。用户运行UI/helper不需要Swift或Rust编译器，但不能套用Windows完整NSIS的免依赖结论。账号-only首次启动源码已实现，不代表干净Mac整体安装闭环已完成。

同步源码不等于触发候选、签名、公开Release或替换已安装程序。真实canary会建隧道；运行安装脚本会改变应用/服务，均须其具体授权。新候选的安装、升级回滚、真实出口、窗口交互和长期稳定分别验收。此次同步没有改现用程序、网络或电源，也没有重新发布Mac安装包。

## 本机状态读取与界面日志

后台流量观测使用不排队的互斥门：健康检查、本地入口验证、城市维护和独立Clash路径验证不会同时批量运行。入口默认30秒；首次健康失败后的快速复测保留。城市维护每5秒最多一个ICMP、只在主通道ready时执行；ICMP本地超时标unknown并继续轮转，不能据此判节点失效。自动恢复连续耗尽后轮间等待默认30/60/120/120秒，原入口→备用SS→同城节点的首轮预算不变，手动重试可立即触发。官方目录自动更新每轮只发一次，失败退避至最多5分钟；成功后恢复正常TTL。手动刷新和显式测速独立，不宣称任何频率保证不会被第三方限流。

失败探测新增 `worker-failure-evidence`：重建前读取内核日志末16KiB，仅保存错误类别计数及关联worker/入口，不复制业务域名或消息正文。当前内核控制接口未提供WG握手时间及外层UDP计数，日志明确标unknown；不能用内层DNS/TCP超时倒推出SS端口被封。

需要进一步取证时，使用[被动SS/WG工具](../scripts/diagnostics/observe_ss_wg.rb)：

```sh
ruby scripts/diagnostics/observe_ss_wg.rb --config "$ACTIVE_SLOT_CONFIG" --interface "$PHYSICAL_INTERFACE" --seconds 30
```

先从本机 `/status` 确认active_slot及对应生成配置，禁止硬编码开发者的槽位/网卡/SS地址。工具仅支持该配置中的aes-256-gcm、IPv4 UDP、Ethernet经典PCAP；本机tcpdump需要已有抓包权限，工具不提权、不更改BPF权限。权限失败不是零回包证据。抓包过滤精确SS地址端口、最长120秒，仅在内存中处理并输出数字计数；不保存PCAP、私钥、密码或流量正文，不主动发包，也不打断通道。若自然发生切换须重新确认路径，旧端点统计不能套到新通道。已有合法捕获可用 `--pcap FILE` 代替 `--interface` 离线分析。

依据[SS AEAD协议](https://shadowsocks.org/doc/aead.html)验证SS封装，再按[WireGuard消息格式](https://www.wireguard.com/protocol/)区分握手发起/回应/cookie/加密数据计数。只解SS外层、不解WG业务内容。只有发包可定位到“此捕获窗口未见该入口回包”；收到可认证SS中的WG握手形状不等于客户端接受握手。没有自然重握手时零握手计数正常；仍须结合真实数据面和时间窗判断。

就绪验证保留隧道IP、DNS、HTTPS检查；外层ICMP并行采样供界面参考，未及时完成时不阻塞就绪结论。完整测速仍保留ICMP检查。事件携带实际后台源码的SHA256，避免仅凭历史固定 `build` 标签混淆已安装版本。

短命探测命令（lsof监听归属、配置验证、ping、curl）由父进程按单调时钟限制等待，双流并行读取、各保留最多64KiB，超时/取消只结束本次探测拥有的进程组。控制器等待把监听归属检查计入总预算，本机HTTP禁止隐式重试。readiness/full canary分别有24/34秒汇总预算及有界清理；本地执行超时独立记为不确定，不能作为节点/SS失效样本。日志记录 `local-command-timeout`、`health-local-deferred`、`recovery-local-deferred` 和数值阶段耗时，区分父进程等待与curl自报耗时。本地spawn/pipe系统错误用`local-command-unavailable`
记录允许的阶段/操作/错误类，不回显命令参数；它仍是不确定观测，不算远端失败。
超时清理遇到进程组信号权限拒绝时记录`local-command-cleanup-deferred`，只在waitpid
仍证明是自己未回收的子进程时尝试单PID结束。清理权限错误不覆盖原超时/取消，
始终继续有界reap与关闭管道；已回收leader不能再按正PID发送信号。无法终止的
子进程不冒充已成功清理，保留诊断并有界脱离等待。这些边界不能保证操作系统严重卡顿时准点执行。

探针超时、执行不可用、清理拒绝及本地观测暂缓日志使用独立写线程，最多暂存128条；
检测返回和回收不等待日志锁或磁盘。拥塞时保留较新事件并记录丢弃数，不声称日志零丢失；
异常退出可能丢失尚未落盘的事件。原观测时间和operation/recovery/attempt关联跨探针线程保留。
超时记录区分spawn_ms、capture_ms和max_poll_gap_ms；状态发布延误区分循环迟到与
state_busy/action_busy/capture_error，30秒内最多一条，不续新旧快照年龄或改变隧道健康。

授权执行`install-daemon.rb --install`时，把已有自有LaunchAgent的ProcessType设为Interactive：
它与子进程承载前台网络和本机状态API，不应按离线后台任务限制CPU/I/O。该服务使用TCP，
没有XPC事务，因此不使用依赖XPC活跃度的Adaptive。升级保留完整原plist，失败及手动回退
还原原字节和权限；`--check`只报告当前/目标策略。源码测试或此策略设计均不证明历史某次
卡顿必然由系统调度造成，也不会自动改变现用服务。依据本机`man launchd.plist`的ProcessType说明。

本地转发监测先测IP地址，失败后再测独立域名HTTPS；同一入口仍有HTTPS流量通过时保留原进程，并记录 `front-target-degraded`。两个目标均失败才进入原有后端对照与连续两次修复阈值，仍保留代次/网络守卫。该策略减少单个探测目标引起的重启，不能把一次重启后恢复当作引擎死锁的证明。详见[运行观测规格](../openspec/changes/mac-runtime-stall-bounds/specs/runtime-observation/spec.md)。

状态通信与隧道健康是两类证据。界面取消一次读取不计故障；晚到的旧响应不能覆盖新结果。单次传输失败显示“状态待更新”，连续三次且跨过至少十秒才显示“无法读取本机服务状态”。HTTP 错误与响应格式错误单独显示，均不等价于隧道断开。保留的快照必须带最后读取时间；成功读取后清除警告。此路径不会触发重连或修改节点。

`GET /status` 读取独立的内存 JSON 快照，不等待连接事务或操作队列的锁，也不做网络、磁盘读取。后台每秒尝试发布一次；锁忙则跳过，不刷新旧快照的时间。超过3秒或尚无快照时返回 HTTP 503（`status_snapshot_stale` / `status_snapshot_unavailable`），界面显示“状态更新延迟”，不能据此判定隧道中断。响应头 `X-Adapter-Status-Age-Ms` / `X-Adapter-Status-Capture-Ms` 提供快照年龄和采集耗时；控制决策仍使用原权威状态、原事务锁和原子提交。

界面状态读取有独立的本机直连 URLSession（无代理、缓存、cookie、凭据存储，超时仍5秒），与账号等长请求分池。状态和城市分别轮询，正常每轮结束后等5秒、操作中1秒；城市读取去重。状态无需等城市或 metrics 完成，手动刷新则并发更新三者。响应时间与服务器快照年龄都计入最后更新时间；旧版后台无时间头仍兼容。此方案消除共享锁和请求队列造成的额外等待，不能保证操作系统严重卡顿时线程仍按时运行。对应[规格](../openspec/changes/mac-lightweight-status/specs/status-publication/spec.md)与锁竞争/请求隔离回归。

`~/Library/Logs/MullvadLocalAdapter/ui-status.jsonl` 及 `.1` 各最多256 KiB，仅记录状态请求编号、错误类别/数值码、耗时、连续失败数、快照年龄、可选的发布年龄/采集耗时、界面版本和会话编号。正常快速轮询不逐条落盘；启动、失败、取消、丢弃旧结果、恢复与慢请求留痕。日志不接收任意错误正文、URL、HTTP响应或账号密钥。串行写队列最多64条待写事件，超额丢弃计数随下一条记录保存；导出等待刷新最多一秒。文件0600、目录0700，拒绝链接和特殊文件；复制排查资料包含两份日志。文件上限并非按天保留承诺。

只改界面时可单独构建并替换签名UI bundle，不必重启Ruby后台或Mihomo。替换前保存完整旧bundle，替换后核对后台/前端/worker/Clash进程身份和真实代理HTTPS。不要运行`install-daemon.rb`来部署UI补丁；不要通过真实断网、睡眠、同身份备用隧道或反复开关主窗制造测试故障。

## Ordered recovery and main-page controls

The [Mac recovery contract](../openspec/changes/mac-ordered-city-recovery/specs/recovery/spec.md) defines the current ladder: original authorized inlet up to 3 starts (0/1/5-second cleanup-relative waits), at most 2 other SS inlets, then at most 4 eligible same-city nodes with 2 inlets each. The 300-second ordered-round admission budget is distinct from the existing cold-start/city-selection budget. DNS-only degradation preserves the live tunnel. Local offline/probe/cleanup problems pause or defer instead of scoring all nodes as dead.

Home exposes actual recovery progress and authenticated `POST /recovery` controls: `{"action":"retry-current"}`, `{"action":"retry-round"}`, `{"action":"stop"}`. Retry controls return the existing operation receipt; stop acknowledges cancellation and lets bounded cleanup finish. Use the existing owner capability; browser-origin mutations remain rejected. The status `recovery` object is optional for older UI/daemon compatibility. Its countdown is a fresh daemon observation; stale reads must not be shown as current progress. Mac has no chain fallback yet.

Regression: include `daemon/test_ordered_recovery.rb` in the existing Ruby suite and `RecoveryTests` in Swift tests. Do not launch desktop windows or interrupt the user's network to simulate this contract. Keep runtime/install/long-term results separate from these deterministic tests.

## Controller ownership and status latency

Generated front/worker controllers require separate random Bearer credentials;
their config files are private (0600). Credentials belong to the daemon lifetime
and are never returned through status. Controller bootstrap registers its process
before waiting; uncertain cleanup retains the slot/peer reservation.

Status requests send `X-Adapter-Request-Id`, a random per-read UUID. The daemon
echoes validated IDs and returns `X-Adapter-Dispatch-Ms` (accept to handler) and
`X-Adapter-Request-Read-Ms` (handler to parsed request), alongside publication-age
headers. Bounded queued events `status-request-received` and
`status-request-finished` record that ID and numeric timing; the latter includes
`response_ms`. UI failure/recovery/slow events retain `correlation_id`, and successful
reads can include `server_dispatch_ms` and `server_request_read_ms`. Legacy daemon
responses without these headers remain compatible. A status write has a one-second
application deadline. Scheduler stalls can exceed deadlines; missing queued events
alone do not prove a request never arrived. These observations support diagnosis
without treating every local timeout as a tunnel failure.
