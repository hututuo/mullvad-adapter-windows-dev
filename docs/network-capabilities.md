# 通道能力与数据来源

## 数据来源

| 数据 | 来源与含义 |
|---|---|
| relay 名称、地点、active、公钥、IPv4/IPv6、SS extra 地址、WG/SS端口范围 | 官方 HTTPS `/app/v1/relays`；active 是目录标记，不是当前可达性 |
| 客户端私钥与公钥 | 本地安全生成；设备登记及隧道地址由官方设备 API 返回 |
| SS aes-256-gcm 与公共密码 mullvad | 上游协议常量，不是个人账号密码 |
| extra SS 端口 20484 | 本地选择值，仅用于 API 发布的 extra 地址；主地址必须满足 API 端口范围 |
| 25秒保活、MTU、回退预算、路由规则 | 明确的客户端策略，不应伪称 API 数据 |
| 本机网卡/路由、Clash端口与节点、进程 | 本机观测或用户配置，不复用开发者机器的值 |

Windows 启动先使用有效本机缓存，物理网络稳定后在独立线程自动刷新官方目录，
成功后每 24 小时更新。失败保留缓存，按 1、5、15 分钟退避；已确认的物理断网暂停请求，
连续失败期间仅允许一次稳定恢复提前唤醒。手动更新共用单个在途任务，不占用账号或隧道队列。
新缓存保存实际获取时间，旧缓存没有时间则如实显示；过期目录不是当前可达性的证明。
更新不会重启健康 worker、主动探测备用 WG，或清空当前恢复轮的失败/时间预算。

## 真实生产路径与限制

当前 Windows 产品的连接路径是 WireGuard over Shadowsocks，外层经物理网卡
绑定的 UDP carrier；carrier 的 SOCKS TCP 控制连接不等于承载业务的 UDP-over-TCP。
Direct IPv4/IPv6 配置生成器存在，但产品自动恢复尚不选择这些路径。
QUIC、UDP-over-TCP、LWO 未接入，不能将官方 App 的支持矩阵套用到本软件。
Windows 对必需多跳/PQ采取显式不支持，不能悄悄降低保护。Mac 旧实现的能力与
验收独立，不能因此宣称 Windows 等价。IPv6、MTU与大流量仍需单独真机验收。

Windows 可从本机 Clash 实际配置及受限的本地 provider 缓存导入一个独立 SS 叶节点，
作为可选的隧道承载。策略为仅直连、优先直连后链式备用、固定链式。默认自动策略在
未保存独立节点时只尝试原有直连；不会猜测或免费生成备用节点。首阶段仅支持 IPv4
出站、无插件的 aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 SS UDP。
不支持的节点、IPv6 literal、歧义名称、越界 provider 路径不列为可用；导入绑定配置摘要，
配置变化后必须重新读取。密码不进入 renderer、日志、报告或公开配置，在本机 DPAPI 保存。

链式路径为 WG → Mullvad SS → 独立 SS → 自持认证 carrier → 物理网卡。物理 socket
和 route witness 指向独立 SS 的真实 IPv4；最终业务选择仍只有 Mullvad。不会借用外部
Clash 的通用 SOCKS 端口冒充物理绑定证据，也不改用户的 Clash 选择组。域名经有界的
系统解析线程解析后，仅接受公网 IPv4；无法解析或被 fake-IP 接管时会明确失败。
仍存活或待恢复的链式原路径不允许后台更换上游，需先显式断开。独立节点本身必须
支持 UDP，链式不是 UDP-over-TCP，不能据此承诺能通过全面 UDP 封锁。

对称型 NAT 不等于必然连接失败：客户端主动连接固定公网 relay 与 P2P 打洞
不同，出站 UDP 及相同目标的回包仍可能可用。25秒 WireGuard 保活用于维护
闲置映射，不解决禁 UDP。SS 也不能突破全面 UDP 丢弃；需要真实 TCP 传输实现
及服务端兼容验收。不能靠改端口、增加并发或更换节点来宣称解决。

账号控制面在未配置代理时显式通过系统路由的 HTTPS 访问，忽略环境代理，保留
证书校验、禁重定向、总超时与响应大小上限。系统路由不是物理网卡绑定；外部
TUN需有独立API规则。配置了本机代理时不会静默回退或重放设备写操作。受限
网络可能仍需独立普通节点或后续 API bridge，不能承诺无节点新用户必定直连成功。

## 稳定与恢复

保留物理断网暂停、稳定恢复2秒后验证原路径、原路径重建后才同城备选的策略。
失败 active Verify 有15秒重试间隔，避免恢复不可启动时每个主循环都重测。
进程创建锁排队每10ms检查取消/截止/路由；持锁后再检查。CreateProcessW本身
不可取消，失败清理仍有 carrier 与进程树的独立预算。45秒是启动 fallback 的
预算，不是端到端恢复保证；完整健康检查自身最长约14秒，健康后间隔15秒。
这些是源码预算，不是这次故障注入实测。没有自动睡眠、物理断网或电源策略测试。

用户连接请求优先于自动 ICMP 维护。后台 Ping 尚未退出时保留一次连接意图，
先取消维护，收到所有原生调用完成的回执后才释放登记位并开始连接。期间可以
取消该意图；断开和退出也会清除它。不会提前释放锁、并行使用同一设备身份，
也不为账号或设备写操作提供自动重试。

## 官方依据

- [WireGuard NAT keepalive](https://www.wireguard.com/quickstart/)
- [Mullvad API access](https://mullvad.net/en/help/api-access)
- [Mullvad restrictive networks](https://mullvad.net/en/help/connecting-to-mullvad-vpn-from-restrictive-locations)
- [Mullvad relay selection](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/relay-selector.md)
- [Mullvad SS implementation](https://github.com/mullvad/mullvadvpn-app/blob/main/tunnel-obfuscation/src/shadowsocks.rs)

### Same-relay SS inlet recovery

Windows keeps the established SS default as its first choice. After a fresh owned data-plane failure and confirmed worker/carrier cleanup, it can try at most four metadata-authorized inlet combinations on that same relay before moving through the existing same-city relay queue. Dedicated extra IPv4 addresses may use 443 or the established default port; primary relay addresses remain restricted to the official SS port ranges. Addresses are read from current metadata, not machine constants. No UDP53 candidate is added.

Original-path recovery still starts with the exact saved inlet. New alternatives are fallback attempts, retain the existing 45-second round start budget, and cannot run concurrently under one WG identity. Stale evidence, cancellation, physical-offline state and local setup errors do not consume an inlet. DNS-only or single-service degradation does not advance this inlet queue. A healthy committed path is retained; no spare tunnel is probed in the background. Metadata refresh cannot resurrect failed endpoints or grow one round beyond twelve measured inlet failures.

With an independent SS upstream configured, automatic mode tries that same Mullvad
inlet through the chain after measured direct failure, then alternates bounded
direct/chain attempts. Both routes share the four-per-relay/twelve-per-round cap.
The original committed route is rebuilt first. A healthy chain is retained rather
than periodically switching its IP or probing another tunnel to prefer direct.

## 启动与系统流量接入

Windows 默认在启动后连接已选城市；优先使用仍被当前目录授权的上次节点和 SS 入口，
完整验证后才提交 front。可在连接设置关闭；本次启动中显式断开/取消会撤销启动意图。
启动不会创建身份或替用户开启系统代理/TUN，也不会在退出后私自更改 Clash 规则。
外部 Clash 已启用所选配置和系统代理/TUN时，命中本机节点的流量才进入适配器。
隧道未就绪或重建时 front 拒绝转发，不提供 DIRECT 回落；已有长连接可能中断，不能
宣称无损切换或系统级 kill switch。国内/局域网直连与用户其他节点继续按 Clash 规则。
