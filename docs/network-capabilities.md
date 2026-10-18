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

目录可使用本机缓存；旧缓存缺少获取时间，界面明确提示缓存而不伪报官方即时数据。
缓存 TTL 与后台刷新尚未完成，不应以缓存 active 或 ICMP 成功承诺可用。

## 真实生产路径与限制

当前 Windows 产品的连接路径是 WireGuard over Shadowsocks，外层经物理网卡
绑定的 UDP carrier；carrier 的 SOCKS TCP 控制连接不等于承载业务的 UDP-over-TCP。
Direct IPv4/IPv6 配置生成器存在，但产品自动恢复尚不选择这些路径。
QUIC、UDP-over-TCP、LWO 未接入，不能将官方 App 的支持矩阵套用到本软件。
Windows 对必需多跳/PQ采取显式不支持，不能悄悄降低保护。Mac 旧实现的能力与
验收独立，不能因此宣称 Windows 等价。IPv6、MTU与大流量仍需单独真机验收。

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
