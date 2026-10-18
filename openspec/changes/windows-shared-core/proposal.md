# Windows shared core

Status: PROPOSED. Implementation and Windows acceptance: NOT_RUN.
Behavioral source baseline: `a8e214ed4ba759b831dc096139f076114d13d91b`.

## Why

现有 SwiftUI 界面与 Ruby 后台只在 macOS 打包。后台同时持有业务策略、Mihomo 进程、系统命令、文件路径和恢复锁；复制一套 Windows 后台会让两端城市/恢复/安全行为逐渐分叉。需要共享控制核心，同时把 OS 接入与界面明确拆开。

## What changes

- 提议共享 Rust domain/control core 与独立后台 executable；Windows 首版用 Tauri 2 + React/TypeScript 界面，macOS SwiftUI 暂时保留。
- 核心统一城市、证据、操作、恢复和保护策略；引擎与系统观察/进程/持久化是替换边界。
- Windows 首版继续外部 Clash 接入，不同时重做系统 TUN、路由、防火墙和分流。Mihomo 随安装包提供并固定版本/摘要，不依赖读取其他 App 的内部文件。
- 在实现前冻结脱敏 API/事件和恢复场景；逐阶段构建 Windows 完整安装候选。

## Capabilities

### New capabilities

- `windows-lifecycle`：独立用户后台、授权 IPC、进程和私密数据所有权、安装/升级/回退、薄客户端行为。
- `windows-recovery`：Windows 硬件接入证据、原路径优先、同城约束、代次与并发、快测/完整测试、可诊断性。

### Preserved behavior

1–3 城市、最多少量候选；ICMP 不当完整可用；单 peer 独占；断网暂停、原路径优先；保护要求不静默降低；日志容量上限和脱敏导出；UI 整按钮可点击及固定反馈空间。规格是 Windows 目标合同，macOS 实现/生产验收范围须另读私有资料，不推定已对两端通过。

## Non-goals

本变更不替换现用程序、不导入真实账号、不创建/撤销设备、不发布、不换 Surge、不整合官方 daemon 的系统 VPN；不启用未经验证的热备用、多跳+PQ、DAITA、QUIC、UDP2TCP 或 LWO；不承诺零中断或同城 IP 完全不变。独立全系统 VPN 是后续单独变更，不能借 Windows UI 迁移顺带切换。

## Impact and release boundary

新核心、UI、Windows 平台和安装目录见 [design.md](design.md)。现有 Ruby/Swift 路径保留为行为参考和可回退基线。第一阶段只允许 mock/隔离路径，不并行争用现用 WG peer 或改现用 Clash。用户最终安装包须包含后台、Mihomo、已支持 helper、许可证和清单；网络接入依赖外部 Clash 时，应明确其配置条件，不能宣称独立系统 VPN。实施任务见 [tasks.md](tasks.md)。
