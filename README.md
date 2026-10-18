# Mullvad Adapter Windows — 开发维护仓库

本仓库用于维护与Clash Verge Rev配合的Windows本地Mullvad隧道适配器：直接阅读源码、修复问题、补测试并构建候选。不是Mullvad或Clash官方项目。

这是独立的公开维护入口，不包含朋友接收、Agent代安装或报告发回流程。面向使用者的安装包和引导仍在[分发仓库](https://github.com/hututuo/mullvad-adapter-windows)。两仓库没有自动同步；维护端修复经过检查和单独验收后，再按发布授权更新分发仓库。

## 开始开发

先读[AGENTS.md](AGENTS.md)、[开发与构建](docs/development.md)、[Windows通道维护参考](docs/windows-maintenance.md)、[架构](docs/architecture.md)和[能力边界](docs/network-capabilities.md)。涉及行为变化再读[规格流程](docs/spec-development.md)。

- `core/`：Rust后台、恢复策略、账号API、目录、IPC、Mihomo、物理UDP绑定与Clash集成。
- `desktop/`：Tauri 2 / React / TypeScript界面与Windows native命令。
- `packaging/windows/`、`engines/`：完整NSIS候选、runtime清单、固定内核和摘要。
- `openspec/`：行为合同与迁移设计，历史任务状态不等于当前验收结果。
- `daemon/`、`ui/`、`helpers/`：导入基线的Mac参考实现和兼容检查，不是当前Mac完整维护分支或Windows运行依赖。
- `.github/workflows/windows-shared-core.yml`：检查和手动候选构建；没有签名、公开Release或自动部署。

Windows完整构建需要Rust/MSVC、Windows SDK、Node/npm和Python。只做源码审查无需装全套；最终安装用户也不需要开发工具。具体命令和候选取得方式见[development.md](docs/development.md)。

## 基线与范围

从已公开审查的源码快照`7e7acf58855cc77280bd440a9e2c8c22d2179b18`建立独立Git历史；未导入旧私有Git历史或私人开发资料。原成品内部源码是`a90c22123c8578871614febee1ce5ee9f4d2db89`，见[SOURCE_BASELINE.json](SOURCE_BASELINE.json)。本仓库新提交不等于该成品已重新编译。

基线已有同城恢复、账号设备管理和Clash独立配置；SS承载UDP，不能作为禁UDP网络的TCP保底。Windows必需的多跳/PQ等未支持能力显式拒绝。已有环境的历史安装/连接结果不代表本仓库新构建、干净系统、所有TUN环境或长期稳定性通过。

开发优先保持原路径与城市、peer独占、取消/代次/owner/freshness守卫；物理离线等待恢复，不把本机断网计为所有节点失效。front没有DIRECT回退，但本软件不是全机kill switch。

## 许可与资料

自有源码GPL-3.0-only，见[LICENSE](LICENSE)；第三方来源与许可见[THIRD_PARTY.md](THIRD_PARTY.md)。不得提交账号、密钥、订阅、DPAPI文件、原始诊断或私人运行目录。内部进度与机器排障证据仍留私有资料；公开维护可以独立开始，无法访问私人历史时明确知识边界。
