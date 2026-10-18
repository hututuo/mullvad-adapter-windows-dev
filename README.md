# Mullvad Adapter — macOS / Windows 开发维护仓库

本仓库统一维护与Clash配合的macOS和Windows本地Mullvad隧道适配器：直接阅读源码、修复问题、补测试并构建候选。不是Mullvad或Clash官方项目。仓库URL暂保留原windows-dev名称。

这是独立的公开维护入口，不包含朋友接收、Agent代安装或报告发回流程。面向使用者的安装包和引导仍在[分发仓库](https://github.com/hututuo/mullvad-adapter-windows)。两仓库没有自动同步；维护端修复经过检查和单独验收后，再按发布授权更新分发仓库。

## 开始开发

先读[AGENTS.md](AGENTS.md)、[开发入口](docs/development.md)和[架构](docs/architecture.md)。Mac开发再读[Mac维护与构建](docs/mac-development.md)、[账号设备](docs/account-devices.md)、[Mac能力差距](docs/mac-parity.md)；Windows开发读[通道维护参考](docs/windows-maintenance.md)和[能力边界](docs/network-capabilities.md)。涉及行为变化再读[规格流程](docs/spec-development.md)。

- `core/`：Rust后台、恢复策略、账号API、目录、IPC、Mihomo、物理UDP绑定与Clash集成。
- `desktop/`：Tauri 2 / React / TypeScript界面与Windows native命令。
- `packaging/windows/`、`engines/`：完整NSIS候选、runtime清单、固定内核和摘要。
- `openspec/`：行为合同与迁移设计，历史任务状态不等于当前验收结果。
- `daemon/`、`ui/`、`helpers/`：当前Mac Ruby后台、SwiftUI界面和PQ helper源码，不是Windows运行依赖。
- `.github/workflows/windows-shared-core.yml`：检查和手动候选构建；没有签名、公开Release或自动部署。
- `.github/workflows/checks-and-candidate.yml`：Mac检查和arm64候选；不签名、不公开发布、不安装。

Windows完整构建需要Rust/MSVC、Windows SDK、Node/npm和Python。只做源码审查无需装全套；最终安装用户也不需要开发工具。具体命令和候选取得方式见[development.md](docs/development.md)。

## 基线与范围

Windows从已公开审查的源码快照`7e7acf58855cc77280bd440a9e2c8c22d2179b18`导入，原成品内部源码是`a90c22123c8578871614febee1ce5ee9f4d2db89`。Mac按模块同步自`784f2fd9ef83d44aa4ad62441144f8ac1145bde3`，版本1.9.1/build13，包含账号/首次身份、窗口/Dock及DNS兼容修复。两端版本分别映射在[SOURCE_BASELINE.json](SOURCE_BASELINE.json)；没有导入原私有Git历史或私人运行资料。本仓库新提交不等于已重编两端安装器。

基线已有同城恢复、账号设备管理和Clash独立配置；SS承载UDP，不能作为禁UDP网络的TCP保底。Windows必需的多跳/PQ等未支持能力显式拒绝。已有环境的历史安装/连接结果不代表本仓库新构建、干净系统、所有TUN环境或长期稳定性通过。

Mac有自己的SwiftUI/Ruby账号与连接路径、多跳及单跳PQ；Windows的一键独立Clash配置等功能尚未全部接到Mac。统一源码仓库不代表双端功能或安装验收已经一致，见[Mac差距清单](docs/mac-parity.md)。

开发优先保持原路径与城市、peer独占、取消/代次/owner/freshness守卫；物理离线等待恢复，不把本机断网计为所有节点失效。front没有DIRECT回退，但本软件不是全机kill switch。

## 许可与资料

自有源码GPL-3.0-only，见[LICENSE](LICENSE)；第三方来源与许可见[THIRD_PARTY.md](THIRD_PARTY.md)。不得提交账号、密钥、订阅、DPAPI文件、原始诊断或私人运行目录。内部进度与机器排障证据仍留私有资料；公开维护可以独立开始，无法访问私人历史时明确知识边界。
