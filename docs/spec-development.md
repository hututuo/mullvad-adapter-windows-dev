# 用规格推动本项目开发

Spec 是可检查的行为合同：发生什么、应如何响应、哪些行为不能发生，以及用什么证据验收。它不能保证 AI 一次写对，也不能替代代码审查或真实安装测试。架构文档解释系统如何组织；Spec 限定某次改动必须交付什么；私有 CONTEXT 记录现在做到哪一步。三者职责不同。

## 工具比较和本项目选择

核对日期：2026-10-05。以下是方法建议，未安装 CLI 或生成 Agent 命令。

| 工具 | 官方流程 | 本项目适用性 |
| --- | --- | --- |
| [GitHub Spec Kit](https://github.com/github/spec-kit) | 项目原则 → specify → plan → tasks → implement → converge；支持既有项目 | 适合希望逐阶段审查的大功能；并非只能新建项目，但本项目已存在原则/交接入口，初始化需避免重复或覆盖 |
| [OpenSpec](https://github.com/Fission-AI/OpenSpec) | explore / propose → proposal、specs、design、tasks → apply → archive | 推荐其增量变更结构；本项目已有后台/回归，按能力迁移更自然 |

工具不是本项目运行依赖。使用一个体系即可，不并排维护两套规格。推荐先采用 OpenSpec 的 Markdown 结构，再按需固定 CLI 版本、在任务分支初始化并审查新增文件；不能用初始化覆盖现有 AGENTS 或私有接手规则。官方命令可能随版本和 Agent 改变，CLI 当前要求 Node.js >=20.19.0，Spec Kit 要求 Python >=3.11 与 uv；这些是开发工具条件，不能出现在最终用户安装要求中。

本仓库已有的 [Windows 迁移变更](../openspec/changes/windows-shared-core/proposal.md) 是手工整理的项目具体规格草案。没有运行 `openspec init`、`apply`、`archive` 或正式 CLI validation。不要因为存在 `openspec/` 就称工具已完整接入，也不要把草案写成已实现。

## 一次改动的阅读和执行顺序

1. 读 AGENTS、源码架构和通过 Git 本地配置定位的私有 CONTEXT。核对实际源码、候选、运行版本。
2. `proposal.md`：问题、范围、保留行为、明确不做什么。一个变更尽量能独立验收；Windows 大迁移按 tasks 中的阶段继续切小变更。
3. `specs/<capability>/spec.md`：带稳定 ID 的 Requirement 和 WHEN/THEN Scenario，先写行为，不把选框架当成用户需求。
4. `design.md`：模块、协议、并发、错误/回退、数据迁移、备选方案与尚待验证的假设。只有这里决定如何实现。
5. `tasks.md`：把每项任务关联 Requirement ID、改动目录和验收方式；完成后填写证据，不凭描述勾选。
6. 实现一个可运行的阶段，核对代码/Spec/测试一致；发现需求变化时先修订对应 Spec 和设计。
7. 记录 PASS / FAIL / NOT_RUN / BLOCKED，绑定完整源码 SHA、云端候选和运行版本；真实验收完成后才能合并规格并归档。CLI 的 archive 不代表发布或用户验收通过。

官方当前 OpenSpec 使用 `/opsx:propose`、`/opsx:apply`、`/opsx:archive`；Codex 集成可能显示为 `$openspec-propose` 等技能，实际以初始化产生的入口为准。这些在 Agent 对话中使用，`openspec validate` 等 CLI 命令在终端中使用。[官方既有项目说明](https://github.com/Fission-AI/OpenSpec/blob/main/docs/existing-projects.md)与[Spec Kit 既有项目说明](https://github.github.io/spec-kit/guides/existing-projects.html)都要求从有界改动开始，不能假定工具替你完整还原旧代码需求。

## 本项目的具体例子

“断网后更智能、更快”无法直接验收。将它拆成：

> **WHEN** 所有物理网卡都没有可用接入，而 VPN 虚拟网卡仍显示在线，**THEN** 显示等待本机网络，暂停自动换节点，不写节点失败史，不添加 DIRECT 回落。
>
> **WHEN** 接入稳定恢复且原数据路径仍活着，但 DNS 测试失败，**THEN** 保留原节点，并显示 DNS 降级；不能仅凭这个失败换 IP。

然后分别验证：虚拟网卡过滤单测、事件序列/旧探针回放、Windows 多网卡真实测试、实际断网恢复计时。四种证据不能互相替代。

## 资料边界

源码仓库保存可公开的行为/接口/构建约束、脱敏场景和通用设计。机器路径、详细事故、运行节点/账号情况、私有计划执行进度和回滚证据仍进入 `project-dev-context` 的本项目目录。两处引用同一源码 SHA；不复制完整聊天、原始日志、凭据或私钥。没有读取私有资料的权限时，应明确接手范围不完整。
