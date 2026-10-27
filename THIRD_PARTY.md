# 第三方来源与许可

自有适配器源码采用GPL-3.0-only；独立组件保留版权和许可，根LICENSE不改写上游条款。

- **Mihomo v1.19.31**：官方MetaCubeX未修改Windows x64二进制，GPL-3.0。版本/ZIP摘要见engines/mihomo-compatibility.json。Release附官方源码（tag解析commit `ab405bad5beeeac8b003bb01f60f134f6df54471`）、完整GPL文本及来源/摘要清单。runtime保留THIRD_PARTY_NOTICES.txt。
- **Microsoft WebView2**：Tauri嵌入Microsoft官方离线安装器，保留其许可流程；本项目不重新许可它。
- **Mac PQ helper**：helpers/pq-negotiator保留独立GPL-3.0-or-later及Mullvad依赖来源；Mac候选提供其源码、锁文件和许可及编译组件，Windows安装器不含它。
- **Rust/npm依赖**：锁文件记录精确依赖，各包适用自己的许可。
- **QUIC carrier**：helpers/quic-carrier链接Mullvad官方2026.5的mullvad-masque-proxy（固定SHA `19fb87407f4b81fe15372c2c7f8a20e7ab4eb220`，上游GPL-3.0-or-later）；包装器GPL-3.0-only。保留UPSTREAM.json、锁文件和可取得的对应源码；新的双端候选包含组件，旧包明确不提供该能力。Windows runtime清单校验组件文件大小、SHA256和x64格式。

[Mihomo v1.19.31](https://github.com/MetaCubeX/mihomo/tree/v1.19.31) · [GPL文本](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/LICENSE) · [固定源码](https://codeload.github.com/MetaCubeX/mihomo/tar.gz/ab405bad5beeeac8b003bb01f60f134f6df54471)

本公开仓库不含原私有Git历史或个人运行资料。
