# Windows 开发、检查与候选构建

这是维护端流程：直接修源码、补测试和构建候选，不要求先完成朋友侧接收或报告发回。目录/通道详解见[Windows维护参考](windows-maintenance.md)，行为变更见[规格流程](spec-development.md)。

## 环境与检查

完整构建使用Windows x64、Visual Studio C++ Build Tools和Windows SDK、Rust MSVC工具链、Node/npm和Python 3.11+。当前候选workflow固定Rust 1.97.1与Node 24.19.0；核心单测job固定Rust 1.88.0。锁文件不可随意更新，核心的最低Rust版本不代表完整桌面的最低版本。首次下载编译器、SDK和依赖可能较大。

在仓库根目录的PowerShell执行：

```powershell
cargo +1.97.1 fmt --manifest-path core/Cargo.toml --all -- --check
cargo +1.97.1 test --manifest-path core/Cargo.toml --locked
python packaging/windows/test_build_candidate.py
python packaging/windows/test_stage_runtime.py
Push-Location desktop
npm ci --ignore-scripts
npm run build
Pop-Location
cargo +1.97.1 test --manifest-path desktop/src-tauri/Cargo.toml --locked
```

按改动选择检查，不为文档修改强行编译全套。Windows专属/ignored测试如实记NOT_RUN；不把Mac/Linux结果当Windows API、路由或安装证据。需要Mac兼容检查时参考workflow，导入的ui/core旧skeleton描述和openspec任务是历史，当前入口以实际命令路由及本维护文档为准。

## 完整候选

源码变更提交后，依[完整打包说明](../packaging/windows/README.md)在Windows运行：

```powershell
$sourceSha = (git rev-parse HEAD).Trim()
python packaging/windows/build_candidate.py --source-sha $sourceSha --output C:/build-output/adapter-candidate --target-dir C:/build-cache/adapter-candidate
```

输出目录必须是新目录，缓存不能被两个构建同时使用。先完成npm依赖安装；不把脏源码的产物标成HEAD。脚本打包后台、固定Mihomo、清单、许可、离线WebView2及静态MSVC CRT，生成candidate.json；不安装、不签名、不发布。最终用户不用装编译器、Rust、Node或Python，外部Clash独立存在。

runtime/manifest.json、UI内嵌摘要和后台源码SHA必须匹配；不要单独替换一个exe。记录完整源码SHA、平台/架构、文件名/大小/SHA256、签名状态和真实测试。`packaged_desktop`与恢复后的编译器输出哈希不同，不能据此误判已安装包。

## GitHub Actions

复用[windows-shared-core.yml](../.github/workflows/windows-shared-core.yml)：

- `core-checks`、`mihomo-config-parser`、`macos-compatibility`、`desktop-checks`负责各自检查；没有真实账号或生产隧道。
- 在Actions手动运行workflow，`build_candidate=false`只检查，`true`在所有前置job通过后生成unsigned Windows x64 NSIS候选。
- 从对应运行的Artifacts取`windows-installer-candidate-<完整SHA>`，包含安装器和candidate.json。开发agent/UI artifact不是完整安装器。
- 签名与publish没有接入自动步骤。工作流文件存在不等于运行成功；读取真实运行号、headSha和各job conclusion，不能把skipped/cached/ignored写PASS。

本次建立维护仓库只复用workflow，未宣称在新仓库重新跑完云端构建、安装或真实网络验收。

## 维护后如何更新分发

维护仓库与[分发仓库](https://github.com/hututuo/mullvad-adapter-windows)独立，没有自动同步或默认镜像。修复完成后按用户授权，把经过审查的源码变更有选择地同步，保留本仓库开发入口和分发仓库接收入口各自职责；不要整树覆盖文档。构建产物必须绑定实际构建提交，不能沿用旧a90标识。公开Release、tag、feed、签名和现用安装分别按授权处理。

历史a90安装器、当前维护源码、新候选和实际运行四者分别记录，见[SOURCE_BASELINE.json](../SOURCE_BASELINE.json)。新增诊断要避免输出用户路径和设备标识；原始报告仍先本机过滤，不传进公开CI。
