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
