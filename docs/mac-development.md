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

状态通信与隧道健康是两类证据。界面取消一次读取不计故障；晚到的旧响应不能覆盖新结果。单次传输失败显示“状态待更新”，连续三次且跨过至少十秒才显示“无法读取本机服务状态”。HTTP 错误与响应格式错误单独显示，均不等价于隧道断开。保留的快照必须带最后读取时间；成功读取后清除警告。此路径不会触发重连或修改节点。

`GET /status` 读取独立的内存 JSON 快照，不等待连接事务或操作队列的锁，也不做网络、磁盘读取。后台每秒尝试发布一次；锁忙则跳过，不刷新旧快照的时间。超过3秒或尚无快照时返回 HTTP 503（`status_snapshot_stale` / `status_snapshot_unavailable`），界面显示“状态更新延迟”，不能据此判定隧道中断。响应头 `X-Adapter-Status-Age-Ms` / `X-Adapter-Status-Capture-Ms` 提供快照年龄和采集耗时；控制决策仍使用原权威状态、原事务锁和原子提交。

界面状态读取有独立的本机直连 URLSession（无代理、缓存、cookie、凭据存储，超时仍5秒），与账号等长请求分池。状态和城市分别轮询，正常每轮结束后等5秒、操作中1秒；城市读取去重。状态无需等城市或 metrics 完成，手动刷新则并发更新三者。响应时间与服务器快照年龄都计入最后更新时间；旧版后台无时间头仍兼容。此方案消除共享锁和请求队列造成的额外等待，不能保证操作系统严重卡顿时线程仍按时运行。对应[规格](../openspec/changes/mac-lightweight-status/specs/status-publication/spec.md)与锁竞争/请求隔离回归。

`~/Library/Logs/MullvadLocalAdapter/ui-status.jsonl` 及 `.1` 各最多256 KiB，仅记录状态请求编号、错误类别/数值码、耗时、连续失败数、快照年龄、可选的发布年龄/采集耗时、界面版本和会话编号。正常快速轮询不逐条落盘；启动、失败、取消、丢弃旧结果、恢复与慢请求留痕。日志不接收任意错误正文、URL、HTTP响应或账号密钥。串行写队列最多64条待写事件，超额丢弃计数随下一条记录保存；导出等待刷新最多一秒。文件0600、目录0700，拒绝链接和特殊文件；复制排查资料包含两份日志。文件上限并非按天保留承诺。

只改界面时可单独构建并替换签名UI bundle，不必重启Ruby后台或Mihomo。替换前保存完整旧bundle，替换后核对后台/前端/worker/Clash进程身份和真实代理HTTPS。不要运行`install-daemon.rb`来部署UI补丁；不要通过真实断网、睡眠、同身份备用隧道或反复开关主窗制造测试故障。
