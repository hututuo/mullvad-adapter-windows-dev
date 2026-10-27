# Design

`identity-profiles.json` 位于已有私有 state 目录；目录 0700，文件 0600，禁止符号链接、多硬链接、越界大小及非白名单模板字段。最多保存 8 份身份，不写进源码、公开日志或诊断。`active_id` 为空时沿用旧模板；设置后由同一文件提供启动身份与管理登录状态，避免跨两个文件提交造成账号/密钥混用。原 `wireguard-template.json` 与 `account.json` 保留作为旧基线。

`POST /account/identities/switch` 要求原有本机 capability、无 Origin、明确确认及 `expected_active_id`；返回现有 operation receipt。实际工作在公共操作 gate 和账户互斥下执行；worker 全部停止后再选择新身份，随后用原节点与原传输偏好验证。发生失败不擅自切换另一个账号，也不添加 DIRECT。

一次性导入脚本仅从本机私有文件与 stdin 读取账号/设备密钥；不联系官方 API，不创建或撤销设备，不选中身份，不启动进程、不覆盖已有资料。

菜单栏采用当前状态与 canary 时间限定延迟。后台继续以 IP 或 HTTPS 成功判断数据面存活，ICMP 不参与恢复判定；本机不确定性保持待复检。新增日志仅包括类型、延迟及分类。
