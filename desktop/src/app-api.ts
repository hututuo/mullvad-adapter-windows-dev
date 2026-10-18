import { invoke } from "@tauri-apps/api/core";
export type Settings = {
  favorite_cities: string[];
  selected_city: string | null;
  bootstrap_port: number | null;
  front_port: number;
  automatic_recovery: boolean;
  required_multihop: boolean;
  required_pq: boolean;
};
export type City = {
  id: string;
  name: string;
  country: string;
  relay_count: number;
};
export type Relay = {
  hostname: string;
  city: string;
  active: boolean;
  ipv4: boolean;
  ipv6: boolean;
  shadowsocks: boolean;
  last_ping_ms: number | null;
  readiness: string | null;
};
export type Device = {
  id: string;
  name: string;
  public_key: string;
  created: string;
  current: boolean;
};
export type ProbeOutcome = "passed" | "rejected" | "cancelled" | "deadline" | "timeout" | "unavailable" | "not_run_dns_failed";
export function probeText(value: boolean | null, outcome?: ProbeOutcome) {
  if (outcome) return {
    passed: "通过", rejected: "校验未通过", cancelled: "检查已取消",
    deadline: "检查超时", timeout: "检查超时", unavailable: "检查不可达",
    not_run_dns_failed: "未测（DNS 未通过）",
  }[outcome];
  return value === null ? "未测" : value ? "通过" : "未通过";
}
export type Dashboard = {
  sequence: number;
  boot_id: string;
  build: string;
  source_sha: string;
  status: string;
  physical_attachment: string;
  settings: Settings;
  front_ready: boolean;
  front_selected: string;
  identity_configured: boolean;
  device_draft: {state:string;public_key:string;device_id:string|null;device_name:string|null}|null;
  device_name: string | null;
  public_key: string | null;
  active_relay: string | null;
  connection?: { relay:string; city:string; inlet:string; interface_index:number; instance:number; phase:string; ip:boolean|null; dns:boolean|null; https:boolean|null; probes?: {ip:ProbeOutcome;dns:ProbeOutcome;https:ProbeOutcome} } | null;
  readiness: string | null;
  cities: City[];
  metadata_source: string;
  metadata_updated_at: number | null;
  account: {
    authenticated: boolean;
    expiry: string | null;
    devices: Device[];
    error_code: string | null;
  };
  operation: string | null;
  last_error: string | null;
  logs_path: string;
  last_report_path: string | null;
  logging_degraded: boolean;
  logging_dropped: number;
  quick_test: {
    city: string;
    total: number;
    completed: number;
    replies: number;
    no_reply: number;
    local_errors: number;
    discarded: number;
    unmeasured: number;
    active: boolean;
    cancelled: boolean;
    finished_at: number | null;
  } | null;
  city_candidates: {
    city: string;
    hostname: string;
    ping_ms: number;
    measured_at: number;
  }[];
};
export type Command =
  | { kind: "connect_relay"; hostname: string }
  | {
      kind:
        | "dashboard"
        | "refresh_catalogue"
        | "connect"
        | "disconnect"
        | "cancel_operation"
        | "account_refresh"
        | "account_logout"
        | "export_report"
        | "shutdown";
    }
  | { kind: "save_settings"; settings: Settings }
  | { kind: "select_city" | "quick_test" | "full_test"; city: string }
  | { kind: "relays"; city: string | null; page: number }
  | { kind: "account_login"; account: string }
  | { kind: "remove_device"; device_id: string }
  | { kind: "create_device" | "use_created_device" | "reveal_key"; confirm: boolean }
  | { kind: "redeem_voucher"; voucher: string };
export type Reply =
  | { kind: "dashboard"; dashboard: Dashboard }
  | { kind: "relays"; relays: Relay[]; page: number; total: number }
  | { kind: "accepted"; operation_id: string }
  | { kind: "report"; path: string }
  | { kind: "private_key"; private_key: string }
  | { kind: "error"; code: string };
export function request(command: Command): Promise<Reply> {
  return invoke("app_request", { command });
}
export function stopBackendAndExit(): Promise<void> {
  return invoke("stop_backend_and_exit");
}
export function copyReport(path: string): Promise<string> {
  const name = path.split(/[\\/]/).pop() ?? "";
  if (!/^report-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i.test(name)) {
    return Promise.reject("invalid_report_id");
  }
  return invoke("copy_last_report", { expectedReport: name });
}
export function reportMatchesOperation(path: string | null, operation: string | null) {
  return !!path && !!operation && path.split(/[\\/]/).pop() === `report-${operation}.json`;
}
export const statusText: Record<string, string> = {
  disconnected: "尚未连接",
  starting_front: "正在准备本地入口",
  connecting: "正在验证连接",
  connected: "已连接",
  degraded_dns: "连接可用，DNS 待恢复",
  degraded_service: "连接可用，服务待恢复",
  waiting_network: "等待本机网络恢复",
  network_recovering: "正在验证原连接",
  unknown_network: "正在确认本机网络",
  blocked: "连接条件未满足",
  stopping: "正在安全断开",
};
const errors: Record<string, string> = {
  backend_unavailable: "后台暂不可达，正在重新连接。",
  backend_start_failed: "后台启动失败，请导出诊断记录。",
  backend_version_mismatch: "界面与后台版本不一致，请先退出旧后台再启动这版应用。",
  incompatible_backend: "后台接口版本不兼容，请核对安装版本。",
  invalid_handshake: "后台握手未通过，请核对安装版本。",
  runtime_build_identity_missing: "此构建缺少版本标识，请使用完整候选。",
  clipboard_busy: "剪贴板正在被占用；文件已保留，可点击重新复制。",
  clipboard_write_failed: "剪贴板写入失败；文件已保留，可点击重新复制。",
  clipboard_window_unavailable: "窗口暂不可用；文件已保留，可点击重新复制。",
  clipboard_allocation_failed: "剪贴板暂不可用；文件已保留，可点击重新复制。",
  report_changed_reconcile: "诊断文件已更新，请复制当前显示的最新文件。",
  report_not_available: "诊断文件还未生成，请稍候。",
  report_write_failed: "诊断文件未能保存，请检查日志位置和磁盘空间。",
  operation_busy: "上一项操作还在完成，请稍候。",
  backend_stopping: "正在停止后台，界面不会重新启动它。",
  backend_stop_unconfirmed: "后台退出尚未确认，已保留现场且不会自动重启。请检查日志后再升级。",
  waiting_network: "本机网络尚未恢复，暂不更换节点。",
  identity_missing: "请登录账号创建本机设备，或导入独立设备身份。",
  candidate_evidence_stale: "探测结果在提交前已过期，正在保留同一节点重试；这不代表节点失效。",
  active_evidence_stale: "本次健康检查证据已过期，保留当前通道并重新核对。",
  candidate_not_ready: "这个节点未通过连接验证；请查看诊断中的具体结果。",
  original_inlet_withdrawn: "原入口已从官方目录撤下，正在当前城市内恢复。",
  worker_configuration_rejected: "连接配置未通过校验；请导出诊断文件。",
  worker_route_unavailable: "当前物理出口暂不可用，等待网络稳定。",
  peer_reservation_unavailable: "本机已有通道正在使用这个设备身份，请先断开。",
  worker_start_failed: "隧道进程未能启动，请查看诊断。",
  worker_controller_unavailable: "无法确认隧道进程已就绪，入口保持阻止。",
  worker_start_cancelled: "此次连接已取消。",
  worker_start_deadline: "隧道启动超时，入口保持阻止。",
  same_city_recovery_exhausted: "本轮同城候选未能恢复；请查看诊断或选择本城其他节点。",
  recovery_budget_exhausted: "本轮恢复已达到时限；没有切换到其他城市。",
  disconnect_before_identity_change: "请先断开连接，再启用新设备。",
  device_creation_outcome_unknown: "设备注册结果未确认，密钥已保留；请先刷新官方列表核实。",
  device_draft_other_account: "本机保留着另一个账号的设备草稿，未覆盖其密钥。",
  identity_backup_occupied: "已有另一份旧身份备份，请先妥善保管，未覆盖任何密钥。",
  identity_activation_uncertain: "新身份的本地写入结果未确认，已暂停使用旧身份。请正常停止后台后重新打开，再核对本机设备身份；密钥和备份均已保留。",
  bootstrap_missing: "请在设置中指定可用的本地外网代理端口。",
  bootstrap_unavailable: "本地外网代理不可用，请检查指定端口。",
  api_unreachable: "账号服务尚未连接，请检查外网代理出口并导出诊断。",
  backend_stop_worker_failed: "停止操作未能启动；后台不会自动重启，请重试停止。",
  api_proxy_tunnel_failed: "外网代理未能建立账号服务连接，请检查代理出口并导出诊断。",
  api_tls_failed: "账号服务的 TLS 安全连接未通过；没有跳过证书验证。",
  api_deadline_exceeded: "账号服务请求超时，请检查外网代理出口或导出诊断。",
  protection_unsupported: "Windows 引擎尚未验收此保护，连接已阻止。",
  account_required: "请先登录账号。",
  invalid_account: "账号应为 16 位数字。",
  current_device_protected: "不能在此撤销当前隧道使用的设备。",
  mutation_outcome_unknown: "服务器结果未确认，请刷新核对，勿重复提交。",
  outcome_unknown: "服务器结果未确认，请刷新核对，勿重复提交。",
  egress_proof_unavailable: "物理出口验证未通过，已阻止切换。",
  invalid_settings: "请检查城市和端口设置。",
  runtime_invalid: "运行组件校验失败，请重新安装可信候选。",
  selected_city_missing: "先添加并选择一个常用城市。",
  metadata_cache_access_denied: "本机节点缓存无权读取，请导出诊断；没有自动改动旧文件权限。",
  metadata_cache_read_failed: "本机节点缓存读取失败，请更新目录或导出诊断。",
  invalid_metadata: "节点目录格式未通过校验，请更新目录。",
  metadata_missing: "节点目录尚未取得，请先更新目录。",
  physical_binding_unavailable: "本机物理出口尚未确认，请等待网络稳定后重试。",
  quick_targets_missing: "这个城市没有可快速检查的 IPv4 节点。",
  quick_city_too_large: "这个城市超过单轮检查上限，请查看节点目录。",
  quick_start_failed: "快速检查未能启动，请导出诊断记录。",
  operation_cannot_cancel: "此操作已提交，需等待结果确认。",
  boot_changed_reconcile: "后台刚重启，请核对当前状态后重试。",
};
export function errorText(code: string) {
  return errors[code] ?? `操作未完成（${code}）`;
}
export function bridgeError(error: unknown) {
  return errorText(typeof error === "string" && Object.hasOwn(errors, error) ? error : "backend_unavailable");
}
export function timeText(seconds: number | null) {
  return seconds === null
    ? "尚未更新"
    : new Date(seconds * 1000).toLocaleString("zh-CN", { hour12: false });
}

export const operationText: Record<string, string> = {
  connect: "结束后台测速并准备连接",
  metadata_refresh: "更新官方目录",
  account_login: "登录账号",
  account_refresh: "刷新账号",
  account_logout: "退出账号",
  device_remove: "撤销设备",
  device_create: "创建本机设备",
  device_activate: "核对并启用本机设备",
  voucher_redeem: "兑换充值码",
  report_export: "生成诊断文件",
  settings_save: "保存设置",
  quick_test: "检查当前城市 · 最多四路 ICMP",
};
