export type EventItem = {
  time: number; stage: string; code: string;
  relay?: string | null; city?: string | null; phase?: string | null;
  ip?: string | null; dns?: string | null; https?: string | null;
};
// Cover the backend's entire closed event vocabulary. Technical codes remain
// available separately, but the primary reading path is ordinary language.
export const eventMessages: Record<string, string> = {
  agent_started:"后台已启动", agent_stopped:"后台已退出", started:"开始建立连接",
  ready_reject:"本地入口已准备，尚未放行流量", stopped:"已停止", stopped_uncertain:"停止结果尚待确认",
  cleanup_uncertain:"清理结果尚待确认，保留现场", available:"本机已取得网络接入", unavailable:"本机网络断开，暂停重试",
  unknown:"暂时无法确认本机网络", binding_changed:"网卡或路由信息变化，正在重新核对",
  cancelled:"检查已取消", complete:"检查已完成",
  invalid_metadata:"官方节点目录未通过校验", policy_write_failed:"连接偏好保存失败",
  report_write_failed:"排查文件保存失败", metadata_cache_write_failed:"新目录已取得，但本机缓存保存失败",
  metadata_cache_access_denied:"没有权限读取节点目录缓存", metadata_cache_read_failed:"节点目录缓存读取失败",
  metadata_missing:"尚未取得节点目录", metadata_refresh_started:"正在更新官方节点目录",
  metadata_refresh_complete:"官方目录检查已完成", metadata_refresh_unavailable:"官方节点目录暂时无法更新",
  metadata_unchanged:"官方连接目录没有变化", metadata_connection_parameters_changed:"官方目录有变化，请查看更新内容",
  metadata_baseline_recorded:"已取得首次目录，暂无旧数据可对比",
  recovery_history_save_failed:"SS 重试记录保存失败，重启后可能无法继续去重",
  cache_write_failed:"已验证的接口地址缓存保存失败",
  account_required:"请先登录账号", identity_missing:"尚未配置本机设备身份",
  current_device_protected:"当前设备受保护，没有撤销", device_not_found:"没有找到指定设备",
  outcome_unknown:"本次账号操作结果尚未确认", invalid_api_command:"账号操作请求无效",
  invalid_bootstrap_proxy:"账号服务的独立代理配置无效", invalid_account_number:"账号号码格式不正确",
  invalid_voucher_code:"充值码格式不正确", invalid_device_id:"设备编号格式不正确",
  invalid_public_key:"公钥格式不正确", api_unreachable:"账号服务暂时无法连接",
  api_proxy_tunnel_failed:"账号服务的代理连接失败", api_tls_failed:"账号服务的安全连接校验失败",
  api_deadline_exceeded:"账号服务请求超时", api_response_too_large:"账号服务返回内容超过限制",
  invalid_api_response:"账号服务返回格式异常", mutation_outcome_unknown:"账号变更可能已提交，正在核对结果",
  invalid_account:"账号未通过验证", invalid_access_token:"账号登录凭据未通过验证",
  invalid_voucher:"充值码未通过验证", voucher_used:"充值码已使用", api_rejected:"账号服务拒绝了本次请求",
  device_creation_outcome_unknown:"新建设备结果尚未确认", device_creation_not_confirmed:"尚未确认新设备已登记",
  device_draft_invalid:"设备草稿未通过校验", device_draft_unavailable:"设备草稿暂不可用",
  device_draft_write_failed:"设备草稿保存失败", device_draft_readback_failed:"保存后无法确认设备草稿",
  device_draft_missing:"没有找到设备草稿", device_draft_other_account:"设备草稿属于其他账号",
  device_not_registered:"设备尚未在官方登记", public_key_in_use:"这个公钥已被设备使用",
  identity_backup_occupied:"设备身份备份位置已占用，没有覆盖", identity_activation_uncertain:"设备身份启用结果尚未确认",
  identity_store_write_failed:"本机身份保存失败", identity_store_read_failed:"本机身份读取失败",
  identity_store_readback_mismatch:"身份保存后的核对不一致", random_unavailable:"暂时无法生成安全随机数据",
  maintenance_started:"开始轻量维护备用节点", maintenance_preempted:"轻量维护让位给连接操作",
  maintenance_complete:"备用节点轻量维护完成", maintenance_cancelled:"备用节点轻量维护已取消",
  connected:"连接成功", disconnected:"连接已停止", probing:"正在检查连接是否可用",
  degraded_preserved:"隧道仍可用，保留当前节点并继续检查异常项",
  candidate_not_ready:"这个候选节点未通过完整连接检查", same_relay_inlet_retry:"正在尝试同一节点的其他 SS 入口",
  same_relay_chain_retry:"正在尝试同节点的备用承载路线", chain_not_configured:"尚未选择链式保底节点",
  chain_configuration_invalid:"链式保底配置未通过校验", chain_write_failed:"链式保底配置保存失败",
  chain_verified_missing:"没有可恢复的已验证备用路线", chain_configured:"链式备用路线已保存，尚不代表隧道可用",
  recovery_retry_scheduled:"本轮未恢复，已安排下一轮重试", recovery_retry_started:"开始新一轮自动恢复",
  shadowsocks_inlets_exhausted:"本轮可尝试的 SS 入口已用完", candidate_cancelled:"候选检查已取消，不计为节点失效",
  candidate_start_failed:"候选通道未能启动", worker_start_cancelled:"隧道启动已取消",
  worker_route_unavailable:"没有找到可用的物理出口路由", worker_chain_resolution_failed:"链式承载的地址解析失败",
  worker_configuration_rejected:"隧道配置未通过校验", peer_reservation_unavailable:"设备通道仍被使用，等待安全清理",
  worker_start_failed:"隧道进程启动失败", worker_controller_unavailable:"暂时无法读取隧道进程状态",
  worker_start_deadline:"隧道进程启动超时", candidate_probe_failed:"候选通道检查未通过",
  candidate_stale:"候选结果已过期，需要重新确认", candidate_evidence_stale:"候选测量已过期，不据此判节点失效",
  active_evidence_stale:"原路径测量已过期，需要重新确认", candidate_commit_failed:"候选通道启用失败",
  candidate_commit_stale:"启用前连接环境已变化，旧结果不再采用", candidate_selection_failed:"本地入口未能切到候选通道",
  connection_cancelled:"连接操作已取消", tunnel_command_busy:"隧道操作正在进行，等待处理",
  tunnel_transaction_failed:"本次隧道操作未完成", active_probe_failed:"原连接检查未通过，按恢复顺序处理",
  active_probe_local_failure:"本机检查过程异常，暂不判节点失效", active_probe_cancelled:"原连接检查被取消，稍后重验",
  active_binding_changed:"网卡环境变化，重新核对原路径", active_local_rebuild:"正在按原节点重建本地通道",
  active_data_failed:"原连接的数据检查失败，先复测原路径", active_failure_confirmation:"正在快速复测，确认是否需要重连",
  active_front_repair_failed:"正在处理本地转发入口，优先保留后端隧道",
  original_inlet_short_retry:"正在重试原节点、原 SS 入口", direct_routes_exhausted_chain_last:"本轮直连路线用尽，最后尝试链式保底",
  route_trial_failed:"路线测试未通过", route_trial_failed_restore_previous:"路线测试未通过，正在恢复之前的连接",
  restore_previous_failed_use_verified_backup:"原路线尚未恢复，尝试已验证的备用承载",
  network_binding_changed:"连接期间网卡环境变化，暂停旧尝试", waiting_network_settle:"等待本机网络稳定后再重试",
  direct_verified:"账号接口直连已验证，不代表业务隧道已连通",
  independent_proxy_verified:"账号接口的独立代理已验证，不代表业务隧道已连通",
  healthy_tunnel_verified:"账号接口通过现有健康隧道访问成功",
  active_worker_missing:"当前隧道进程不存在，需要恢复", relay_not_active:"官方目录中的这个节点已不再可用",
  original_inlet_withdrawn:"官方目录已撤回原 SS 入口", same_city_recovery_exhausted:"本轮同城候选未能恢复，等待下一轮或手动重试",
  recovery_budget_exhausted:"本轮新尝试预算已用完，等待下一轮重试",
};
const cancelled = new Set(["cancelled","candidate_cancelled","worker_start_cancelled","connection_cancelled","active_probe_cancelled","maintenance_cancelled","maintenance_preempted","binding_changed","network_binding_changed","active_binding_changed","candidate_stale","candidate_evidence_stale","active_evidence_stale"]);
export function eventView(item: EventItem) {
  const title = eventMessages[item.code] ?? "记录了一项新的系统事件";
  const node = item.relay ? `节点 ${item.relay}` : item.stage === "connection" ? "当前连接（未记录节点）" : "本机服务";
  const ok = ["connected","complete","maintenance_complete","metadata_refresh_complete","available","direct_verified","independent_proxy_verified","healthy_tunnel_verified"].includes(item.code);
  const bad = !cancelled.has(item.code) && /failed|exhausted|unavailable|rejected|uncertain|invalid|missing|unregistered|not_ready/.test(item.code);
  const outcomes: Record<string,string> = {passed:"通过", rejected:"未通过",cancelled:"已取消",deadline:"超时",timeout:"超时",unavailable:"无法检查",not_run_dns_failed:"未测（DNS 未通过）"};
  const probes = ([["IP",item.ip],["DNS",item.dns],["HTTPS",item.https]] as const)
    .filter(([,value])=>value!=null).map(([key,value])=>`${key}：${outcomes[value!] ?? "结果未知"}`).join(" · ");
  return { title: `${node} · ${title}`, probes, tone:ok ? "success" : bad ? "warning" : "info" };
}
export function eventTimestamp(time:number) {
  const date=new Date(time*1000);
  return Number.isFinite(date.getTime()) ? {label:date.toLocaleString("zh-CN",{hour12:false}),iso:date.toISOString()} : {label:"时间不可用",iso:undefined};
}
