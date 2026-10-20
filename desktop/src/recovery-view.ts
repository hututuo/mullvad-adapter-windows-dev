import type { Dashboard } from "./app-api";
const stages: Record<string, [string, number]> = {
  local_front:["正在修复本地转发入口",0], idle:["等待连接",-1], waiting_network:["等待本机网络稳定",-1], confirming:["复测原路径，暂不换节点",0],
  original_inlet:["短重试原节点、原 SS 入口",0], same_relay_inlets:["尝试原节点的备用 SS 入口",1],
  same_city:["尝试同城备用节点",2], chain_fallback:["直连路线已用尽，启用链式保底",3],
  testing_backup:["正在测试备用路线的实际流量",3], restoring_previous:["正在恢复测试前的路线",3],
  returning_direct:["正在尝试回到 SS 直连",0], chain_connected:["链式保底已连接",3],
  connected:["SS 直连已连接",4], exhausted:["本轮恢复已结束",-1],
};
const next: Record<string,string> = {
  verify_original:"联网稳定后，先验证原路径", original_retry:"确认仍失败才重连原入口",
  same_relay_inlets:"仍失败时，尝试原节点的 1–2 个备用入口", same_city:"再尝试最多四个同城备用节点",
  chain_fallback:"直连均失败后，才尝试链式保底", new_round:"等待下一轮，也可以立即手动重试",
  return_direct:"后台会尝试回到直连，失败则恢复链式", monitor:"持续检查当前路径，短暂异常先复测",
  restore_chain_if_failed:"直连成功即保留；失败则恢复刚才的链式路线",
  restore_previous_after_test:"验证完成后恢复测试前的路线", verify_previous:"恢复后验证真实流量",
};
export function recoveryView(data: Dashboard, busy: boolean) {
  const p = data.recovery;
  const [title, index] = stages[p?.stage ?? "idle"] ?? ["正在核对连接",-1];
  const online = data.physical_attachment === "available";
  const connected = data.status === "connected";
  const trial = ["testing_backup","restoring_previous","returning_direct"].includes(p?.stage ?? "");
  return { title, index, next:next[p?.next ?? ""] ?? "可手动重试当前节点或当前城市",
    canRetry:online && !busy && !trial && data.identity_configured && !!data.settings.selected_city,
    canStop:!!data.operation || !!data.active_relay || data.retry_in_seconds != null || !!p && p.attempt>0 && !connected,
    chained:!!data.connection?.chained && connected,
    target:p?.relay ?? data.active_relay ?? null, inlet:p?.inlet ?? null, trial };
}
