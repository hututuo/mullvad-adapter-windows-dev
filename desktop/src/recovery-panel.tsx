import React from "react";
import type { Command, Dashboard } from "./app-api";
import { errorText } from "./app-api";
import { recoveryView } from "./recovery-view";
export function RecoveryPanel({data,busy,onAction,observationCurrent=true}:{data:Dashboard;busy:boolean;observationCurrent?:boolean;onAction:(command:Command)=>Promise<void>}) {
  const v=recoveryView(data,busy), p=data.recovery;
  return <section className="panel recovery-panel" aria-label="连接与自动恢复">
    <div className="panel-heading"><div><p className="eyebrow">CONNECTION RECOVERY</p><h2>{observationCurrent ? v.title : "上次连接状态 · 等待更新"}</h2></div>
      <span className={`pill ${observationCurrent && data.status === "connected" ? "positive" : ""}`}>{!observationCurrent ? "当前状态未确认" : data.status === "connected" ? data.readiness==="ready" ? "通道健康" : "通道可用，继续复测" : "保留当前城市"}</span></div>
    <ol className="recovery-steps" aria-label="自动恢复顺序">{["原入口重试","同节点备用入口","同城备用节点","QUIC / 原生保底","链式保底"].map((text,i)=><li key={text} className={!observationCurrent ? "" : v.index===i ? "current" : v.index>i ? "done" : ""} aria-current={observationCurrent && v.index===i ? "step" : undefined}><span>{i+1}</span>{text}</li>)}</ol>
    <div className="recovery-detail">
      <div><small>{observationCurrent ? "当前目标" : "上次目标"}</small><strong>{v.target ?? "尚未开始连接"}</strong><span>{v.inlet ? `${v.transport} · ${v.inlet}` : "连接后显示实际协议与入口"}</span></div>
      <div><small>{observationCurrent ? "本轮进度" : "上次进度"}</small><strong>{p?.attempt ? `已发起 ${p.attempt} 次` : "待命"}</strong><span>{p?.attempt ? `${p.elapsed_seconds} 秒 · 新尝试预算 ${p.budget_seconds} 秒` : "本机断网时暂停恢复"}</span></div>
      <div><small>下一步</small><strong>{!observationCurrent ? "等待最新状态" : p?.wait_seconds ? `${p.wait_seconds} 秒后继续` : v.chained && p?.direct_return_in_seconds != null ? `${p.direct_return_in_seconds} 秒后尝试直连` : data.status==="connected" ? "保持当前连接" : "按顺序自动恢复"}</strong><span>{v.next}</span></div>
    </div>
    <div className="recovery-feedback" role="status">{!observationCurrent ? "以上是上次记录，不据此判断当前是否断网；读取状态不会触发节点切换。" : data.last_error && !v.trial ? errorText(data.last_error) : data.status==="connected" ? v.chained ? "当前通过备用节点承载，最终出口仍为所选 Mullvad 城市。" : "短暂波动先复测，优先保留原节点与原入口。" : "不会因本机断网、过期探测或 DNS 单项异常而遍历节点。"}</div>
    <div className="panel-actions">
      <button className="primary" disabled={!v.canRetry} onClick={()=>void onAction({kind:"recovery_action",action:"retry_current"})}>重试当前节点</button>
      <button disabled={!v.canRetry} onClick={()=>void onAction({kind:"recovery_action",action:"retry_city"})}>重新自动恢复一轮</button>
      {v.chained ? <button disabled={!v.canRetry} onClick={()=>void onAction({kind:"recovery_action",action:"return_direct"})}>现在尝试直连</button>
        : <button disabled={!v.canRetry || !data.chain_node} onClick={()=>void onAction({kind:"recovery_action",action:"chain_fallback"})}>使用链式保底</button>}
      <button className="quiet" disabled={!v.canStop} onClick={()=>void onAction({kind:"disconnect"})}>停止连接与重试</button>
    </div>
  </section>;
}
