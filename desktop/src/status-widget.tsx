import React,{useEffect,useState} from "react";
import {listen} from "@tauri-apps/api/event";
import {getDesktopStatus,hideWidget,dragWidget,openWorkspace,type DesktopStatus} from "./desktop-api";
export function StatusWidget(){
  const [status,setStatus]=useState<DesktopStatus|null>(null);
  useEffect(()=>{let alive=true;void getDesktopStatus().then(v=>{if(alive)setStatus(v)}).catch(()=>{});const registration=listen<DesktopStatus>("desktop-status",e=>{if(alive)setStatus(e.payload)});return()=>{alive=false;void registration.then(f=>f()).catch(()=>{})}},[]);
  return <div className={`status-widget ${status?.state??"unknown"}`}>
    <button className="widget-globe" title="拖动状态窗" aria-label="拖动状态窗" onMouseDown={e=>{if(e.button===0)void dragWidget().catch(()=>{})}}><svg viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="13"/><ellipse cx="16" cy="16" rx="6" ry="13"/><path d="M3 16h26M5 9h22M5 23h22"/></svg></button>
    <button className="widget-body" onClick={()=>void openWorkspace().catch(()=>{})} title={status?`${status.headline} · ${status.relay??"暂无节点"} · 点击打开工作台`:"打开连接工作台"}><strong>{status?.headline??"正在读取状态…"}</strong><span>{status?.relay?`${status.stale?"上次：":""}${status.relay}`:"尚无当前节点"}</span><small>{status?.ping_ms!=null ? `ICMP ${status.ping_ms} ms · ${status.ping_age_seconds??0} 秒前` : "暂无近期延迟测量"}</small></button>
    <button className="widget-close" title="关闭悬浮窗" aria-label="关闭悬浮窗" onClick={()=>void hideWidget().catch(()=>{})}>×</button>
  </div>
}
