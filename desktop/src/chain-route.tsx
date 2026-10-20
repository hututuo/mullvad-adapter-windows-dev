import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { errorText, request, timeText, type Dashboard, type Settings } from "./app-api";
type Choice={name:string;fingerprint:string};
type AutoResult={selected?:string;accepted?:boolean;kept?:boolean};
const pause=(ms:number)=>new Promise<void>(resolve=>window.setTimeout(resolve,ms));
export function useChainBackup(data:Dashboard|null) {
  const [working,setWorking]=useState(false),[notice,setNotice]=useState(""),[choices,setChoices]=useState<Choice[]>([]),[selected,setSelected]=useState("");
  const current=useRef(data),alive=useRef(true),flight=useRef(false),next=useRef(0);
  const generation=useRef(0);
  current.current=data;
  useEffect(()=>{setSelected(data?.settings.chain_selection??"");},[data?.settings.chain_selection]);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  async function prepare(manual:boolean) {
    const choice=manual?choices.find(c=>c.name===selected):undefined;
    return invoke<AutoResult>("clash_request",{input:{kind:"chain_auto",directory:null,...(choice?{chain_name:choice.name,chain_fingerprint:choice.fingerprint}:{})}});
  }
  async function maintain(manual=false) {
    if(flight.current||!current.current)return;
    flight.current=true;setWorking(true);
    try {
      const result=await prepare(manual);
      if(alive.current)setNotice(result.kept?"当前正在使用已保存的备用路线，继续维护这条连接。":`已自动准备备用：${result.selected??"本机节点"}。直连恢复全部失败后才启用。`);
      next.current=performance.now()+30*60*1000;
    }catch(e){next.current=performance.now()+5*60*1000;if(alive.current)setNotice(errorText(typeof e==="string"?e:"clash_not_found"));}
    finally{flight.current=false;if(alive.current)setWorking(false);}
  }
  async function loadChoices() {
    try{const r=await invoke<{choices:Choice[]}>("clash_request",{input:{kind:"chain_list",directory:null}});
      if(alive.current){setChoices(r.choices);setSelected(s=>r.choices.some(c=>c.name===s)?s:"");}
    }catch(e){if(alive.current)setNotice(errorText(typeof e==="string"?e:"clash_not_found"));}
  }
  async function test() {
    if(flight.current||!current.current)return;
    flight.current=true;setWorking(true);setNotice("正在自动选择备用并验证实际流量…");
    const token=generation.current,boot=current.current.boot_id,previous=current.current.backup_verified_at;
    try {
      const result=await prepare(!!selected),saveDeadline=performance.now()+12_000;
      let saved=false;
      while(alive.current&&performance.now()<saveDeadline){
        const r=await request({kind:"dashboard"});
        if(r.kind==="dashboard"&&r.dashboard.boot_id===boot&&r.dashboard.chain_node===result.selected&&!r.dashboard.operation){saved=true;break;}
        if(r.kind==="error"&&r.code!=="operation_busy")throw r.code;
        await pause(300);
      }
      if(token!==generation.current)throw "connection_cancelled";
      if(!saved)throw "operation_busy";
      if(!alive.current||current.current?.boot_id!==boot)throw "boot_changed_reconcile";
      const r=await request({kind:"recovery_action",action:"test_backup"});
      if(r.kind==="error")throw r.code;
      setNotice("正在检查备用隧道的真实流量，完成后恢复测试前的路线。");
      const deadline=performance.now()+210_000;let started=false;
      while(alive.current&&performance.now()<deadline){
        await pause(1000);if(token!==generation.current)throw "connection_cancelled";const d=current.current;
        if(!d||d.boot_id!==boot)throw "boot_changed_reconcile";
        const stage=d.recovery?.stage;
        started ||= stage==="testing_backup"||stage==="restoring_previous";
        const verified=d.backup_verified_at!=null&&d.backup_verified_at!==previous;
        if(d.status==="connected"&&!d.operation&&stage!=="testing_backup"&&stage!=="restoring_previous"&&(verified||started)){
          setNotice(verified?"备用路线实际流量已通过，已恢复日常连接。":"备用路线未通过，已恢复测试前的路线；原配置仍保留。");return;
        }
        if(started&&!d.operation&&!["testing_backup","restoring_previous"].includes(stage??"")&&d.status==="retry_wait")throw "route_trial_failed";
      }
      if(alive.current)setNotice("测试仍在后台处理，请查看上方连接与恢复进度。");
    }catch(e){if(alive.current)setNotice(errorText(typeof e==="string"?e:"clash_not_found"));}
    finally{flight.current=false;next.current=performance.now()+30*60*1000;if(alive.current)setWorking(false);}
  }
  // Independent SS-only maintenance does not open another WG identity.
  useEffect(()=>{
    if(!data||!("__TAURI_INTERNALS__" in window)||data.settings.tunnel_route==="direct"||data.physical_attachment!=="available"||data.operation||data.status!=="connected"||data.connection?.chained||flight.current||performance.now()<next.current)return;
    next.current=performance.now()+5*60*1000;void maintain();
  },[data?.sequence]);
  return {working,notice,choices,selected,setSelected,loadChoices,maintain,test,cancel:()=>{generation.current+=1;}};
}
export type ChainBackup=ReturnType<typeof useChainBackup>;
export function ChainRoute({data,disabled,onSettings,backup}:{data:Dashboard;disabled:boolean;onSettings:(settings:Settings)=>Promise<void>;backup:ChainBackup}) {
  return <section className="panel backup-route">
    <div className="panel-heading"><div><p className="eyebrow">LAST RESORT</p><h2>链式备用</h2></div><span className="pill">{data.connection?.chained&&data.status==="connected"?"正在保底":"自动维护"}</span></div>
    <div className="backup-route-summary"><div><strong>{data.chain_node??"正在从本机 Clash 准备备用"}</strong><p>优先美国，其次新加坡，再尝试英国。保底后仍会尝试回到直连。</p></div>
      <button disabled={disabled||backup.working||data.physical_attachment!=="available"||!data.identity_configured} onClick={()=>void backup.test()}>{backup.working?"正在自动检查…":"测试备用路线"}</button></div>
    <p className="backup-route-result" role="status">{backup.notice||(data.backup_verified_at?`最近一次完整连通：${timeText(data.backup_verified_at)}`:data.chain_node?"备用已保存；原入口、备用入口和同城节点均失败后才使用。":"不需要逐个选、逐个测试；后台会从实际配置中筛选可承载隧道的节点。")}</p>
    <details className="clash-advanced" onToggle={e=>{if(e.currentTarget.open&&!backup.choices.length)void backup.loadChoices();}}><summary>备用节点与连接策略</summary>
      <div className="settings-grid"><label>备用节点<select aria-label="链式备用节点" value={backup.selected} disabled={disabled||backup.working} onChange={e=>{backup.setSelected(e.target.value);void onSettings({...data.settings,chain_selection:e.target.value||null});}}><option value="">自动选择（推荐）</option>{backup.choices.map(c=><option key={c.fingerprint} value={c.name}>{c.name}</option>)}</select></label>
      <label>连接策略<select aria-label="隧道连接策略" value={data.settings.tunnel_route??"auto"} disabled={disabled||backup.working} onChange={e=>void onSettings({...data.settings,tunnel_route:e.target.value as Settings["tunnel_route"]})}><option value="auto">直连恢复后，最后链式保底</option><option value="direct">仅直连</option><option value="chain" disabled={!data.chain_node}>固定链式</option></select></label></div>
      <div className="panel-actions"><button disabled={disabled||backup.working} onClick={()=>void backup.maintain(!!backup.selected)}>应用并自动检查</button><button disabled={backup.working} onClick={()=>void backup.loadChoices()}>刷新本机节点</button></div>
      <p className="hint">读取本机实际 Clash 配置与订阅缓存，当前可导入无插件的标准 SS UDP 节点。列表包含所有兼容节点；名称用于优先顺序，真实收发决定是否采用。密码只在本机后台读取与加密保存。</p>
    </details>
  </section>;
}
