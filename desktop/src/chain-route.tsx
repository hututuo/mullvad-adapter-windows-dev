import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { errorText, request, timeText, type Dashboard, type Settings } from "./app-api";
import {backupResult,canContinueBackup} from "./backup-result";
type Choice={name:string;fingerprint:string};
type AutoResult={selected?:string;accepted?:boolean;kept?:boolean;fingerprint?:string;source_fingerprint?:string;revision?:number};
const pause=(ms:number)=>new Promise<void>(resolve=>window.setTimeout(resolve,ms));
export function useChainBackup(data:Dashboard|null,observationCurrent=true) {
  const [working,setWorking]=useState(false),[notice,setNotice]=useState(""),[choices,setChoices]=useState<Choice[]>([]),[selected,setSelected]=useState("");
  const current=useRef(data),alive=useRef(true),flight=useRef(false),next=useRef(0);
  const generation=useRef(0);
  current.current=data;
  const observation=useRef(observationCurrent);observation.current=observationCurrent;
  useEffect(()=>{setSelected(data?.settings.chain_selection??"");},[data?.settings.chain_selection]);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  async function prepare(manual:boolean,excluded:string[]=[]) {
    const choice=manual?choices.find(c=>c.name===selected):undefined;
    return invoke<AutoResult>("clash_request",{input:{kind:"chain_auto",directory:null,exclude_fingerprints:excluded,...(choice?{chain_name:choice.name,chain_fingerprint:choice.fingerprint}:{})}});
  }
  async function maintain(manual=false) {
    if(!observation.current){setNotice(errorText("status_snapshot_stale"));return;}
    if(flight.current||!current.current)return;
    flight.current=true;setWorking(true);
    try {
      const result=await prepare(manual);
      if(alive.current)setNotice(result.kept?"保留已验证的备用路线，直连恢复全部失败后才启用。":`已自动准备备用：${result.selected??"本机节点"}。直连恢复全部失败后才启用。`);
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
    if(!observation.current){setNotice(errorText("status_snapshot_stale"));return;}
    if(flight.current||!current.current)return;
    flight.current=true;setWorking(true);setNotice("正在自动选择备用并验证实际流量…");
    const token=generation.current,initial=current.current,boot=initial.boot_id;
    const pinned=!!(selected||initial.settings.chain_selection),excluded:string[]=[],roundDeadline=performance.now()+420_000;
    let failedSafely=false,passed=false,finalText="没有找到可用的备用路线，当前连接保持原路径。";
    function checkIntent() {
      if(!observation.current)throw "status_snapshot_stale";
      if(token!==generation.current||!alive.current)throw "connection_cancelled";
      if(current.current?.boot_id!==boot||current.current?.source_sha!==initial.source_sha)throw "boot_changed_reconcile";
      if((current.current.settings.chain_selection??null)!==(initial.settings.chain_selection??null))throw "clash_config_changed";
      if(current.current.physical_attachment!=="available")throw "waiting_network";
    }
    try {
      for(let attempt=0;attempt<6&&performance.now()<roundDeadline;attempt++) {
        checkIntent();
        setNotice(attempt?"上一条未通过，原连接已恢复；正在自动检查下一条备用…":"正在自动选择备用并验证实际流量…");
        const result=await prepare(pinned,excluded),saveDeadline=performance.now()+12_000;
        let saved:Dashboard|null=null;
        while(alive.current&&performance.now()<saveDeadline){
          checkIntent();const r=await request({kind:"dashboard"});
          if(r.kind==="dashboard"&&r.dashboard.boot_id===boot&&r.dashboard.chain_node===result.selected&&r.dashboard.chain_fingerprint===result.fingerprint&&(r.dashboard.chain_revision??0)===(result.revision??0)&&!r.dashboard.operation){saved=r.dashboard;break;}
          if(r.kind==="error"&&r.code!=="operation_busy")throw r.code;
          await pause(300);
        }
        checkIntent();
        if(!saved||!result.fingerprint)throw "operation_busy";
        if(performance.now()>=roundDeadline)break;
        const baseline=saved.backup_test_id??0;
        const r=await request({kind:"recovery_action",action:"test_backup"});
        if(r.kind==="error")throw r.code;
        failedSafely=false;
        setNotice(`正在验证备用 ${result.selected??"本机节点"} 的实际流量，完成后恢复原路径。`);
        const deadline=performance.now()+210_000;let done:Dashboard|null=null;
        while(alive.current&&performance.now()<deadline){
          await pause(1000);checkIntent();const d=current.current;
          if(d&&backupResult(d,baseline+1)){done=d;break;}
        }
        if(!done){finalText="测试仍在后台处理，请查看上方连接与恢复进度。";break;}
        finalText=backupResult(done,baseline+1)!;
        passed=done.backup_test_status==="passed";
        failedSafely=done.backup_test_status==="failed"&&done.backup_test_restored===true;
        if(pinned||passed||!canContinueBackup(done,{
          boot,source:initial.source_sha,id:baseline+1,fingerprint:result.fingerprint,revision:result.revision??0,
          relay:saved.connection?.relay??null,inlet:saved.connection?.inlet??null,
        }))break;
        excluded.push(result.source_fingerprint??result.fingerprint);
      }
    }catch(e){finalText=errorText(typeof e==="string"?e:"clash_not_found");}
    finally {
      // Testing candidates must not erase a previously verified standby. Never
      // alter configuration during an in-flight trial, cancellation or live chain.
      const d=current.current;
      if(observation.current&&!passed&&!pinned&&failedSafely&&alive.current&&token===generation.current&&d?.boot_id===boot&&d.source_sha===initial.source_sha&&!d.settings.chain_selection&&d.physical_attachment==="available"&&d.backup_test_status==="failed"&&d.backup_test_restored===true&&d.status==="connected"&&!d.operation&&!d.connection?.chained) {
        try {
          const revision=d.chain_revision??0,r=await request({kind:"restore_verified_chain",expected_revision:revision});
          if(r.kind==="accepted") {
            const until=performance.now()+12_000;let restored=false;
            while(alive.current&&token===generation.current&&performance.now()<until){
              await pause(300);const state=await request({kind:"dashboard"});
              if(state.kind==="dashboard"&&state.dashboard.boot_id===boot&&!state.dashboard.operation&&(state.dashboard.chain_revision??0)>revision&&state.dashboard.backup_verified_at){restored=true;break;}
            }
            finalText=restored?"本轮未找到更好的备用；已保留上次完整通过的路线，当前直连正常。":"原路径已恢复；上次备用配置的恢复尚未确认，请查看当前状态。";
          }
        }catch{/* The separate encrypted snapshot remains available after restart. */}
      }
      flight.current=false;next.current=performance.now()+(passed?30:5)*60*1000;
      if(alive.current){setNotice(finalText);setWorking(false);}
    }
  }
  // Independent SS-only maintenance does not open another WG identity.
  useEffect(()=>{
    if(!observationCurrent||!data||!("__TAURI_INTERNALS__" in window)||data.settings.tunnel_route==="direct"||data.physical_attachment!=="available"||data.operation||!["connected","disconnected","retry_wait"].includes(data.status)||data.connection?.chained||flight.current||performance.now()<next.current)return;
    next.current=performance.now()+5*60*1000;void maintain();
  },[data?.sequence,observationCurrent]);
  return {working,notice,choices,selected,setSelected,loadChoices,maintain,test,cancel:()=>{generation.current+=1;}};
}
export type ChainBackup=ReturnType<typeof useChainBackup>;
export function ChainRoute({data,disabled,onSettings,backup,observationCurrent=true}:{data:Dashboard;observationCurrent?:boolean;disabled:boolean;onSettings:(settings:Settings)=>Promise<void>;backup:ChainBackup}) {
  return <section className="panel backup-route">
    <div className="panel-heading"><div><p className="eyebrow">LAST RESORT</p><h2>链式备用</h2></div><span className="pill">{!observationCurrent?"状态待更新":data.connection?.chained&&data.status==="connected"?"正在保底":"自动维护"}</span></div>
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
