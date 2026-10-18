import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type View = {
  directory: string; profile: string; script: string; proxy_port: number | null;
  tun_enabled: boolean; groups: string[]; ordinary_proxies: string[];
  managed: boolean; saved: boolean; conflict: boolean; active: boolean;
  target_group: string | null; ordinary_proxy: string | null; backup_path: string | null;
  other_profiles: string[];
};
type Choice = { target_group: string; ordinary_proxy: string; front_port: number };
type Preview = { id: string; config: string; summary: View };
type Outcome = { saved: boolean; active: boolean; code: string; backup_path: string };
const explanations: Record<string,string> = {
  clash_not_found: "没有找到 Clash Verge Rev。请先安装并打开它，或在下方指定配置目录。",
  clash_multiple_clients: "发现多份 Clash 配置，请指定要接入的那一份目录。",
  clash_controller_missing: "没有找到 Clash 已启用的本机控制通道。请确认 Clash 正在运行，并已提供本机管道或本机控制接口。",
  clash_controller_nonlocal: "Clash 控制地址不是受支持的本机管道或本机地址，未连接该地址。",
  clash_controller_pipe_unsupported: "当前系统不支持此 Windows 本机管道，请使用对应系统的 Clash 接入方式。",
  clash_controller_auth: "无法通过 Clash 控制接口认证。请重新应用当前订阅后检测。",
  clash_controller_unavailable: "暂时无法连接 Clash 控制接口。请确认 Clash 正在运行。",
  clash_controller_response: "Clash 控制接口响应不兼容，配置未被覆盖。",
  clash_tunnel_required: "请先在常用城市连接 Mullvad，再启用 Clash 接入，避免把当前流量交给尚未连接的入口。",
  clash_rule_mode_required: "请先在 Clash 中切换到规则模式。接入不会替你改变运行模式。",
  clash_script_missing: "当前订阅没有可识别的扩展脚本。可先在 Clash 中创建订阅扩展脚本，或复制下方配置手动接入。",
  clash_script_shared: "此扩展脚本由多个订阅共用，未修改。请先为当前订阅创建独立扩展脚本，或使用手动接入。",
  clash_profile_missing: "Clash 尚未选择订阅，请先在 Clash 中启用一个订阅。",
  clash_invalid_choice: "请选择现有的手动策略组，以及独立的普通外网节点。",
  clash_selection_unavailable: "无法读取策略组当前选择，未执行接入。",
  clash_config_changed: "检测后配置发生了变化。已保留现场，请重新检测；撤销时不会覆盖这些修改。",
  clash_name_conflict: "Clash 已有同名但内容不同的节点，请先处理名称冲突。",
  clash_rule_conflict: "订阅已经有相同的账号出口规则。为防撤销时误删现有规则，未自动接入；可使用手动配置。",
  clash_runtime_diverged: "Clash 当前运行的路由与订阅文件不一致。请先在 Clash 重新应用当前订阅再检测；未覆盖这些改动。",
  clash_already_managed: "当前订阅已有接入记录。可检查生效情况，或先撤销后重新配置。",
  clash_backup_exists: "发现未完成的接入记录，请先检查并撤销，原文件备份已保留。",
  clash_backup_missing: "脚本里有接入标记，但本机缺少对应备份。请勿覆盖，先从原设备恢复接手资料。",
  clash_backup_invalid: "接入备份无法核验。已停止操作并保留原文件。",
  clash_write_failed: "无法安全写入配置。请检查文件权限或是否被占用，备份会保留。",
  clash_write_unconfirmed: "配置写入结果未确认，请重新检测。不要删除备份。",
  clash_validation_failed: "Mihomo 配置自检未通过，未覆盖原扩展脚本。备份与待检配置已保留。",
  clash_activation_unconfirmed: "配置已保存，但没有确认 Clash 已生效。可重新检测，或撤销本次接入。",
  clash_unsafe_path: "此目录含链接、跳转或不安全的文件路径，未执行写入。",
  clash_file_access: "无法读取 Clash 配置。请确认目录正确且当前用户有权限。",
  clash_invalid_yaml: "当前 Clash 配置无法解析，未覆盖原文件。",
  clash_rules_missing: "当前订阅没有可识别的规则列表，请使用规则订阅或手动接入。",
  clash_file_too_large: "配置超过安全读取上限，请使用较小的配置或手动接入。",
  clash_script_encoding: "扩展脚本不是 UTF-8 编码，未修改原文件。",
  clash_busy: "另一项接入操作正在进行，请稍后再试。",
  clash_not_managed: "当前订阅没有本软件的接入记录。",
  clash_windows_required: "自动接入目前用于 Windows 的 Clash Verge Rev。",
  operation_busy: "本机后台正在处理其他请求，请稍后重新检测。",
  clash_connected: "Clash 已接入。指定策略组已选择本机入口。",
  clash_removed: "已撤销本次接入，原扩展脚本已恢复；备份继续保留。",
};
function explain(value: unknown): string {
  const code = typeof value === "string" ? value : "";
  return explanations[code] ?? "操作未完成，请重新检测。原配置和备份会保留。";
}
function call<T>(kind:string, directory:string, extra:object = {}):Promise<T> {
  return invoke("clash_request", {input:{kind,directory:directory.trim()||null,...extra}});
}

function LegacyClashPage({frontPort, connected, disabled, bootstrapPort, onUseProxy}: {
  frontPort:number; connected:boolean; disabled:boolean; bootstrapPort:number|null;
  onUseProxy:(port:number)=>Promise<void>;
}) {
  const [directory,setDirectory]=useState("");
  const [view,setView]=useState<View|null>(null);
  const [group,setGroup]=useState("");
  const [ordinary,setOrdinary]=useState("");
  const [preview,setPreview]=useState<Preview|null>(null);
  const [working,setWorking]=useState(false);
  const [notice,setNotice]=useState("正在检测本机 Clash…");
  const [failed,setFailed]=useState(false);
  const [useProxy,setUseProxy]=useState(true);
  // Public display data needs no native transaction. Running an export request
  // beside detection would contend for the native integration gate on mount.
  // Clipboard still obtains the authoritative front from the verified backend.
  const exported=`proxies:\n  - name: "Mullvad Adapter Local [managed]"\n    type: socks5\n    server: 127.0.0.1\n    port: ${frontPort}\n    udp: true\n`;
  const [showPreview,setShowPreview]=useState(false);
  const [undoConfirm,setUndoConfirm]=useState(false);
  const generation=useRef(0), alive=useRef(true), running=useRef(false);
  // StrictMode can replay mount effects while a native detection is pending.
  // Share that read instead of launching another command against its held gate.
  const detectionRequest=useRef<Promise<View>|null>(null);
  const mounted=useRef(false);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;generation.current++;mounted.current=false;running.current=false}},[]);
  const isBusy=working||disabled;
  const change=()=>{generation.current++;setPreview(null);setUndoConfirm(false)};
  async function detect() {
    if(running.current)return;
    running.current=true;setWorking(true);setPreview(null);setFailed(false);
    const token=++generation.current;
    try {
      detectionRequest.current??=call<View>("detect",directory);
      const next=await detectionRequest.current;
      if(!alive.current||token!==generation.current)return;
      setView(next);setDirectory(next.directory);
      setGroup(next.target_group??(next.groups.includes(group)?group:""));
      setOrdinary(next.ordinary_proxy??(next.ordinary_proxies.includes(ordinary)?ordinary:""));
      setNotice(next.conflict?"发现未完成的接入或脚本改动。请保留备份，避免覆盖。":next.active?"Clash 配置已接入；下方分别显示策略与隧道状态。":"检测完成。选择要接入的策略组和普通外网节点。");
      setFailed(next.conflict);
    }catch(e){if(alive.current&&token===generation.current){setView(null);setNotice(explain(e));setFailed(true)}}
    finally{if(token===generation.current){detectionRequest.current=null;running.current=false;if(alive.current)setWorking(false)}}
  }
  useEffect(()=>{
    if(!disabled&&!mounted.current){mounted.current=true;void detect();}
  },[disabled]);
  async function connect(previewOnly=false) {
    if(running.current||!view)return;
    running.current=true;setWorking(true);setFailed(false);setNotice(previewOnly?"正在生成接入预览…":"正在备份、自检并接入 Clash…");
    const token=++generation.current;
    const choice:Choice={target_group:group,ordinary_proxy:ordinary,front_port:frontPort};
    try {
      const plan=await call<Preview>("preview",view.directory,{choice});
      if(!alive.current||token!==generation.current)return;
      setPreview(plan);setShowPreview(previewOnly);
      if(previewOnly){setNotice("预览已生成，尚未修改 Clash。点击一键接入时还会重新核对配置。");return}
      const result=await call<Outcome>("apply",view.directory,{choice,preview_id:plan.id});
      if(!alive.current)return;
      setNotice(explain(result.code));setFailed(!result.active);
      if(result.active&&useProxy&&plan.summary.proxy_port&&bootstrapPort!==plan.summary.proxy_port) {
        try{await onUseProxy(plan.summary.proxy_port)}catch{if(alive.current){setNotice("Clash 已接入；账号代理设置未保存，请到诊断与设置核对端口。");setFailed(true)}}
      }
      const next=await call<View>("detect",view.directory);if(alive.current){setView(next);setPreview(null)}
    }catch(e){if(alive.current){setNotice(explain(e));setFailed(true);try{setView(await call<View>("detect",view.directory))}catch{/* Keep last successful snapshot; never invent success. */}}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  async function undo() {
    if(running.current||!view)return;
    running.current=true;setWorking(true);setFailed(false);setUndoConfirm(false);setNotice("正在核对备份并撤销接入…");
    try{
      const result=await call<Outcome>("undo",view.directory);
      if(!alive.current)return;
      setNotice(explain(result.code));setFailed(result.code!=="clash_removed");
      const next=await call<View>("detect",view.directory);if(alive.current)setView(next);
    }catch(e){if(alive.current){setNotice(explain(e));setFailed(true)}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  async function enable() {
    if(running.current||!view)return;
    running.current=true;setWorking(true);setNotice("正在恢复策略组选择并读取结果…");setFailed(false);
    try{const result=await call<Outcome>("enable",view.directory);if(!alive.current)return;setNotice(explain(result.code));setFailed(!result.active);const next=await call<View>("detect",view.directory);if(alive.current)setView(next)}
    catch(e){if(alive.current){setNotice(explain(e));setFailed(true)}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  async function useForBootstrap() {
    if(running.current||!view?.proxy_port)return;
    running.current=true;setWorking(true);setFailed(false);
    try{await onUseProxy(view.proxy_port);if(alive.current){setUseProxy(true);setNotice("账号和节点目录已使用此 Clash。接下来可登录账号、连接城市，再启用分流接入。")}}
    catch{if(alive.current){setNotice("未能保存账号外网代理，请稍后重试。");setFailed(true)}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  return <div className="clash-page">
    <section className="intro"><h2>让 Clash 把流量交给本机入口</h2><p>仅接入当前订阅和你选定的策略组。城市与节点仍在“常用城市”管理。</p></section>
    <div className={`clash-feedback ${failed?"is-error":""}`} role="status" aria-live="polite"><span aria-hidden="true">{working?"◌":"●"}</span><span>{notice}</span></div>
    <section className="panel clash-overview" aria-label="接入状态">
      <div><small>Clash 配置</small><strong>{view?(view.saved?"已保存接入":view.managed?"有待核对的备份":"检测到当前订阅"):"尚未接入"}</strong><span>{view?.profile??"自动识别 Clash Verge Rev"}</span></div>
      <div><small>策略组生效</small><strong>{view?.active?"已指向适配器":"尚未确认"}</strong><span>{view?.target_group??"选择需要接入的策略组"}</span></div>
      <div><small>Mullvad 隧道</small><strong>{connected?"已连接":"尚未连接"}</strong><span>127.0.0.1:{frontPort} · SOCKS5 / UDP</span></div>
    </section>
    <section className="panel">
      <div className="panel-heading"><div><h2>一键接入</h2><p className="hint">自动接入支持 Windows Clash Verge Rev；其他客户端可复制下方节点配置。</p></div><button disabled={isBusy} onClick={()=>void detect()}>重新检测</button></div>
      {view&&<>
        {view.other_profiles.length>0&&<p className="clash-warning">另外 {view.other_profiles.length} 个订阅有接入记录：{view.other_profiles.join("、")}。如需撤销，请先在 Clash 切回对应订阅。</p>}
        <div className="settings-grid">
          <label>哪些流量交给 Mullvad<select value={group} disabled={isBusy||view.managed} onChange={e=>{change();setGroup(e.target.value)}}><option value="">选择 Clash 的手动策略组</option>{view.groups.map(n=><option key={n} value={n}>{n}</option>)}</select></label>
          <label>账号接口使用的普通外网节点<select value={ordinary} disabled={isBusy||view.managed} onChange={e=>{change();setOrdinary(e.target.value)}}><option value="">选择独立的普通外网节点</option>{view.ordinary_proxies.map(n=><option key={n} value={n}>{n}</option>)}</select></label>
        </div>
        <p className="hint">账号接口单独走普通节点，避免从 Clash 绕回适配器。不会改变 DNS、TUN 或系统代理；当前需使用 Clash 规则模式。</p>
        <label className="check-row"><input type="checkbox" checked={useProxy} disabled={isBusy||view.managed||!view.proxy_port} onChange={e=>setUseProxy(e.target.checked)}/><span>将此 Clash 用于账号和目录访问{view.proxy_port?`（端口 ${view.proxy_port}）`:"（未检测到 mixed-port）"}</span></label>
        <div className="clash-actions"><button disabled={isBusy||!view.proxy_port||bootstrapPort===view.proxy_port} onClick={()=>void useForBootstrap()}>{view.proxy_port&&bootstrapPort===view.proxy_port?"账号与目录已使用此 Clash":"先用于账号与节点目录"}</button></div>
        <div className="clash-actions">
          <button className="primary" disabled={isBusy||!connected||!group||!ordinary||view.conflict||view.active||(view.managed&&!view.saved)} onClick={()=>void(view.managed?enable():connect())}> {working?"正在处理…":view.active?"已接入":view.managed?(view.saved?"重新启用接入":"接入未完成"):"一键接入配置"} </button>
          <button disabled={isBusy||!group||!ordinary||view.managed} onClick={()=>void connect(true)}>查看配置预览</button>
          {view.managed&&<button disabled={isBusy||view.conflict} onClick={()=>setUndoConfirm(true)}>撤销本次接入</button>}
        </div>
        {!connected&&<p className="hint">首次使用可先将此 Clash 用于账号与节点目录，再登录并连接城市，最后启用分流接入。检测和预览不会改变当前分流。</p>}
        {view.managed&&!view.active&&<p className="clash-warning">配置有接入记录，但当前策略未生效。若 Clash 恢复了旧选择，可点击“重新启用接入”；若记录未完成，请先撤销后重新接入。</p>}
        <p className="hint">接入会为所选策略组增加本机节点并选中它，现有规则和其他选项保留。订阅更新后脚本继续添加节点；Clash 自身若恢复旧选择，需重新选中。</p>
        {view.backup_path&&<p className="hint clash-path">原配置备份：{view.backup_path}</p>}
      </>}
      <details className="clash-advanced"><summary>配置目录与兼容性</summary><label>Clash 配置目录<input value={directory} disabled={isBusy} placeholder="留空自动检测；便携版可填写配置目录" onChange={e=>{change();setDirectory(e.target.value);setView(null)}}/></label><p className="hint">自动识别当前用户的 Clash Verge Rev，优先使用它现有的 Windows 本机管道，也支持本机 HTTP 控制接口，无需额外开放端口。只有 provider 的订阅及其他客户端暂不支持自动写入，可复制节点配置手动接入。</p></details>
    </section>
    {showPreview&&preview&&<section className="panel"><div className="panel-heading"><h2>本次追加的扩展脚本</h2><button onClick={()=>setShowPreview(false)}>收起预览</button></div><pre className="clash-code" tabIndex={0}>{preview.config}</pre><p className="hint">原订阅与扩展脚本会先备份；预览不含订阅密码、账号或私钥。</p></section>}
    <section className="panel"><div className="panel-heading"><h2>其他客户端 · 手动接入</h2><button disabled={isBusy||!exported} onClick={()=>void invoke("copy_clash_config").then(()=>{if(alive.current){setNotice("本机节点配置已复制，不含账号或私钥。");setFailed(false)}}).catch(()=>{if(alive.current){setNotice("暂时无法写入剪贴板，可选中下方配置按 Ctrl+C 复制。");setFailed(true)}})}>复制节点配置</button></div><p className="hint">复制下面的本机 SOCKS5 节点到客户端，再将需要的策略组指向它。这里不包含你的 Mullvad 密钥。</p><textarea className="clash-code" aria-label="可复制的本机节点配置" readOnly rows={8} value={exported} onFocus={e=>e.target.select()}/><p className="hint">也可选中后按 Ctrl+C 复制。只显示“已接入”不等于目标网站已通；还需确认隧道连接和实际应用出口。</p></section>
    {undoConfirm&&<div className="clash-undo-confirm" role="alert"><p>撤销将恢复本次接入前的扩展脚本，并恢复所选策略组原选择。Mullvad 隧道保持运行；已发生的外部修改会阻止撤销。</p><div className="clash-actions"><button disabled={isBusy} onClick={()=>setUndoConfirm(false)}>保留接入</button><button disabled={isBusy} onClick={()=>void undo()}>确认撤销接入</button></div></div>}
  </div>;
}

type PageProps = {frontPort:number; connected:boolean; disabled:boolean; bootstrapPort:number|null; onUseProxy:(port:number)=>Promise<void>};
type ProfileSelection = {ai:string|null; ordinary:string|null; api:string|null};
type ProfileSummary = {name:string; policy_sha256:string; rule_count:number; choices:string[]; api_choices:string[]; provider_count:number; skipped_nodes:number; skipped_providers:number; selection:ProfileSelection; requires_geodata:boolean};
type ProfilePlan = {id:string; directory:string; summary:ProfileSummary; proxy_port:number|null; registered:boolean; selected:boolean};
type ProfileResult = {id:string; path?:string; registered:boolean; selected:boolean; import_requested?:boolean; runtime_verified:boolean};

export function ClashPage(props:PageProps) {
  const [directory,setDirectory]=useState("");
  const [plan,setPlan]=useState<ProfilePlan|null>(null);
  const [selection,setSelection]=useState<ProfileSelection>({ai:null,ordinary:null,api:null});
  const [result,setResult]=useState<ProfileResult|null>(null);
  const [notice,setNotice]=useState("正在读取本机 Clash 节点…");
  const [error,setError]=useState(false),[working,setWorking]=useState(false),[legacy,setLegacy]=useState(false);
  const alive=useRef(true),running=useRef(false),initial=useRef<Promise<ProfilePlan>|null>(null),started=useRef(false);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false}},[]);
  const busy=props.disabled||working;
  function failure(e:unknown) {
    const messages:Record<string,string>={
      clash_profile_service_port_busy:"本机订阅端口被其他程序占用，未改用其他地址。已有 Clash 配置仍保留，请关闭冲突程序后重试。",
      clash_profile_service_busy:"另一份适配器正在提供本机订阅，请使用正在运行的那一份。",
      clash_import_handler_missing:"没有找到 Clash 的导入协议。完整配置已保存在本机，可在 Clash 的订阅页通过文件导入。",
      clash_profile_service_record:"本机订阅记录无法核验，已停止操作。请保留现有配置与记录。",
    };
    return typeof e==="string"&&messages[e]?messages[e]:explain(e);
  }
  async function detect(first=false) {
    if(running.current)return;running.current=true;setWorking(true);setError(false);
    try {
      const promise=first?(initial.current??=call<ProfilePlan>("profile_preview",directory,{selection})):call<ProfilePlan>("profile_preview",directory,{selection});
      const next=await promise;if(!alive.current)return;
      setPlan(next);setDirectory(next.directory);setSelection(next.summary.selection);
      setResult(next.registered?{id:next.id,registered:true,selected:next.selected,runtime_verified:false}:null);
      setNotice(next.registered
        ?next.selected?"已读回适配器配置，Clash 已选择它。实际流量还需核对出口。":"已读回适配器配置；当前仍使用其他订阅，可在 Clash 中切换。"
        :`已读取 ${next.summary.choices.length-1} 个可选节点或订阅组。国内与局域网直连，AI 和普通外网默认使用 Mullvad。`);
    } catch(e){if(alive.current){setPlan(null);setNotice(failure(e));setError(true)}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  useEffect(()=>{if(!props.disabled&&!started.current){started.current=true;void detect(true)}},[props.disabled]);
  async function generate(importProfile:boolean) {
    if(running.current)return;running.current=true;setWorking(true);setError(false);setResult(null);
    setNotice(importProfile?"正在生成、自检并一键写入 Clash，等待客户端确认…":"正在检查并保存完整配置…");
    try {
      const fresh=await call<ProfilePlan>("profile_preview",directory,{selection});if(!alive.current)return;setPlan(fresh);
      const next=await call<ProfileResult>(importProfile?"profile_import":"profile_export",fresh.directory,{selection,preview_id:fresh.id});
      if(!alive.current)return;setResult(next);
      setNotice(next.registered?(next.selected?"配置已自动添加并被 Clash 选中。实际流量还需核对出口。":"配置已自动添加到 Clash，无需手动导入。在 Clash 选中新配置即可使用，原订阅仍保留。") : importProfile?"Clash 尚未确认导入。配置已保存，请确认 Clash 正在运行后点击“核对导入”；不要重复手动导入文件。":"完整配置已保存。也可点击“一键写入 Clash”自动添加，无需手动导入文件。");
    }catch(e){if(alive.current){setNotice(failure(e));setError(true)}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  async function check() {
    if(running.current||!result||!plan)return;running.current=true;setWorking(true);setError(false);
    try {const next=await call<ProfileResult>("profile_status",plan.directory,{preview_id:result.id});if(!alive.current)return;setResult({...result,...next});
      setNotice(next.registered?(next.selected?"已读回新配置，Clash 已选择它。实际流量还需通过连接与出口检查确认。":"已读回新配置，当前仍使用原订阅；在 Clash 中选中新配置即可。") : "尚未在 Clash 订阅列表找到此配置。请确认 Clash 正在运行，再点击“一键写入 Clash”重试。");
    }catch(e){if(alive.current){setNotice(failure(e));setError(true)}}
    finally{running.current=false;if(alive.current)setWorking(false)}
  }
  function change(key:keyof ProfileSelection,value:string){setSelection({...selection,[key]:value});setResult(null)}
  return <div className="clash-page">
    <section className="intro"><h2>连接你的 Clash</h2><p>添加一份独立的分流配置，在 Clash 切换过去即可使用。原订阅保留，城市与隧道由适配器维护。</p></section>
    <div className={`clash-feedback ${error?"is-error":""}`} role="status" aria-live="polite"><span aria-hidden="true">{working?"◌":"●"}</span><span>{notice}</span></div>
    <section className="panel clash-overview" aria-label="新配置状态">
      <div><small>Mullvad 隧道</small><strong>{props.connected?"已连接":"尚未连接"}</strong><span>本机入口 · {props.frontPort}</span></div>
      <div><small>独立配置</small><strong>{result?.registered?"Clash 已导入":result?.path?"已保存，待导入":"尚未生成"}</strong><span>{result?.selected?"客户端已选择，实际出口待核对":"保留原订阅"}</span></div>
      <div><small>国内与局域网</small><strong>正常直连</strong><span>AI 与普通外网分别选择出口</span></div>
    </section>
    <section className="panel">
      <div className="panel-heading"><div><h2>新建分流配置</h2><p className="hint">有无现有节点都可使用。两个出口默认 Mullvad；也可选现有节点，订阅组内的具体节点可在 Clash 选择。</p></div><button disabled={busy} onClick={()=>void detect()}>重新读取节点</button></div>
      {plan&&<>
        <div className="settings-grid">
          <label>AI 出口<select disabled={busy} value={selection.ai??"Mullvad Adapter Local [managed]"} onChange={e=>change("ai",e.target.value)}>{plan.summary.choices.map(n=><option key={n} value={n}>{n==="Mullvad Adapter Local [managed]"?"Mullvad · 当前城市":n}</option>)}</select></label>
          <label>普通外网出口<select disabled={busy} value={selection.ordinary??"Mullvad Adapter Local [managed]"} onChange={e=>change("ordinary",e.target.value)}>{plan.summary.choices.map(n=><option key={n} value={n}>{n==="Mullvad Adapter Local [managed]"?"Mullvad · 当前城市":n}</option>)}</select></label>
        </div>
        <p className="hint">Google Drive 走普通外网，ChatGPT、Claude 等走 AI 出口。国内网站和局域网保留直连。生成后仍可在 Clash 中分别改选。</p>
        {plan.summary.skipped_nodes+plan.summary.skipped_providers>0&&<p className="clash-warning">有 {plan.summary.skipped_nodes} 个节点、{plan.summary.skipped_providers} 个订阅源未复用（包括本机入口、依赖旧策略的链式节点或本地文件源）。原配置保留。</p>}
        <div className="clash-actions"><button className="primary" disabled={busy||!props.connected} onClick={()=>void generate(true)}>一键写入 Clash</button><button disabled={busy} onClick={()=>void generate(false)}>保存完整配置文件</button>{result&&<button disabled={busy} onClick={()=>void check()}>核对导入</button>}</div>
        {!props.connected&&<p className="hint">可先保存配置；连接 Mullvad 后再导入，避免首次导入被 Clash 自动选择时没有可用隧道。</p>}
        {result?.path&&<p className="hint clash-path">本机配置：{result.path}</p>}
        <details className="clash-advanced"><summary>账号接口与配置说明</summary>
          <label>账号与节点目录出口<select disabled={busy} value={selection.api??"DIRECT"} onChange={e=>change("api",e.target.value)}>{plan.summary.api_choices.map(n=><option key={n} value={n}>{n==="DIRECT"?"系统网络 · 独立直连":n}</option>)}</select></label>
          <p className="hint">此出口独立于业务隧道，防止账号接口循环。直连受限时选已有独立节点，再把诊断设置中的账号代理端口设为 Clash mixed-port。</p>
          <p className="hint">本机订阅随适配器托盘运行，关闭界面窗口不影响。退出界面进程后，Clash 继续使用已下载副本；再次打开适配器后可更新。订阅源中的节点自行更新。首次使用所需的 CN 地理规则数据由 Clash 管理。</p>
          <p className="hint">共 {plan.summary.rule_count} 条规则。Mac 策略已移除个人路径、指定网卡和个人 IP 例外；源节点密码仅在本机配置内，预览不展示。</p>
        </details>
      </>}
      <details className="clash-advanced"><summary>便携版配置目录</summary><label>Clash 配置目录<input disabled={busy} value={directory} placeholder="留空自动识别 Clash Verge Rev" onChange={e=>{setDirectory(e.target.value);setPlan(null);setResult(null)}}/></label></details>
    </section>
    <details className="panel clash-advanced" onToggle={e=>setLegacy(e.currentTarget.open)}><summary>旧版接入与撤销</summary><p className="hint">仅用于已经增量接入过的旧订阅，以及其他客户端的本机节点片段。</p>{legacy&&<LegacyClashPage {...props}/>}</details>
  </div>;
}
