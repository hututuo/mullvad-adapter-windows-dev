import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { type Dashboard } from "./app-api";

type Client = { installed:boolean; protocol_registered:boolean; configuration_count:number };
type Profile = { registered:boolean; selected:boolean };
type Destination = "account" | "cities" | "clash" | "diagnostics";
const call = <T,>(kind:string) => invoke<T>("clash_request", {input:{kind}});

export function SetupPage({data, navigate}:{data:Dashboard|null; navigate:(page:Destination)=>void}) {
  const [client,setClient]=useState<Client|null>(null),[profile,setProfile]=useState<Profile|null>(null);
  const [working,setWorking]=useState(false),[notice,setNotice]=useState("正在检测本机 Clash…");
  const live=useRef(true),flight=useRef(false);
  useEffect(()=>{live.current=true;void detect();return()=>{live.current=false}},[]);
  async function detect() {
    if(flight.current)return;flight.current=true;setWorking(true);
    try {
      const next=await call<Client>("setup_status");if(!live.current)return;setClient(next);setProfile(null);
      if(next.configuration_count===1) {
        try {const p=await call<Profile>("profile_preview");if(live.current)setProfile(p)} catch { if(live.current){setNotice("已找到 Clash，但配置内容或导入状态尚未核实。请到 Clash 接入页查看具体错误并重试。");return} }
      }
      if(live.current)setNotice(next.configuration_count>1?"找到多份 Clash 配置。请在 Clash 接入页明确选择使用哪份。":next.configuration_count===1?"已找到本机 Clash 配置。下面按真实状态显示剩余步骤。":next.installed?"已找到 Clash。请先打开它一次完成初始化，再重新检测。":"尚未确认支持的 Clash 安装。可打开官方安装页面；便携版也可在 Clash 接入页指定配置目录。");
    } catch {if(live.current){setClient(null);setNotice("本机 Clash 检测未完成，请重新检测。此时不能判断为未安装。")}}
    finally{flight.current=false;if(live.current)setWorking(false)}
  }
  async function download() {
    if(flight.current)return;flight.current=true;setWorking(true);
    try {await call("setup_download");if(live.current)setNotice("已打开 Clash Verge Rev 官方安装页面。选择 Windows 安装包完成安装，打开一次后回到这里重新检测。现有 Clash 无需重装。")}
    catch {if(live.current)setNotice("无法打开系统浏览器。请访问 github.com/clash-verge-rev/clash-verge-rev/releases/latest 下载官方安装包。")}
    finally{flight.current=false;if(live.current)setWorking(false)}
  }
  const full=!!data?.account.authenticated&&data.account.devices.length>=5;
  const healthy=data?.status==="connected"&&data.front_ready&&data.front_selected!=="reject"&&data.readiness==="ready"&&data.connection?.dns===true&&data.connection?.https===true;
  const identity=!!data?.identity_configured;
  return <div className="setup-page">
    <section className="intro"><h2>第一次使用，按这几步完成</h2><p>不需要遍历所有节点。配置好本机身份，选定常用城市，再把系统流量接入 Clash。</p></section>
    <div className="clash-feedback" role="status" aria-live="polite"><span aria-hidden="true">{working?"◌":"●"}</span><span>{notice}</span></div>
    <ol className="setup-steps">
      <li className="panel"><div className="setup-step-number">1</div><div className="setup-step-content">
        <div className="panel-heading"><h2>准备 Clash</h2><span className="pill">{client===null?"尚未确认":client.configuration_count===1&&client.protocol_registered?"已找到配置与导入接口":client.installed?"已安装，待初始化":"待安装或指定目录"}</span></div>
        <p>支持 Clash Verge Rev 一键添加独立配置，原订阅保留。有自己的节点也可以继续选择；没有节点时 AI 和普通外网默认走 Mullvad，国内与局域网直连。</p>
        <div className="clash-actions"><button disabled={working} onClick={()=>void detect()}>重新检测</button>{(!client?.installed||!client.protocol_registered)&&<button disabled={working} onClick={()=>void download()}>打开官方安装页面</button>}</div>
      </div></li>
      <li className="panel"><div className="setup-step-number">2</div><div className="setup-step-content">
        <div className="panel-heading"><h2>登录账号，配置本机设备</h2><span className={`pill ${identity?"positive":""}`}>{identity?"已有本机身份":data?.account.authenticated?"已登录，待配置设备":"待登录"}</span></div>
        <p>{identity?`本机正在使用 ${data?.device_name??"已配置的设备"}。账号管理登录独立于隧道，已有身份无需重新创建。`:"输入 Mullvad 账号，在官方设备列表中为这台电脑创建设备，然后点“使用这个设备”。私钥仅保存在本机安全存储。"}</p>
        {full&&<p className="clash-warning">账号已达到 5 台设备上限。若需要新设备，请先在设备列表中辨认并明确撤销一台不再使用的设备，再创建。其他设备的私钥不能从服务端取回；不会自动删除任何设备。</p>}
        {data?.device_draft&&data.device_draft.state!=="created"&&<p className="hint">已有待核实的设备创建记录。先刷新官方列表确认结果，不重复注册。</p>}
        <button onClick={()=>navigate("account")}>{identity?"查看账号与设备":"登录并管理设备"}</button>
      </div></li>
      <li className="panel"><div className="setup-step-number">3</div><div className="setup-step-content">
        <div className="panel-heading"><h2>选择城市，连接并验证隧道</h2><span className={`pill ${healthy?"positive":""}`}>{healthy?"当前隧道检查通过":data?.physical_attachment==="unavailable"?"等待本机联网":"待连接验证"}</span></div>
        <p>收藏 1–3 个城市，平时选定其中一个。后台在同城内恢复，不因本机暂时离线跨城市跳转。延迟测速只供参考，IP、DNS 和 HTTPS 结果分别显示，连接以后台完整验证为准。</p>
        <button disabled={!identity} onClick={()=>navigate("cities")}>选择常用城市并连接</button>
      </div></li>
      <li className="panel"><div className="setup-step-number">4</div><div className="setup-step-content">
        <div className="panel-heading"><h2>一键写入分流配置</h2><span className="pill">{profile?.selected?"Clash 已选择配置":profile?.registered?"已导入，待选择":"待接入"}</span></div>
        <p>隧道连通后，在接入页点“一键写入 Clash”，再在 Clash 中选中新配置。AI 和普通外网可分别选 Mullvad 或自己的节点。导入不会开启系统代理或 TUN；请在 Clash 中选择需要的接管方式。</p>
        <button className="primary" onClick={()=>navigate("clash")}>前往一键接入</button>
        <p className="hint">“已导入”只证明配置已保存，“已选择”只证明客户端选择了它；不代表所有应用的实际出口已经验证。</p>
      </div></li>
    </ol>
    <section className="panel"><h2>连接不顺畅时，从这里开始</h2><p>先看本机是否联网，再看当前隧道的 IP / DNS / HTTPS 结果。保留当前城市，由后台恢复；需要协助时生成诊断报告并复制路径，便于本地 Agent 检查前后日志。</p><button onClick={()=>navigate("diagnostics")}>查看诊断与日志</button></section>
  </div>;
}
