import React,{useEffect,useState} from "react";
import {getDesktopPreferences,setAutostart,setWidget,desktopError,type DesktopPreferences} from "./desktop-api";
export function DesktopSettings(){
  const [prefs,setPrefs]=useState<DesktopPreferences|null>(null),[notice,setNotice]=useState<string|null>(null),[busy,setBusy]=useState(false);
  useEffect(()=>{let alive=true;getDesktopPreferences().then(p=>{if(alive){setPrefs(p);setNotice(p.startup_error?desktopError(p.startup_error):null)}}).catch(e=>{if(alive)setNotice(desktopError(e))});return()=>{alive=false}},[]);
  async function change(kind:"autostart"|"widget",enabled:boolean){
    if(busy||!prefs)return;setBusy(true);setNotice(null);
    try{const actual=await(kind==="autostart"?setAutostart(enabled):setWidget(enabled));setPrefs({...prefs,[kind]:actual});setNotice(kind==="autostart" ? actual?"已开启：登录 Windows 时在托盘启动，不弹出主窗口。":"已关闭开机自启。" : actual?"已显示小状态窗，可拖动位置。":"已关闭小状态窗。")}
    catch(e){setNotice(desktopError(e))}finally{setBusy(false)}
  }
  return <section className="panel desktop-settings"><h2>开机与状态显示</h2><label className="desktop-toggle"><span><strong>开机自启</strong><small>默认关闭。开启后，登录 Windows 时在托盘启动；连接仍遵循现有连接设置。</small></span><input type="checkbox" role="switch" checked={prefs?.autostart??false} disabled={!prefs||busy} onChange={e=>void change("autostart",e.target.checked)}/></label><label className="desktop-toggle"><span><strong>小悬浮状态窗</strong><small>默认关闭。一直显示当前节点、连接状态和近期 ICMP 延迟；不额外建立隧道。</small></span><input type="checkbox" role="switch" checked={prefs?.widget??false} disabled={!prefs||busy} onChange={e=>void change("widget",e.target.checked)}/></label><p className="hint">托盘地球图标会随状态变色；悬停可查看节点和延迟，单击打开主窗口。</p>{notice&&<p className="desktop-settings-notice" role="status">{notice}</p>}</section>
}
