import React, {useCallback,useEffect,useRef,useState} from "react";
import {readEvents,desktopError,type EventPage} from "./desktop-api";
import {eventView,eventTimestamp} from "./event-text";
import {recoveryView} from "./recovery-view";
import {statusText,type Dashboard} from "./app-api";
export function ActivityPanel({current,stale,onClose,onExport}:{current:Dashboard|null;stale:boolean;onClose:()=>void;onExport:()=>void}) {
  const [page,setPage]=useState<EventPage|null>(null),[error,setError]=useState<string|null>(null),[search,setSearch]=useState(""),[follow,setFollow]=useState(true),[loading,setLoading]=useState(false);
  const busy=useRef(false),alive=useRef(true),list=useRef<HTMLDivElement>(null);
  const refresh=useCallback(async()=>{
    if(busy.current)return;busy.current=true;setLoading(true);
    try{const result=await readEvents();if(alive.current){setPage(result);setError(null)}}
    catch(e){if(alive.current)setError(desktopError(e))}
    finally{busy.current=false;if(alive.current)setLoading(false)}
  },[]);
  useEffect(()=>{alive.current=true;void refresh();const timer=setInterval(()=>void refresh(),5000);return()=>{alive.current=false;clearInterval(timer)}},[refresh]);
  useEffect(()=>{if(follow&&list.current)list.current.scrollTop=list.current.scrollHeight},[page,follow]);
  const items=(page?.events??[]).map((item,index)=>({item,index,view:eventView(item)})).filter(({item,view})=>`${view.title} ${view.probes} ${item.code}`.toLowerCase().includes(search.toLowerCase()));
  return <section className="activity-panel" aria-label="操作详情与事件日志">
    <div className="panel-heading"><div><p className="eyebrow">ACTIVITY</p><h2 id="event-log-title">操作详情与事件日志</h2><p>按时间记录发生了什么；检查取消或测量过期，不等于节点失效。</p></div><button className="quiet" onClick={onClose} aria-label="关闭事件详情">关闭</button></div>
    <div className="activity-current"><strong>{stale?"界面状态尚未更新，以下保留上次资料":current?current.recovery?recoveryView(current,false).title:statusText[current.status]??"正在核对连接":"尚未取得当前状态"}</strong><span>{current?.recovery?.relay??current?.active_relay??"暂无当前节点"}{current?.recovery?` · 下一步：${recoveryView(current,false).next}`:""}</span></div>
    <div className="activity-tools"><label className="activity-search">搜索节点或事件<input value={search} onChange={e=>setSearch(e.target.value)} placeholder="例如 508、重试、连接成功"/></label><label className="activity-follow"><input type="checkbox" checked={follow} onChange={e=>setFollow(e.target.checked)}/>跟随最新</label><button disabled={loading} onClick={()=>void refresh()}>{loading?"读取中…":"刷新"}</button><button onClick={onExport}>生成排查资料</button></div>
    <div className="activity-notice" role="status">{error ?? (page ? `显示最近 ${page.events.length} 条记录${page.truncated?"；更早记录仍保存在本机轮转日志中":""}${page.skipped?`；跳过 ${page.skipped} 条不完整或无法验证的记录`:""}。仅查看，不会重连或换节点。` : "正在读取本机日志…")}</div>
    <div className="activity-list" ref={list} tabIndex={0} aria-label="按时间排列的事件">
      {items.map(({item,index,view})=><article key={`${item.time}-${item.code}-${index}`} className={`activity-event ${view.tone}`}><time dateTime={eventTimestamp(item.time).iso}>{eventTimestamp(item.time).label}</time><div><strong>{view.title}</strong>{view.probes&&<p>{view.probes}</p>}<details><summary>技术字段</summary><code>{item.stage} / {item.code}{item.phase?` / ${item.phase}`:""}</code></details></div></article>)}
      {page&&!items.length&&<div className="activity-empty">{search?"没有匹配的记录。":"还没有事件记录；后台运行后会自动记录。"}</div>}
    </div>
  </section>;
}
