import { useState } from "react";
import { timeText, type CatalogueFieldChange, type CatalogueRelayChange, type Dashboard } from "./app-api";
import { catalogueSummary, catalogueRelayState } from "./catalogue-change";

function Fields({ values }: { values: CatalogueFieldChange[] }) {
  return <div className="catalogue-fields">{values.map(field=><div className="catalogue-field" key={field.key}>
    <strong>{field.label}</strong>
    {field.added_count!==undefined ? <>
      <span>新增 {field.added_count} · 移除 {field.removed_count??0}</span>
      {!!field.added?.length && <code>新增：{field.added.join("、")}</code>}
      {!!field.removed?.length && <code>移除：{field.removed.join("、")}</code>}
      {(field.added_count>(field.added?.length??0) || (field.removed_count??0)>(field.removed?.length??0)) && <small>明细各最多显示 6 项。</small>}
    </> : <><code>之前：{field.before}</code><code>现在：{field.after}</code></>}
  </div>)}</div>;
}
function RelayRow({ relay }: { relay:CatalogueRelayChange }) {
  const [expanded,setExpanded]=useState(false);
  return <div className="catalogue-relay">
    <button className="catalogue-relay-toggle" aria-expanded={expanded} onClick={()=>setExpanded(!expanded)}>
      <span aria-hidden="true">{expanded?"⌄":"›"}</span><code>{relay.relay}</code><span>{catalogueRelayState(relay.state)}</span>
    </button>
    {expanded && (relay.fields.length ? <Fields values={relay.fields}/> : <p>{catalogueRelayState(relay.state)}</p>)}
  </div>;
}
export function CatalogueDetails({data,onClose}:{data:Dashboard|null;onClose:()=>void}) {
  const report=data?.metadata_changes,focus=report?.current_relay;
  return <section className="catalogue-details">
    <div className="panel-heading"><h2 id="catalogue-title">官方目录更新内容</h2><button className="quiet" onClick={onClose}>完成</button></div>
    <p className="muted">对照上一次有效目录；更新不会主动重建当前连接。</p>
    <div className="catalogue-details-scroll">
      {data?.metadata_error && <div className="catalogue-warning">本次获取失败，继续使用上次有效目录。下面如有对比，属于最近一次成功检查。</div>}
      {!report ? <p>暂无目录对比。请点击“更新官方目录”；旧版后台也可能尚未提供此功能。</p> : <>
        <section><h3>{catalogueSummary(report)}</h3><small>检查时间：{timeText(report.checked_at)}</small></section>
        {report.catalogue_changed && report.added_count+report.removed_count+report.changed_count===0 && <p>节点本身没有增减或修改；变化来自共享端口或其他目录参数。</p>}
        {focus && <section className="catalogue-current"><h3>检查时使用的节点</h3><code>{focus.relay??"未选定"}</code><p>{catalogueRelayState(focus.state)}</p>
          {data?.active_relay && focus.relay && data.active_relay!==focus.relay && <p className="muted">当前已切换到 {data.active_relay}；以下对比针对检查时的 {focus.relay}。</p>}
          {focus.ss_after_count!==null && <p>SS 地址／端口组合：{focus.ss_before_count??"无旧记录"} → {focus.ss_after_count}</p>}
          {focus.state==="unchanged" && <p className="muted">专用 SS 地址、主地址 SS 端口、IPv4／IPv6、公钥和官方可用状态均未变化。</p>}
          <Fields values={focus.fields}/>
        </section>}
        {!!report.shared_changes.length && <section><h3>共享目录参数</h3><Fields values={report.shared_changes}/></section>}
        {!!report.changed_relays.length && <section><h3>变化的节点</h3>{report.changed_relays.map(row=><RelayRow key={`${row.relay}:${report.checked_at}`} relay={row}/>)}
          {report.truncated_count>0 && <small>另有 {report.truncated_count} 个节点变化；此处优先保留检查时使用的节点。</small>}
        </section>}
        <p className="catalogue-explanation">目录没变，只能排除“官方公布的这些参数发生变化”，不能排除远端服务或网络路径波动。SS 数量是候选地址与端口的组合数，不代表都可用，也不会因此进行全量测试。</p>
      </>}
      {data?.metadata_cache_error && <div className="catalogue-warning">新目录已在内存生效，但本地缓存保存失败。重启后可能仍读取旧缓存。</div>}
    </div>
  </section>;
}
