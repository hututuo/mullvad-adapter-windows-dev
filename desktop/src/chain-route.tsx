import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { errorText, type Dashboard, type Settings } from "./app-api";
type Choice = { name: string; fingerprint: string };
export function ChainRoute({ data, disabled, onSettings }: {
  data: Dashboard; disabled: boolean; onSettings: (settings: Settings) => Promise<void>;
}) {
  const [choices, setChoices] = useState<Choice[]>([]), [selected, setSelected] = useState("");
  const [working, setWorking] = useState(false), [notice, setNotice] = useState("");
  const alive = useRef(true), flight = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function run(configure: boolean) {
    if (flight.current) return;
    flight.current = true; setWorking(true); setNotice("");
    try {
      const choice = choices.find(c => c.name === selected);
      if (configure && !choice) return;
      const result = await invoke<{choices?: Choice[]; accepted?: boolean}>("clash_request", {
        input: { kind: configure ? "chain_configure" : "chain_list", directory: null,
          ...(configure ? {chain_name: choice!.name, chain_fingerprint: choice!.fingerprint} : {}) },
      });
      if (!alive.current) return;
      if (result.choices) {
        setChoices(result.choices); setSelected(result.choices.some(c => c.name === selected) ? selected : result.choices[0]?.name ?? "");
        setNotice(result.choices.length ? "请选择一个独立节点。密码只在本机后台读取并加密保存。" : "没有找到兼容的独立 SS 节点，当前路线保持不变。");
      } else { setNotice("保存请求已受理，后台确认后会显示节点名称；现有连接保持运行。"); }
    } catch (e) {
      if (alive.current) setNotice(typeof e === "string" && e.startsWith("clash_chain_")
        ? "此 Clash 节点或订阅缓存不支持安全导入。可使用无插件、支持 UDP 的独立 SS 节点；当前路线保持不变。"
        : errorText(typeof e === "string" ? e : "clash_not_found"));
    } finally { flight.current = false; if (alive.current) setWorking(false); }
  }
  return <section className="panel">
    <div className="panel-heading"><h2>隧道备用路线</h2><span className="pill">{data.chain_node ? "已保存独立节点" : "尚未配置"}</span></div>
    <p>优先直接连接 Mullvad；直连失败时，可通过独立节点承载隧道，最终出口仍为所选 Mullvad 城市。</p>
    <div className="settings-grid">
      <label>连接策略<select aria-label="隧道连接策略" value={data.settings.tunnel_route ?? "auto"} disabled={disabled || working}
        onChange={e => void onSettings({...data.settings, tunnel_route: e.target.value as Settings["tunnel_route"]})}>
        <option value="auto">优先直连，失败后链式备用</option><option value="direct">仅直连</option>
        <option value="chain" disabled={!data.chain_node}>固定链式</option>
      </select></label>
      <label>从 Clash 选择独立节点<select aria-label="独立链式节点" value={selected} disabled={disabled || working || !choices.length} onChange={e => setSelected(e.target.value)}>
        {!choices.length && <option value="">先读取本机节点</option>}{choices.map(c => <option key={c.fingerprint} value={c.name}>{c.name}</option>)}
      </select></label>
    </div>
    <div className="panel-actions"><button disabled={disabled || working} onClick={() => void run(false)}>{working ? "正在处理…" : "读取 Clash 节点"}</button>
      <button disabled={disabled || working || !selected} onClick={() => void run(true)}>保存为链式备用</button></div>
    <p className="hint">已保存：{data.chain_node ?? "无"}。策略用于新连接；自动恢复先重试当前路线，失败后按策略选备用。健康隧道保持运行，更换正在使用的链式节点需先断开。当前支持无插件的标准 SS UDP 节点。</p>
    <p className="hint" role="status" style={{minHeight:"2.8em"}}>{notice || "独立节点只承载加密隧道，不会被选为业务最终出口。"}</p>
  </section>;
}
