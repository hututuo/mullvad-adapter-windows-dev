import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { listen } from "@tauri-apps/api/event";
import {
  request,
  statusText,
  errorText,
  bridgeError,
  copyReport,
  stopBackendAndExit,
  reportMatchesOperation,
  probeText,
  timeText,
  operationText,
  type Command,
  type Dashboard,
  type Reply,
  type Relay,
  type Settings,
} from "./app-api";
import "./style.css";
import { ClashPage } from "./clash-page";
import { SetupPage } from "./setup-page";
import { canCreateDevice } from "./device-creation";
type Page = "setup" | "cities" | "account" | "clash" | "relays" | "diagnostics";
const pages: { id: Page; name: string; mark: string }[] = [
  { id: "setup", name: "使用引导", mark: "◇" },
  { id: "cities", name: "常用城市", mark: "◉" },
  { id: "account", name: "连接与账号", mark: "⌁" },
  { id: "clash", name: "Clash 接入", mark: "⇄" },
  { id: "relays", name: "节点目录", mark: "≡" },
  { id: "diagnostics", name: "诊断与设置", mark: "⚙" },
];
function Modal({
  children,
  labelledBy,
  onClose,
  small = false,
}: {
  children: React.ReactNode;
  labelledBy: string;
  onClose: () => void;
  small?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = ref.current;
    if (element && !element.open) element.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={small ? "modal small-modal" : "modal"}
      aria-labelledby={labelledBy}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      {children}
    </dialog>
  );
}
function App() {
  const [page, setPage] = useState<Page>("cities"),
    [data, setData] = useState<Dashboard | null>(null),
    [message, setMessage] = useState("正在连接本机后台…"),
    [error, setError] = useState(false),
    [pending, setPending] = useState(false);
  const reportRequested = useRef<{ operation: string | null; boot: string } | null>(null);
  const actionRequested = useRef<{ boot: string; sequence: number } | null>(null);
  const stopping = useRef(false);
  const initialDestination = useRef(false);
  const keyGeneration = useRef(0), activePage = useRef(page);
  activePage.current = page;
  useEffect(() => {
    if (!data || initialDestination.current) return;
    initialDestination.current = true;
    if (!data.identity_configured) setPage("setup");
  }, [data]);
  useLayoutEffect(() => {
    // Each page starts at its own heading, rather than inheriting another
    // page's scroll offset and hiding its status or primary controls.
    window.scrollTo(0, 0);
  }, [page]);
  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    let closed = false;
    const registration = listen<string>("backend-stopping", ({payload}) => {
      if (closed) return;
      stopping.current = true;
      keyGeneration.current += 1;
      setPrivateKey(null);
      setPending(payload === "stopping");
      setMessage(payload === "stopping" ? "正在停止后台并确认退出…" : errorText(payload));
      setError(payload !== "stopping");
    });
    return () => { closed = true; void registration.then(unlisten => unlisten()).catch(() => {}); };
  }, []);
  const flight = useRef(false),
    refreshFailed = useRef(false),
    mounted = useRef(false),
    current = useRef<Dashboard | null>(null);
  const [chooser, setChooser] = useState(false),
    [search, setSearch] = useState(""),
    [rows, setRows] = useState<Relay[]>([]),
    [total, setTotal] = useState(0),
    [relayPage, setRelayPage] = useState(0);
  const [privateKey, setPrivateKey] = useState<string|null>(null);
  const [stopConfirm, setStopConfirm] = useState(false);
  const [account, setAccount] = useState(""),
    [voucher, setVoucher] = useState(""),
    [confirm, setConfirm] = useState<{ text: string; command: Command } | null>(
      null,
    ),
    [settings, setSettings] = useState<Settings | null>(null);
  const accept = useCallback((reply: Reply) => {
    if (reply.kind === "dashboard") {
      current.current = reply.dashboard;
      setData(reply.dashboard);
    } else if (reply.kind === "relays") {
      setRows(reply.relays);
      setTotal(reply.total);
      setRelayPage(reply.page);
    }
  }, []);
  const refresh = useCallback(async (manual = false) => {
    if (flight.current || stopping.current) return;
    flight.current = true;
    try {
      const reply = await request({ kind: "dashboard" });
      if (mounted.current && !stopping.current) {
        const firstSnapshot = current.current === null;
        accept(reply);
        if (reply.kind === "error") {
          refreshFailed.current = true;
          setMessage(errorText(reply.code));
          setError(true);
        } else if (reply.kind === "dashboard" && actionRequested.current
          && reply.dashboard.boot_id !== actionRequested.current.boot) {
          actionRequested.current = null;
          setMessage("后台已重启，请核对刚才操作的结果。");
          setError(true);
        } else if (reply.kind === "dashboard" && actionRequested.current
          && reply.dashboard.sequence > actionRequested.current.sequence
          && !reply.dashboard.operation
          && !["connecting", "disconnecting"].includes(reply.dashboard.status)) {
          actionRequested.current = null;
          refreshFailed.current = false;
          setMessage(reply.dashboard.last_error ? errorText(reply.dashboard.last_error) : "操作已完成");
          setError(!!reply.dashboard.last_error);
        } else if (manual || firstSnapshot || refreshFailed.current) {
          setMessage(refreshFailed.current ? "后台连接已恢复" : "当前状态已同步");
          setError(false);
          refreshFailed.current = false;
        }
      }
    } catch (failure) {
      if (mounted.current && !stopping.current) {
        refreshFailed.current = true;
        setMessage(bridgeError(failure));
        setError(true);
      }
    } finally {
      flight.current = false;
    }
  }, [accept]);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const id = setInterval(() => void refresh(), 1500);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, [refresh]);
  useEffect(() => { keyGeneration.current += 1; setPrivateKey(null); }, [page]);
  useEffect(() => {
    const hide=()=>{keyGeneration.current += 1;setPrivateKey(null);};
    window.addEventListener("blur",hide);
    const visibility=()=>{if(document.hidden)hide();};
    document.addEventListener("visibilitychange",visibility);
    const timeout=privateKey ? setTimeout(hide,20000) : null;
    return ()=>{window.removeEventListener("blur",hide);document.removeEventListener("visibilitychange",visibility);if(timeout)clearTimeout(timeout);};
  },[privateKey]);
  async function act(command: Command) {
    if (stopping.current) return;
    if (flight.current) {
      setMessage("正在同步状态，请稍后再试。");
      return;
    }
    if (command.kind === "export_report" && current.current) {
      reportRequested.current = {
        operation: null,
        boot: current.current.boot_id,
      };
    }
    flight.current = true;
    refreshFailed.current = false;
    actionRequested.current = null;
    setPending(true);
    setError(false);
    setMessage("正在提交操作…");
    const revealGeneration = keyGeneration.current;
    try {
      const reply = await request(command);
      if (!mounted.current || stopping.current) return;
      accept(reply);
      if (reply.kind === "error") {
        if (command.kind === "export_report") reportRequested.current = null;
        setMessage(errorText(reply.code));
        setError(true);
      } else if (reply.kind === "private_key") {
        if (revealGeneration !== keyGeneration.current || activePage.current !== "account" || document.hidden || !document.hasFocus()) return;
        setPrivateKey(reply.private_key);
        setMessage("私钥仅在本机显示，20 秒后或离开窗口时自动隐藏。");
      } else if (reply.kind === "report") {
        reportRequested.current = null;
        try {
          await copyReport(reply.path);
          setMessage("诊断文件已创建，路径已复制。可直接发给本地 Agent。");
        } catch (failure) {
          setMessage(`${bridgeError(failure)} 文件：${reply.path}`);
          setError(true);
        }
      } else {
        if (reply.kind === "accepted" && command.kind !== "export_report" && current.current) {
          actionRequested.current = { boot: current.current.boot_id, sequence: current.current.sequence };
        }
        if (command.kind === "export_report" && reply.kind === "accepted" && reportRequested.current) {
          reportRequested.current.operation = reply.operation_id;
        }
        setMessage(
          reply.kind === "accepted"
            ? "操作已受理，进度将在这里更新。"
            : "操作已完成",
        );
      }
    } catch (failure) {
      if (command.kind === "export_report") reportRequested.current = null;
      setError(true);
      setMessage(bridgeError(failure));
    } finally {
      flight.current = false;
      if (mounted.current && !stopping.current) setPending(false);
    }
  }
  async function stopApp() {
    setStopConfirm(false);
    keyGeneration.current += 1;
    setPrivateKey(null);
    setPending(true);
    try {
      await stopBackendAndExit();
    } catch (failure) {
      setMessage(bridgeError(failure));
      setError(true);
      setPending(false);
    }
  }
  async function copySavedReport(path: string) {
    if (flight.current) {
      setMessage("正在同步状态，文件已保留，请稍后点击重新复制。");
      return;
    }
    flight.current = true;
    setPending(true);
    try {
      await copyReport(path);
      if (mounted.current) {
        setMessage("诊断文件已创建，路径已复制。可直接发给本地 Agent。");
        setError(false);
      }
    } catch (failure) {
      if (mounted.current) {
        setMessage(`${bridgeError(failure)} 文件：${path}`);
        setError(true);
      }
    } finally {
      flight.current = false;
      if (mounted.current) setPending(false);
    }
  }
  function saveCities(ids: string[]) {
    if (!data) return;
    void act({
      kind: "save_settings",
      settings: {
        ...data.settings,
        favorite_cities: ids,
        selected_city: ids.includes(data.settings.selected_city ?? "")
          ? data.settings.selected_city
          : (ids[0] ?? null),
      },
    });
  }
  useEffect(() => {
    const requested = reportRequested.current;
    if (!requested || !data) return;
    if (data.boot_id !== requested.boot) {
      reportRequested.current = null;
      setMessage("后台已重启，请重新生成诊断文件。");
      setError(true);
    } else if (data.last_report_path && reportMatchesOperation(data.last_report_path, requested.operation)) {
      reportRequested.current = null;
      void copySavedReport(data.last_report_path);
    } else if (!data.operation && data.last_error === "report_write_failed") {
      reportRequested.current = null;
      setMessage(errorText("report_write_failed"));
      setError(true);
    }
  }, [data?.last_report_path, data?.boot_id, data?.operation, data?.last_error]);
  const chosen = data?.cities.find((c) => c.id === data.settings.selected_city),
    busy = pending || !!data?.operation,
    quickState = data?.quick_test;
  useEffect(() => {
    if (page === "diagnostics" && data && !settings)
      setSettings({ ...data.settings });
  }, [page, data, settings]);
  useEffect(() => {
    if (page === "relays" && data && !flight.current)
      void act({ kind: "relays", city: null, page: 0 });
  }, [
    page,
    data?.boot_id,
    data?.metadata_updated_at,
    data?.quick_test?.finished_at,
  ]);
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">M</span>
          <div>
            Mullvad Adapter<small>固定城市 · 安全恢复</small>
          </div>
        </div>
        <nav aria-label="主导航">
          {pages.map((p) => (
            <button
              key={p.id}
              aria-current={page === p.id ? "page" : undefined}
              className={page === p.id ? "nav-item selected" : "nav-item"}
              onClick={() => {
                initialDestination.current = true;
                setPage(p.id);
                setSettings(null);
              }}
            >
              <span aria-hidden="true">{p.mark}</span>
              {p.name}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span
            className={`status-dot ${data?.status === "connected" ? "green" : ""}`}
          />
          {data ? (statusText[data.status] ?? data.status) : "后台连接中"}
          <small>
            本机入口 {data ? `127.0.0.1:${data.settings.front_port}` : "—"}
          </small>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <p className="eyebrow">WINDOWS WORKSPACE</p>
            <h1>{pages.find((p) => p.id === page)?.name}</h1>
          </div>
          <button
            className="quiet"
            onClick={() => void refresh(true)}
            disabled={pending}
          >
            刷新状态
          </button>
        </header>
        <div
          className={`notice ${error ? "notice-error" : ""}`}
          role="status"
          aria-live="polite"
        >
          <span
            className={busy ? "spinner" : "notice-dot"}
            aria-hidden="true"
          />
          <span>
            {data?.operation
              ? `正在进行：${operationText[data.operation] ?? data.operation}`
              : message}
          </span>
        </div>
        {page === "setup" && <SetupPage data={data} navigate={setPage}/>}
        {page === "clash" && <ClashPage frontPort={data?.settings.front_port??17890} connected={data?.status==="connected"} disabled={!data||busy} bootstrapPort={data?.settings.bootstrap_port??null} onUseProxy={async(port)=>{
          const latest=current.current;if(!latest)throw new Error("backend_unavailable");
          const reply=await request({kind:"save_settings",settings:{...latest.settings,bootstrap_port:port}});
          if(reply.kind==="error")throw new Error(reply.code);
          accept(reply);
        }}/>}
        {page === "cities" && (
          <>
            <section className="intro">
              <h2>选择一个城市，其余交给后台</h2>
              <p>
                维护最多三个常用城市。自动恢复留在当前城市；本机断网时等待恢复，先验证原连接。
              </p>
            </section>
            <div className="city-grid">
              {[0, 1, 2].map((index) => {
                const id = data?.settings.favorite_cities[index],
                  city = data?.cities.find((c) => c.id === id),
                  selected = !!id && id === data?.settings.selected_city;
                return id ? (
                  <button
                    key={id}
                    className={`city-card ${selected ? "active" : ""}`}
                    disabled={busy}
                    aria-pressed={selected}
                    onClick={() => void act({ kind: "select_city", city: id })}
                  >
                    <div className="city-card-top">
                      <span>
                        {city?.country ?? id.split("-")[0].toUpperCase()}
                      </span>
                      <span>{selected ? "当前城市" : "常用城市"}</span>
                    </div>
                    <strong>{city?.name ?? id}</strong>
                    <small>{city?.relay_count ?? "—"} 个目录节点</small>
                    <span className="city-card-bottom">
                      {selected ? "查看当前连接 ↓" : "选择此城市 →"}
                    </span>
                  </button>
                ) : (
                  <button
                    key={index}
                    className="city-card empty"
                    disabled={!data || busy}
                    onClick={() => {
                      setChooser(true);
                      setSearch("");
                    }}
                  >
                    <span className="plus">+</span>
                    <strong>添加常用城市</strong>
                    <small>最多三个，随时可调整</small>
                  </button>
                );
              })}
            </div>
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">CURRENT CONNECTION</p>
                  <h2>{chosen?.name ?? (data?.settings.selected_city ? "节点目录尚未加载" : "尚未选择城市")}</h2>
                </div>
                <span
                  className={`pill ${data?.status === "connected" ? "positive" : ""}`}
                >
                  {data ? (statusText[data.status] ?? data.status) : "等待后台"}
                </span>
              </div>
              <div className="connection-facts">
                <div>
                  <small>主节点</small>
                  <strong>{data?.active_relay ?? "尚未建立"}</strong>
                </div>
                <div>
                  <small>设备身份</small>
                  <strong>{data?.device_name ?? "尚未导入"}</strong>
                </div>
                <div>
                  <small>本机网络</small>
                  <strong>
                    {data?.physical_attachment === "available"
                      ? "已有本地接入"
                      : data?.physical_attachment === "unavailable"
                        ? "已断开，等待恢复"
                        : "正在确认"}
                  </strong>
                </div>
              </div>
              <div className="panel-actions">
                <button
                  className="primary"
                  disabled={!data || busy || !chosen}
                  onClick={() =>
                    void act({
                      kind: data?.active_relay && data.status==="connected" ? "disconnect" : "connect",
                    })
                  }
                >
                  {data?.active_relay && data.status==="connected" ? "断开连接" : data?.active_relay ? "重连当前节点" : "连接当前城市"}
                </button>
                <button
                  disabled={!chosen || busy}
                  onClick={() =>
                    chosen && void act({ kind: "quick_test", city: chosen.id })
                  }
                >
                  快速检查
                </button>
                <button
                  className="quiet"
                  disabled={!data || busy}
                  onClick={() => setChooser(true)}
                >
                  管理城市
                </button>
              </div>
              <p className="hint">
                备用由低成本检查和有时效的历史筛选。ICMP
                通过不表示隧道可用，切换前完整验证；不常驻第二条同身份通道。
              </p>
              <div className="backup-grid" aria-label="同城备选">
                {[0, 1].map((index) => {
                  const candidate = data?.city_candidates.filter(
                    (c) => c.city === chosen?.id,
                  )[index];
                  return (
                    <div className="backup-card" key={index}>
                      <small>备选 {index + 1} · 切换前验证</small>
                      <strong>{candidate?.hostname ?? "等待快速检查"}</strong>
                      <span>
                        {candidate
                          ? `${candidate.ping_ms} ms · 仅 ICMP`
                          : "未建立第二条隧道"}
                      </span>
                      <small>
                        {candidate
                          ? timeText(candidate.measured_at)
                          : "只选择当前城市内的节点"}
                      </small>
                    </div>
                  );
                })}
              </div>
              {quickState && quickState.city === chosen?.id && (
                <div className="quick-progress" aria-live="polite">
                  <div className="panel-heading">
                    <strong>
                      {quickState.active
                        ? "快速检查进行中"
                        : quickState.cancelled
                          ? "检查已取消，旧结果未更新"
                          : "快速检查已结束"}
                    </strong>
                    {quickState.active && (
                      <button
                        disabled={pending}
                        onClick={() => void act({ kind: "cancel_operation" })}
                      >
                        取消检查
                      </button>
                    )}
                  </div>
                  <progress
                    aria-label="城市检查进度"
                    max={Math.max(1, quickState.total)}
                    value={quickState.completed}
                  />
                  <p>
                    {quickState.completed}/{quickState.total} 已处理 ·{" "}
                    {quickState.replies} 回复 · {quickState.no_reply} 未回应 ·{" "}
                    {quickState.local_errors} 本地检查异常 ·{" "}
                    {quickState.discarded} 已丢弃 · {quickState.unmeasured} 未测
                  </p>
                  <small>
                    未收到 ICMP
                    回复可能是服务器不响应；不会据此标记隧道失效。网络变化时丢弃本轮结果。
                  </small>
                </div>
              )}
              {data?.last_error && (
                <div className="inline-error">{errorText(data.last_error)}</div>
              )}
            </section>
            <section className="panel compact">
              <div>
                <h3>需要排查时，一键交给本地 Agent</h3>
                <p>生成脱敏状态文件，包含阶段、网络观察和日志位置。</p>
              </div>
              <button
                disabled={!data || pending}
                onClick={() => void act({ kind: "export_report" })}
              >
                复制当前状态
              </button>
            </section>
          </>
        )}
        {page === "account" && (
          <>
            <section className="panel">
              <div className="panel-heading">
                <h2>本机隧道身份</h2>
                <span className="pill">
                  {data?.identity_configured
                    ? "已保存至本机安全存储"
                    : "尚未配置"}
                </span>
              </div>
              <dl className="details">
                <div>
                  <dt>设备名称</dt>
                  <dd>{data?.device_name ?? "未配置"}</dd>
                </div>
                <div>
                  <dt>WireGuard 公钥</dt>
                  <dd className="mono">{data?.public_key ?? "未配置"}</dd>
                </div>
                <div>
                  <dt>当前隧道</dt>
                  <dd>{data?.active_relay ?? "尚未连接"}</dd>
                </div>
              </dl>
              <div className="panel-actions">
                <button disabled={busy || !data?.identity_configured} onClick={()=>privateKey ? setPrivateKey(null) : setConfirm({text:"在本机显示当前设备私钥？请勿发送给别人或放进诊断报告。20 秒后、离开页面或窗口时自动隐藏。",command:{kind:"reveal_key",confirm:true}})}>{privateKey ? "隐藏私钥" : "查看本机私钥…"}</button>
              </div>
              {privateKey && <div className="secret-display"><strong>当前设备私钥 · 本机临时显示</strong><code>{privateKey}</code></div>}
              <p className="hint">
                账号用于管理设备与有效期；隧道是否连接以实际验证结果为准。私钥由
                Windows DPAPI 保护。
              </p>
            </section>
            <section className="panel">
              <div className="panel-heading">
                <h2>Mullvad 账号</h2>
                <span className="pill">
                  {data?.account.authenticated ? "已登录" : "尚未登录"}
                </span>
              </div>
              {!data?.account.authenticated ? (
                <form
                  className="inline-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const value = account;
                    setAccount("");
                    void act({ kind: "account_login", account: value });
                  }}
                >
                  <label>
                    16 位账号
                    <input
                      type="password"
                      autoComplete="off"
                      inputMode="numeric"
                      value={account}
                      onChange={(e) => setAccount(e.target.value)}
                      placeholder="只发送至本机后台"
                    />
                  </label>
                  <button
                    className="primary"
                    disabled={busy || account.replaceAll(" ", "").length !== 16}
                  >
                    登录
                  </button>
                </form>
              ) : (
                <>
                  <dl className="details">
                    <div>
                      <dt>有效期</dt>
                      <dd>
                        {data.account.expiry
                          ? new Date(data.account.expiry).toLocaleString(
                              "zh-CN",
                            )
                          : "等待刷新"}
                      </dd>
                    </div>
                  </dl>
                  <div className="panel-actions">
                    <button
                      disabled={busy}
                      onClick={() => void act({ kind: "account_refresh" })}
                    >
                      刷新账号与设备
                    </button>
                    <button
                      className="quiet"
                      disabled={busy}
                      onClick={() =>
                        setConfirm({
                          text: "退出账号管理会清除登录信息，导入的隧道身份将保留。",
                          command: { kind: "account_logout" },
                        })
                      }
                    >
                      退出账号
                    </button>
                  </div>
                </>
              )}
              {data?.account.error_code && (
                <p className="inline-error">
                  {errorText(data.account.error_code)}
                </p>
              )}
            </section>
            {data?.account.authenticated && (
              <section className="panel">
                <div className="panel-heading"><h2>设备列表 · {data.account.devices.length} 台</h2>
                  <button disabled={!canCreateDevice(data,busy)} onClick={()=>setConfirm({text:"为本机创建新的 Mullvad 设备？密钥会先保存到本机安全存储，再注册公钥。这会占用一个设备名额，当前连接保持原身份。",command:{kind:"create_device",confirm:true}})}>为本机创建新设备…</button>
                </div>
                <p className="hint">这里列出此账号下的设备。官方接口只提供公钥；其他电脑的私钥无法从服务端取回。</p>
                {data.account.devices.length>=5&&<p className="clash-warning">已达到 5 台设备上限。需要新增设备时，请先明确撤销一台不再使用的设备，再创建；本机正在使用的设备受保护，不会自动删除。</p>}
                {data.device_draft && <div className="device-draft">
                  <strong>{data.device_draft.device_name ?? "本机待确认设备"}</strong>
                  <small className="mono">{data.device_draft.public_key}</small>
                  <p>{data.device_draft.state==="created" ? (data.public_key===data.device_draft.public_key ? "已启用为本机身份，私钥保存在本机安全存储。" : "设备已注册，私钥保存在本机；等待明确启用。") : "注册结果尚未确认，密钥已保留。请刷新官方设备列表核对，不要重复注册。"}</p>
                  {data.device_draft.state==="created" && data.public_key!==data.device_draft.public_key && <button disabled={busy || data.status!=="disconnected" || data.front_selected!=="reject"} onClick={()=>setConfirm({text:"使用这个新设备作为本机隧道身份？请先断开连接。旧身份会保留在安全备份中，随后需要重新连接验证。",command:{kind:"use_created_device",confirm:true}})}>使用这个设备</button>}
                  {data.public_key===data.device_draft.public_key && <span className="pill positive">已作为本机身份</span>}
                </div>}

                {data.account.devices.length === 0 ? (
                  <p className="hint">尚未取得设备列表，请刷新。</p>
                ) : (
                  <div>
                    {data.account.devices.map((d) => (
                      <div className="device-row" key={d.id}>
                        <div>
                          <strong>{d.name}</strong>
                          <small className="mono">{d.public_key}</small>
                        </div>
                        {d.current ? (
                          <span className="pill positive">本机身份</span>
                        ) : (
                          <button
                            className="quiet danger"
                            disabled={busy}
                            onClick={() =>
                              setConfirm({
                                text: `撤销设备“${d.name}”（设备 ID：${d.id}；公钥：${d.public_key}）后，其隧道将无法继续连接。`,
                                command: {
                                  kind: "remove_device",
                                  device_id: d.id,
                                },
                              })
                            }
                          >
                            撤销设备
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                <form
                  className="inline-form voucher"
                  onSubmit={(e) => {
                    e.preventDefault();
                    setConfirm({
                      text: "确认兑换充值码？结果未确认时请先刷新核对，不重复提交。",
                      command: { kind: "redeem_voucher", voucher },
                    });
                    setVoucher("");
                  }}
                >
                  <label>
                    充值码
                    <input
                      type="password"
                      autoComplete="off"
                      value={voucher}
                      onChange={(e) => setVoucher(e.target.value)}
                    />
                  </label>
                  <button disabled={busy || !voucher}>兑换</button>
                </form>
              </section>
            )}
            <section className="panel">
              <h2>连接保护</h2>
              <p>
                Windows 多跳与抗量子隧道仍在接入验收，必需保护不会静默降级。
              </p>
              {["多跳", "抗量子密钥协商", "DAITA"].map((name) => (
                <div className="feature-row" key={name}>
                  <span>{name}</span>
                  <span className="pill">
                    {name === "DAITA" ? "当前引擎不支持" : "尚未验收"}
                  </span>
                </div>
              ))}
            </section>
          </>
        )}
        {page === "relays" && (
          <>
            <section className="intro">
              <h2>完整目录，用于查看与选择</h2>
              <p>官方活跃标记与支持的传输是元数据，不表示当前连通。</p>
            </section>
            <section className="panel">
              <div className="panel-heading">
                <span>
                  共 {total} 个节点 ·{" "}
                  {timeText(data?.metadata_updated_at ?? null)}
                  {data?.metadata_source === "local_cache" ? " · 本机缓存（获取时间未核实，可更新）" : data?.metadata_source === "official_api" ? " · 官方 API" : " · 尚未取得官方目录"}
                </span>
                <button
                  disabled={!data || busy}
                  onClick={() => void act({ kind: "refresh_catalogue" })}
                >
                  更新目录
                </button>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>节点</th>
                      <th>城市</th>
                      <th>传输</th>
                      <th>最近快速检查</th>
                      <th>连接</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.hostname}>
                        <td>
                          <strong>{r.hostname}</strong>
                          <small>{r.active ? "官方活跃" : "官方停用"}</small>
                        </td>
                        <td>
                          {data?.cities.find((c) => c.id === r.city)?.name ??
                            r.city}
                        </td>
                        <td>
                          {[
                            r.shadowsocks && "SS",
                            r.ipv6 && "IPv6",
                            r.ipv4 && "IPv4",
                          ]
                            .filter(Boolean)
                            .join(" / ")}
                        </td>
                        <td>
                          {r.last_ping_ms !== null
                            ? `${r.last_ping_ms} ms · 仅 ICMP`
                            : "未测或未回应"}
                        </td>
                        <td><button disabled={busy || !r.active || r.city!==data?.settings.selected_city}
                          onClick={()=>void act({kind:"connect_relay",hostname:r.hostname})}>
                          {r.city===data?.settings.selected_city ? "连接此节点" : "请先选择城市"}</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!rows.length && (
                  <p className="empty-state">
                    尚未取得目录。可直接更新；若接口受限，请在设置中指定独立外网代理。
                  </p>
                )}
              </div>
              <div className="pagination">
                <button
                  disabled={busy || relayPage === 0}
                  onClick={() =>
                    void act({
                      kind: "relays",
                      city: null,
                      page: relayPage - 1,
                    })
                  }
                >
                  上一页
                </button>
                <span>第 {relayPage + 1} 页</span>
                <button
                  disabled={busy || (relayPage + 1) * 64 >= total}
                  onClick={() =>
                    void act({
                      kind: "relays",
                      city: null,
                      page: relayPage + 1,
                    })
                  }
                >
                  下一页
                </button>
              </div>
            </section>
          </>
        )}
        {page === "diagnostics" && (
          <>
            <section className="panel">
              <div className="panel-heading">
                <div><h2>后台与退出</h2><p>停止连接和本机入口，确认后台退出后关闭应用。</p></div>
                <button disabled={pending} onClick={() => setStopConfirm(true)}>停止后台并退出</button>
              </div>
            </section>
            <section className="panel">
              <div className="panel-heading">
                <h2>当前状态与日志</h2>
                <div className="button-row">
                  <button
                    className="primary"
                    disabled={!data || pending}
                    onClick={() => void act({ kind: "export_report" })}
                  >
                    生成文件并复制路径
                  </button>
                  <button
                    disabled={!data?.last_report_path || pending}
                    onClick={() =>
                      data?.last_report_path && void copySavedReport(data.last_report_path)
                    }
                  >
                    重新复制路径
                  </button>
                </div>
              </div>
              <dl className="details">
                {data?.connection && <>
                  <div><dt>最近连接目标</dt><dd>{data.connection.relay} · {data.connection.city}</dd></div>
                  <div><dt>外层 SS 入口</dt><dd className="mono">{data.connection.inlet} · 网卡 {data.connection.interface_index}</dd></div>
                  <div><dt>最近一次测量</dt><dd>{([["IP",data.connection.ip,data.connection.probes?.ip],["DNS",data.connection.dns,data.connection.probes?.dns],["HTTPS",data.connection.https,data.connection.probes?.https]] as const).map(([name,result,outcome])=>`${name}：${probeText(result,outcome)}`).join(" · ")}</dd></div>
                </>}
                <div>
                  <dt>固定入口</dt>
                  <dd>
                    127.0.0.1:{data?.settings.front_port ?? "—"} ·{" "}
                    {data?.front_ready ? "进程已验证" : "尚未就绪"}
                  </dd>
                </div>
                <div>
                  <dt>入口指向</dt>
                  <dd>{data?.front_selected ?? "未知"}</dd>
                </div>
                <div>
                  <dt>日志位置</dt>
                  <dd className="mono">{data?.logs_path ?? "等待后台"}</dd>
                </div>
                <div>
                  <dt>最近诊断文件</dt>
                  <dd className="mono">{data?.last_report_path ?? "尚未生成"}</dd>
                </div>
                <div>
                  <dt>日志状态</dt>
                  <dd>
                    {data?.logging_degraded
                      ? `记录异常，丢弃 ${data.logging_dropped} 条`
                      : "正常记录"}
                  </dd>
                </div>
                <div>
                  <dt>源码 SHA</dt>
                  <dd className="mono">
                    {data?.source_sha || "开发构建，未绑定候选"}
                  </dd>
                </div>
                <div>
                  <dt>后台版本</dt>
                  <dd>{data?.build ?? "—"}</dd>
                </div>
              </dl>
              <p className="hint">
                日志按总量约 20 MB
                轮转，时长取决于事件量。报告不含账号、私钥和登录令牌。
              </p>
            </section>
            {settings && (
              <section className="panel">
                <h2>连接设置</h2>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void act({ kind: "save_settings", settings });
                  }}
                >
                  <div className="settings-grid">
                    <label>
                      本地入口端口
                      <input
                        type="number"
                        min="1024"
                        max="65535"
                        value={settings.front_port}
                        disabled
                        onChange={(e) =>
                          setSettings({
                            ...settings,
                            front_port: Number(e.target.value),
                          })
                        }
                      />
                    </label>
                    <label>
                      目录 / 账号代理端口（可选）
                      <input
                        type="number"
                        min="1024"
                        max="65535"
                        value={settings.bootstrap_port ?? ""}
                        placeholder="留空使用系统网络；可填 Clash mixed-port"
                        onChange={(e) =>
                          setSettings({
                            ...settings,
                            bootstrap_port: e.target.value
                              ? Number(e.target.value)
                              : null,
                          })
                        }
                      />
                    </label>
                  </div>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={settings.automatic_recovery}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          automatic_recovery: e.target.checked,
                        })
                      }
                    />
                    <span>网络恢复后先验证原连接，再按需要同城恢复</span>
                  </label>
                  <p className="hint">
                    留空时通过系统网络访问官方 HTTPS 接口，不读取环境代理；受限网络可填独立代理。Clash 的 API 路由不能指回本适配器入口。
                  </p>
                  <button className="primary" disabled={busy}>
                    保存设置
                  </button>
                </form>
              </section>
            )}
          </>
        )}
        <footer>
          关闭窗口可从托盘重新打开。这里只保护经过适配器的流量，系统分流由外部代理管理。
        </footer>
      </main>
      {chooser && data && (
        <Modal labelledBy="city-title" onClose={() => setChooser(false)}>
          <div className="panel-heading">
            <h2 id="city-title">
              管理常用城市{" "}
              <small>{data.settings.favorite_cities.length}/3</small>
            </h2>
            <button className="quiet" onClick={() => setChooser(false)}>
              关闭
            </button>
          </div>
          <label>
            搜索城市
            <input
              autoFocus
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="城市名称或代码"
            />
          </label>
          <div className="city-list">
            {data.cities
              .filter((c) =>
                `${c.name} ${c.country} ${c.id}`
                  .toLowerCase()
                  .includes(search.toLowerCase()),
              )
              .map((c) => {
                const selected = data.settings.favorite_cities.includes(c.id);
                return (
                  <button
                    key={c.id}
                    disabled={
                      busy ||
                      (!selected && data.settings.favorite_cities.length >= 3)
                    }
                    aria-pressed={selected}
                    className={selected ? "city-option pinned" : "city-option"}
                    onClick={() =>
                      saveCities(
                        selected
                          ? data.settings.favorite_cities.filter(
                              (id) => id !== c.id,
                            )
                          : [...data.settings.favorite_cities, c.id],
                      )
                    }
                  >
                    <span>
                      <strong>{c.name}</strong>
                      <small>
                        {c.country} · {c.id} · {c.relay_count} 个节点
                      </small>
                    </span>
                    <span>{selected ? "移除" : "添加"}</span>
                  </button>
                );
              })}
          </div>
          {!data.cities.length && (
            <p>目录尚未加载，请先更新节点目录；接口受限时可配置独立外网代理。</p>
          )}
        </Modal>
      )}
      {stopConfirm && (
        <Modal small labelledBy="stop-confirm-title" onClose={() => setStopConfirm(false)}>
          <h2 id="stop-confirm-title">停止后台并退出</h2>
          <p>当前连接会断开。本机入口和后台将停止；账号、设备密钥和日志会保留。</p>
          <div className="panel-actions">
            <button autoFocus onClick={() => setStopConfirm(false)}>取消</button>
            <button className="primary" onClick={() => void stopApp()}>确认停止</button>
          </div>
        </Modal>
      )}
      {confirm && (
        <Modal
          small
          labelledBy="confirm-title"
          onClose={() => setConfirm(null)}
        >
          <h2 id="confirm-title">确认操作</h2>
          <p>{confirm.text}</p>
          <div className="panel-actions">
            <button autoFocus onClick={() => setConfirm(null)}>
              取消
            </button>
            <button
              className="primary"
              onClick={() => {
                const command = confirm.command;
                setConfirm(null);
                void act(command);
              }}
            >
              确认
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
