import { invoke } from "@tauri-apps/api/core";
import type { EventItem } from "./event-text";
export type EventPage = { events: EventItem[]; skipped:number; truncated:boolean };
export type DesktopPreferences = { autostart:boolean; widget:boolean; startup_error:string|null };
export type DesktopStatus = { headline:string; relay:string|null; ping_ms:number|null; ping_age_seconds:number|null; state:string; stale:boolean };
export const readEvents = () => invoke<EventPage>("read_recent_events");
export const getDesktopPreferences = () => invoke<DesktopPreferences>("desktop_preferences");
export const setAutostart = (enabled:boolean) => invoke<boolean>("set_autostart",{enabled});
export const setWidget = (enabled:boolean) => invoke<boolean>("set_status_widget",{enabled});
export const getDesktopStatus = () => invoke<DesktopStatus>("desktop_status");
export const hideWidget = () => invoke<void>("hide_status_widget");
export const dragWidget = () => invoke<void>("drag_status_widget");
export const openWorkspace = () => invoke<void>("open_workspace");
export function desktopError(error:unknown):string {
  const code=typeof error==="string" ? error : "desktop_request_failed";
  const messages:Record<string,string> = {
    startup_entry_conflict:"发现同名的其他启动项，已保留原设置，没有覆盖。",
    startup_unsupported:"此系统不支持 Windows 登录自启设置。",
    log_file_rejected:"日志文件未通过安全检查，没有读取。",
    event_log_unavailable:"暂时无法读取或验证日志，已保留上次显示的内容。",
    log_read_failed:"暂时无法读取日志，已保留上次显示的内容。",
    desktop_request_failed:"设置暂未完成，请重试；没有改动当前隧道。",
  };
  return messages[code] ?? "暂时无法完成操作，请重试；现有连接保持运行。";
}
