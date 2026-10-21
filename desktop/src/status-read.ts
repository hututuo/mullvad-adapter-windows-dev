import type { Dashboard } from "./app-api";

export const STATUS_MAX_AGE_MS = 3000;
type Issue = "busy" | "pending" | "stale" | "transport" | "invalid" | "rejected";
const codes: Record<string, Issue | "cancelled"> = {
  operation_busy:"busy", status_read_busy:"busy", backend_starting:"pending",
  status_snapshot_unavailable:"pending", status_snapshot_stale:"stale",
  status_channel_unavailable:"transport", backend_unavailable:"transport",
  status_request_write_failed:"transport", status_response_read_failed:"transport",
  status_response_ack_failed:"transport", response_read_failed:"transport",
  request_write_failed:"transport", response_ack_failed:"transport",
  status_response_invalid:"invalid", status_identity_mismatch:"rejected",
  backend_identity_or_pipe_rejected:"rejected", user_identity_unavailable:"rejected",
  backend_version_mismatch:"rejected", incompatible_backend:"rejected",
  incompatible_protocol:"rejected", invalid_handshake:"rejected",
  runtime_invalid:"rejected", runtime_manifest_unpinned:"rejected",
  runtime_manifest_pin_mismatch:"rejected", runtime_build_identity_missing:"rejected",
  status_read_only:"rejected", status_channel_required:"rejected",
  cancelled:"cancelled", backend_stopping:"cancelled",
};
export type StatusReadView = {
  fresh:boolean; kind:string; label:string; message:string; ageSeconds:number|null;
};

// Only observes local IPC. Never reconnects, selects nodes or retries mutations.
export class StatusReadHealth {
  private issued=0;
  private finished=0;
  private observed: { at:number; boot:string; sequence:number } | null = null;
  private issue:Issue|null=null;
  private transportFailures=0;
  private transportSince:number|null=null;

  begin():number { return ++this.issued; }
  success(id:number, data:Dashboard, started:number, now:number):boolean {
    if(id<this.finished)return false;
    const timing=data?.status_observation;
    if(!data || !Number.isFinite(now) || !Number.isFinite(started) || !timing || !Number.isSafeInteger(timing.age_ms) || !Number.isSafeInteger(timing.capture_ms)
      || !Number.isSafeInteger(timing.native_elapsed_ms) || timing.native_elapsed_ms<0 || timing.native_elapsed_ms>60000
      || timing.age_ms<0 || timing.capture_ms<0 || timing.capture_ms>timing.age_ms
      || !Number.isSafeInteger(data.sequence) || data.sequence<0 || !data.boot_id) {
      this.failure(id,"status_response_invalid",now);
      return false;
    }
    // Native has already added its pipe/delivery time to age_ms. Only add
    // the remaining invocation/scheduling delay, rather than counting it twice.
    const age=timing.age_ms+Math.max(0,now-started-timing.native_elapsed_ms);
    if(age>STATUS_MAX_AGE_MS) {
      this.failure(id,"status_snapshot_stale",now);
      return false;
    }
    // Same-boot snapshots cannot go backwards, even from a newer invocation.
    if(this.observed?.boot===data.boot_id && data.sequence<this.observed.sequence) {
      this.finished=id;
      return false;
    }
    const at=now-age;
    this.observed={at:this.observed?.boot===data.boot_id && this.observed.sequence===data.sequence
      ? Math.min(this.observed.at,at) : at,boot:data.boot_id,sequence:data.sequence};
    this.finished=id;
    this.issue=null;
    this.transportFailures=0;
    this.transportSince=null;
    return true;
  }
  failure(id:number, error:unknown, now:number):boolean {
    const kind=typeof error==="string" ? codes[error] :
      error instanceof Error && error.name==="AbortError" ? "cancelled" : undefined;
    if(id<this.finished || kind==="cancelled")return false;
    this.finished=id;
    this.issue=kind??"invalid";
    if(this.issue==="transport") {
      this.transportFailures++;
      this.transportSince??=now;
    } else { this.transportFailures=0;this.transportSince=null; }
    return true;
  }
  view(now:number):StatusReadView {
    const age=this.observed ? Math.max(0,now-this.observed.at) : null;
    const fresh=age!==null && age<=STATUS_MAX_AGE_MS && (!this.issue || this.issue==="busy" || this.issue==="pending");
    const sustained=this.issue==="transport" && this.transportFailures>=3
      && this.transportSince!==null && now-this.transportSince>=10000;
    const kind=sustained ? "unavailable" : this.issue??(fresh?"ready":this.observed?"stale":"pending");
    const label=({ready:"状态已更新",busy:"稍后重读状态",pending:"正在读取状态",stale:"状态更新延迟",
      transport:"状态暂未更新",unavailable:"无法读取本机状态",invalid:"状态读取异常",rejected:"本机通信校验未通过"} as Record<string,string>)[kind];
    const text=({ready:"状态读取独立运行，不会触发重连或测速。",busy:"本机读取暂忙，稍后自动重试；这不代表隧道断开。",
      pending:"正在等待本机状态；不会因此重试节点。",stale:"连接状态更新延迟，下面保留上次记录；尚不能据此判断断网。",
      transport:"暂未读到本机状态，正在重读；尚不能据此判断隧道中断。",
      unavailable:"持续无法读取本机状态，当前连接情况未知；正在重试。",
      invalid:"本机状态未通过核验，已保留上次记录；请查看诊断。",
      rejected:"本机身份或程序版本校验未通过；没有放宽校验，请核对配套版本。"} as Record<string,string>)[kind];
    const ageSeconds=age===null?null:Math.floor(age/1000);
    return {fresh,kind,label,message:text+(ageSeconds===null?" 尚无已确认状态。":` 上次记录为 ${ageSeconds} 秒前。`),ageSeconds};
  }
}
