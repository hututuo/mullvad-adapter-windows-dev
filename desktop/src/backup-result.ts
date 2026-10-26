import type { Dashboard } from "./app-api";
export type BackupFence={boot:string;source:string;id:number;fingerprint:string;revision:number;relay:string|null;inlet:string|null;transport:string|null};
export function canContinueBackup(data:Dashboard,fence:BackupFence):boolean {
  return data.boot_id===fence.boot && data.source_sha===fence.source
    && data.backup_test_id===fence.id && data.backup_test_status==="failed" && data.backup_test_restored===true
    && data.chain_fingerprint===fence.fingerprint && data.chain_revision===fence.revision
    && !data.operation && data.status==="connected" && data.physical_attachment==="available"
    && !data.settings.chain_selection && !data.connection?.chained
    && data.connection?.relay===fence.relay && data.connection?.inlet===fence.inlet && (data.connection?.transport??null)===fence.transport;
}
export function backupResult(data:Dashboard,expectedId:number):string|null {
  if(data.backup_test_id!==expectedId||data.backup_test_status==null||data.backup_test_status==="testing")return null;
  if(data.backup_test_status==="passed")return data.backup_test_restored
    ? "备用路线实际流量已通过，已恢复测试前的路线。"
    : "备用路线实际流量已通过，当前已使用链式连接；原直连未就绪时继续保底。";
  if(data.backup_test_status==="cancelled")return "测试已停止。";
  return data.backup_test_restored?"备用路线未通过，已恢复测试前的路线。":"备用路线未通过，请查看上方当前恢复进度。";
}
