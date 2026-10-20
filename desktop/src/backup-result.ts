import type { Dashboard } from "./app-api";
export function backupResult(data:Dashboard,expectedId:number):string|null {
  if(data.backup_test_id!==expectedId||data.backup_test_status==null||data.backup_test_status==="testing")return null;
  if(data.backup_test_status==="passed")return data.backup_test_restored
    ? "备用路线实际流量已通过，已恢复测试前的路线。"
    : "备用路线实际流量已通过，当前已使用链式连接；原直连未就绪时继续保底。";
  if(data.backup_test_status==="cancelled")return "测试已停止。";
  return data.backup_test_restored?"备用路线未通过，已恢复测试前的路线。":"备用路线未通过，请查看上方当前恢复进度。";
}
