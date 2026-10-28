import React from 'react';
import type {Dashboard} from './app-api';
import {apiCheckedAt,apiRequestSummary} from './account-api-text';
export function AccountAPIStatus({account,busy=false}:{account:Dashboard['account'];busy?:boolean}) {
 const summary=busy?'正在查询官方账号服务，当前隧道身份保留。':account.error_code?'最近操作未完成；下面保留上次成功取得的资料。':account.checked_at?'设备资料已从官方读取；隧道状态单独判断。':'可输入账号管理设备；设备被撤销也不妨碍使用账号查询。';
 return <div className="account-api-status" aria-label="账号服务请求状态">
  <p className={account.error_code?'clash-warning':'hint'} role="status">{summary}</p>
  <p className="hint">上次成功核实：{apiCheckedAt(account.checked_at)}</p>
  <p className="hint">{apiRequestSummary(account.api_last_result)}</p>
 </div>;
}
