import type {ApiRequestEvidence} from './app-api';
const phases:Record<string,string>={
 deadline:'本轮等待预算已用尽', dns:'域名解析未完成',
 connection_setup:'连接建立未完成（TCP、代理转接或 TLS，尚不能细分）',
 proxy_connect:'代理转接未通过', tls:'TLS 安全连接未通过',
 response_headers:'等待官方响应头', response_body:'读取官方响应内容',
 transport_unknown:'连接失败，具体阶段未确认',
};
export function apiRouteText(route?:string|null) {
 const routes:Record<string,string>={direct:'官方地址 HTTPS',independent_proxy:'本机独立代理',healthy_tunnel:'已验证健康的适配器通道'};
 return route && Object.hasOwn(routes,route)?routes[route]:'尚未确认出口';
}
export function apiRequestSummary(value?:ApiRequestEvidence|null) {
 if(!value)return '尚无账号请求记录；查询失败不等于设备已撤销。';
 const status=Number.isInteger(value.http_status)&&value.http_status!>=100&&value.http_status!<=599?value.http_status:null;
 const phase=value.phase==='http_response'?(status?`官方返回 HTTP ${status}`:'已收到官方 HTTPS 响应'):(Object.hasOwn(phases,value.phase)?phases[value.phase]:'具体请求阶段未确认');
 const ms=value.elapsed_ms;
 const elapsed=Number.isFinite(ms)&&ms>=0&&ms<=600000?` · ${(ms/1000).toFixed(1)} 秒`:'';
 return `${apiRouteText(value.route)} · ${phase}${elapsed}`;
}
export function apiCheckedAt(time?:number|null) {
 if(time==null||!Number.isFinite(time)||time<0||time>8_640_000_000_000)return '尚无成功核实时间';
 const date=new Date(time*1000);
 return Number.isFinite(date.getTime())?date.toLocaleString('zh-CN',{hour12:false}):'核实时间不可用';
}
