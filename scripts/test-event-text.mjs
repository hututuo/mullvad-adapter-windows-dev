import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {eventMessages,eventView,eventTimestamp} from '../desktop/src/event-text.ts';
const source=readFileSync(new URL('../core/crates/agent/src/live_diagnostics.rs',import.meta.url),'utf8');
const closed=source.slice(source.indexOf('fn safe_event'),source.indexOf('/// Renderer-safe event'));
const codes=[...closed.matchAll(/"([a-z_]+)"/g)].map(m=>m[1]).filter(c=>!['agent','start','front','physical','api','api_access','stop','quick','connection'].includes(c));
for(const code of new Set(codes))assert.ok(eventMessages[code],`missing readable event: ${code}`);
const failed=eventView({time:1,stage:'connection',code:'active_probe_failed',relay:'test-city-wg-001',ip:'passed',dns:'timeout',https:'not_run_dns_failed'});
assert.match(failed.title,/test-city-wg-001/);assert.match(failed.probes,/DNS：超时/);assert.match(failed.probes,/HTTPS：未测/);
assert.equal(eventView({time:1,stage:'connection',code:'active_probe_cancelled'}).tone,'info');
assert.equal(eventView({time:1,stage:'connection',code:'connected',relay:'test-city-wg-001'}).tone,'success');
assert.match(eventView({time:1,stage:'connection',code:'worker_start_failed'}).title,/未记录节点/);
assert.doesNotMatch(eventView({time:1,stage:'connection',code:'worker_start_failed'}).title,/us-sjc/);
assert.match(eventView({time:1,stage:'other',code:'unknown_future'}).title,/新/);
assert.equal(eventTimestamp(Number.MAX_SAFE_INTEGER).iso,undefined);
assert.ok(eventTimestamp(1792590000).iso);
console.log(`readable event vocabulary: ${new Set(codes).size} mapped; node attribution, cancelled!=dead, DNS/HTTPS dependency and time bounds PASS`);

const {apiRequestSummary,apiRouteText}=await import('../desktop/src/account-api-text.ts');
const sample={route:'direct',endpoint:'device_list',phase:'http_response',outcome:'response_received',elapsed_ms:12,http_status:401};
assert.match(apiRequestSummary(sample),/HTTP 401/);
assert.doesNotMatch(apiRequestSummary(sample),/TLS.*失败|设备已撤销/);
for (const value of ['Bearer private-sentinel','__proto__','toString']) {
 const text=apiRequestSummary({...sample,route:value,phase:value,error_code:value,configured_endpoint:value,transaction_id:value});
 assert.doesNotMatch(text,/private-sentinel|__proto__|toString|function/);
 assert.equal(apiRouteText(value),'尚未确认出口');
}
assert.equal(eventView({time:1,stage:'api',code:'api_request_observed',api_request:sample}).tone,'warning');
assert.equal(eventView({time:1,stage:'api',code:'api_request_observed',api_request:{...sample,http_status:200}}).tone,'info');
console.log('API request text: safe closed vocabulary, HTTP != TLS/device status, no false tunnel success PASS');
