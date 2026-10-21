import assert from 'node:assert/strict';
import {StatusReadHealth} from '../desktop/src/status-read.ts';
import {bridgeError} from '../desktop/src/app-api.ts';
const data=(sequence=1,age_ms=0,boot_id='fixture-boot')=>({
  boot_id,sequence,status:'connected',status_observation:{age_ms,capture_ms:0,native_elapsed_ms:0},
});
let cases=0;
function check(name,test){test();cases++;console.log(`status read: ${name} PASS`);}
const observe=(h,d,started=0,now=started)=>h.success(h.begin(),d,started,now);
const fail=(h,code,now)=>h.failure(h.begin(),code,now);
check('healthy observations expire without any subsequent request or warning',()=>{
 const h=new StatusReadHealth();assert.equal(h.view(0).fresh,false);
 assert.equal(observe(h,data()),true);assert.equal(h.view(3000).fresh,true);
 assert.equal(h.view(3001).fresh,false);assert.equal(h.view(4000).kind,'stale');
 assert.match(h.view(4000).message,/4 秒前/);
});
check('busy and startup do not accumulate unreachable strikes or change the data',()=>{
 const h=new StatusReadHealth();observe(h,data());
 for(const [code,time] of [['operation_busy',100],['status_read_busy',1000],['backend_starting',2000]]){
  fail(h,code,time);assert.equal(h.view(time).fresh,true);assert.notEqual(h.view(time).kind,'unavailable');
 }
 assert.equal(h.view(3001).fresh,false);assert.equal(h.view(3001).ageSeconds,3);
});
check('sustained transport requires both three failures and ten seconds; success resets',()=>{
 const h=new StatusReadHealth();observe(h,data());
 for(const t of [1,100,200]){fail(h,'status_response_read_failed',t);assert.equal(h.view(t).kind,'transport');}
 fail(h,'status_response_read_failed',10001);assert.equal(h.view(10001).kind,'unavailable');
 observe(h,data(2),11000);assert.equal(h.view(11000).fresh,true);assert.equal(h.view(11000).kind,'ready');
 fail(h,'status_channel_unavailable',12000);assert.equal(h.view(12000).kind,'transport');
});
check('publication delay is not transport failure',()=>{
 const h=new StatusReadHealth();observe(h,data());
 for(const time of [100,5000,11000]){fail(h,'status_snapshot_stale',time);assert.equal(h.view(time).kind,'stale');}
 fail(h,'status_response_read_failed',12000);assert.equal(h.view(12000).kind,'transport');
});
check('cancellation does not advance completion fence or erase a known result',()=>{
 const h=new StatusReadHealth(),older=h.begin(),cancelled=h.begin();
 assert.equal(h.failure(cancelled,'cancelled',5),false);
 assert.equal(h.success(older,data(),0,6),true);
 assert.equal(fail(h,Object.assign(new Error('private'),{name:'AbortError'}),7),false);
 assert.equal(h.view(7).fresh,true);
});
check('old failures and successes cannot replace newer observations',()=>{
 const h=new StatusReadHealth(),old=h.begin(),newer=h.begin();
 assert.equal(h.success(newer,data(3),10,10),true);
 assert.equal(h.failure(old,'status_response_read_failed',11),false);
 assert.equal(h.success(old,data(1),0,12),false);assert.equal(h.view(12).kind,'ready');
});
check('same-boot sequence cannot regress or renew a repeated publication',()=>{
 const h=new StatusReadHealth();observe(h,data(5),0);
 assert.equal(observe(h,data(4),1000),false);
 assert.equal(observe(h,data(5),2000),true);
 assert.equal(h.view(3001).fresh,false);
 assert.equal(observe(h,data(0,0,'new-verified-boot'),4000),true);assert.equal(h.view(4000).fresh,true);
});
check('native age plus invoke delay cannot revive old ready',()=>{
 const h=new StatusReadHealth();assert.equal(observe(h,data(1,2300),0,700),true);
 assert.equal(h.view(701).fresh,false);
 assert.equal(observe(h,data(2,2300),1000,1701),false);
 assert.equal(h.view(1701).kind,'stale');
});
check('native elapsed time is not counted twice as stale delivery',()=>{
 const h=new StatusReadHealth();
 const d={...data(1,2000),status_observation:{age_ms:2000,capture_ms:1,native_elapsed_ms:1500}};
 assert.equal(observe(h,d,0,1500),true);assert.equal(h.view(1500).fresh,true);
 assert.equal(h.view(2501).fresh,false);
 assert.equal(observe(h,{...d,sequence:2},3000,5600),false);
});
check('missing, malformed and negative timing is invalid and never fresh',()=>{
 for(const timing of [undefined,null,{age_ms:-1,capture_ms:0},{age_ms:0,capture_ms:1},{age_ms:NaN,capture_ms:0},{age_ms:0.5,capture_ms:0}]){
  const h=new StatusReadHealth();assert.equal(observe(h,{...data(),status_observation:timing}),false);
  assert.equal(h.view(0).fresh,false);assert.equal(h.view(0).kind,'invalid');
 }
});
check('security errors remain distinct; unknown errors never echo private data',()=>{
 const h=new StatusReadHealth();fail(h,'backend_version_mismatch',0);assert.equal(h.view(0).kind,'rejected');
 for(const secret of ['private_key=sentinel',new Error('Bearer account-sentinel')]){
  fail(h,secret,20);assert.equal(h.view(20).kind,'invalid');assert.doesNotMatch(h.view(20).message,/sentinel|private_key|Bearer/);
  assert.doesNotMatch(bridgeError(secret),/sentinel|private_key|Bearer|后台暂不可达/);
 }
 assert.match(bridgeError('response_read_failed'),/核对|勿重复/);
});
check('explicit stopping is expected read suspension, not an outage alarm',()=>{
 const h=new StatusReadHealth();observe(h,data());
 const view=h.view(60000,true);assert.equal(view.kind,'stopping');assert.equal(view.fresh,false);
 assert.doesNotMatch(view.message,/更新延迟|无法读取|断网/);
 assert.equal(h.view(60000).fresh,false);
});
console.log(`status read: ${cases} scenario groups PASS (synthetic; no native app or network)`);
