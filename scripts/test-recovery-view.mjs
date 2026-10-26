import assert from 'node:assert/strict';
import {recoveryView} from '../desktop/src/recovery-view.ts';
const d={identity_configured:true,physical_attachment:'available',status:'disconnected',settings:{selected_city:'us-sjc'},active_relay:null,operation:null,recovery:{stage:'original_inlet',relay:'us-sjc-wg-002',inlet:'192.0.2.1:443',attempt:2,next:'same_relay_inlets'}};
assert.equal(recoveryView(d,false).target,'us-sjc-wg-002');
assert.equal(recoveryView(d,false).canRetry,true);
assert.equal(recoveryView({...d,physical_attachment:'unavailable'},false).canRetry,false);
assert.equal(recoveryView(d,true).canRetry,false);
for(const stage of ['testing_backup','restoring_previous','returning_direct'])assert.equal(recoveryView({...d,recovery:{...d.recovery,stage}},false).canRetry,false);
assert.equal(recoveryView({...d,operation:'automatic_recovery'},true).canStop,true);
assert.equal(recoveryView({...d,status:'connected',active_relay:'r',connection:{chained:true},recovery:{...d.recovery,stage:'chain_connected'}},false).chained,true);
console.log('recovery view: target, offline, trial, busy and stop guards PASS');

const {backupResult}=await import('../desktop/src/backup-result.ts');
const t={...d,backup_test_id:2,backup_test_status:'testing',backup_test_restored:false,backup_verified_at:42};
assert.equal(backupResult(t,2),null);
assert.equal(backupResult({...t,backup_test_status:'passed'},1),null);
assert.match(backupResult({...t,backup_test_status:'passed'},2),/当前已使用链式/);
assert.match(backupResult({...t,backup_test_status:'passed',backup_test_restored:true},2),/已恢复测试前/);
assert.match(backupResult({...t,backup_test_status:'cancelled'},2),/已停止/);
assert.match(backupResult({...t,backup_test_status:'failed',backup_test_restored:true},2),/未通过，已恢复/);
console.log('backup result: exact test id, in-progress, restored, rescue and cancellation PASS');

const {canContinueBackup}=await import('../desktop/src/backup-result.ts');
const restored={...t,boot_id:'boot',source_sha:'sha',status:'connected',backup_test_status:'failed',backup_test_restored:true,chain_fingerprint:'fp',chain_revision:3,connection:{relay:'r',inlet:'i',chained:false}};
const fence={boot:'boot',source:'sha',id:2,fingerprint:'fp',revision:3,relay:'r',inlet:'i',transport:null};
assert.equal(canContinueBackup(restored,fence),true);
for(const patch of [{boot_id:'new'},{source_sha:'new'},{backup_test_id:1},{backup_test_status:'passed'},{backup_test_status:'cancelled'},{backup_test_restored:false},{chain_fingerprint:'new'},{chain_revision:4},{operation:'connect'},{status:'retry_wait'},{physical_attachment:'unknown'},{settings:{...restored.settings,chain_selection:'pinned'}},{connection:{...restored.connection,chained:true}},{connection:{...restored.connection,inlet:'other'}},{connection:{...restored.connection,relay:'other'}}]) {
  assert.equal(canContinueBackup({...restored,...patch},fence),false,JSON.stringify(patch));
}
assert.equal(recoveryView({...d,status:'network_recovering',active_relay:'r',recovery:{...d.recovery,stage:'verifying_original'}},false).title,'正在复验原路径');
console.log('backup continuation: exact candidate, restored path, boot, source, cancellation, network and manual-pin fences PASS');

assert.equal(recoveryView({...d,recovery:{...d.recovery,stage:'native_ipv6',next:'native_ipv4',transport:'wireguard-ipv6'}},false).index,3);
assert.match(recoveryView({...d,recovery:{...d.recovery,stage:'native_ipv4'}},false).title,/IPv4/);
assert.equal(recoveryView({...d,recovery:{...d.recovery,stage:'chain_fallback'}},false).index,4);
assert.match(recoveryView({...d,status:'connected',connection:{transport:'wireguard-ipv6'},recovery:{...d.recovery,stage:'connected'}},false).title,/IPv6/);
assert.equal(canContinueBackup({...restored,connection:{...restored.connection,transport:'wireguard-ipv4'}},fence),false);
console.log('native recovery: V6/V4 before chain, transport labels and exact backup protocol fence PASS');
