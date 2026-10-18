// No browser/real profile access. Exercise the exact appended JavaScript in an
// isolated JS realm, including unusual names and subscription regeneration.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const implementation=fs.readFileSync(new URL('../core/crates/clash-integration/src/integrate.js',import.meta.url),'utf8');
const spec={front_port:17890,target_group:'AI "出口" 🇯🇵',ordinary_proxy:'普通 \\ 节点'};
const base={proxies:[{name:spec.ordinary_proxy,type:'ss',server:'192.0.2.1',port:443,password:'synthetic-only'}],
 'proxy-groups':[{name:spec.target_group,type:'select',proxies:[spec.ordinary_proxy,'REJECT']}],
 rules:['DOMAIN,drive.google.com,DIRECT',`MATCH,${spec.target_group}`],dns:{nameserver:['192.0.2.53']},tun:{enable:false}};
const context=vm.createContext({input:structuredClone(base)});
vm.runInContext(`function main(c){c.beforeRan=true;return c;};(()=>{const before=main;const spec=${JSON.stringify(spec)};${implementation};main=function(config,...args){return integrate(before(config,...args),spec)}})(); output=main(input);`,context);
const output=JSON.parse(JSON.stringify(context.output));assert.equal(output.beforeRan,true);
assert.equal(output.proxies.length,2);assert.deepEqual(output.rules.slice(1),base.rules);
assert.deepEqual(output.dns,base.dns);assert.deepEqual(output.tun,base.tun);
assert.deepEqual(output['proxy-groups'][0].proxies.slice(1),base['proxy-groups'][0].proxies);
vm.runInContext('output=main(output)',context);assert.equal(context.output.proxies.length,2);assert.equal(context.output.rules.length,3);
const bad=vm.createContext({input:{...structuredClone(base),proxies:[{name:spec.ordinary_proxy,type:'socks5',server:'127.0.0.1',port:7897}]}});
assert.throws(()=>vm.runInContext(`${implementation};integrate(input,${JSON.stringify(spec)})`,bad),/ordinary API exit unavailable/);
console.log('PASS extension: existing main, quoted Unicode names, unrelated routes/DNS/TUN, regeneration idempotence, loopback rejection');
