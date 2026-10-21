// Pure server-side React rendering. No browser, installed app or native invokes.
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {createServer} from 'vite';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const server=await createServer({configFile:false,root,server:{middlewareMode:true,hmr:false,watch:null},appType:'custom'});
try {
 const {RecoveryPanel}=await server.ssrLoadModule('/src/recovery-panel.tsx');
 const {SetupPage}=await server.ssrLoadModule('/src/setup-page.tsx');
 const {StatusReadStrip}=await server.ssrLoadModule('/src/status-read-strip.tsx');
 const {StatusReadHealth}=await server.ssrLoadModule('/src/status-read.ts');
 const d={boot_id:'fixture',sequence:1,status_observation:{age_ms:0,capture_ms:0,native_elapsed_ms:0},status:'connected',physical_attachment:'available',active_relay:'us-sjc-wg-001',identity_configured:true,device_name:'fixture',front_ready:true,front_selected:'slot_a',readiness:'ready',settings:{selected_city:'us-sjc',favorite_cities:['us-sjc']},connection:{relay:'us-sjc-wg-001',dns:true,https:true},account:{authenticated:false,devices:[]}};
 const render=(component,props)=>renderToStaticMarkup(React.createElement(component,props));
 const fresh=render(RecoveryPanel,{data:d,busy:false,observationCurrent:true,onAction:async()=>{}});
 assert.match(fresh,/通道健康/);assert.match(fresh,/pill positive/);
 const old=render(RecoveryPanel,{data:d,busy:false,observationCurrent:false,onAction:async()=>{}});
 assert.match(old,/当前状态未确认/);assert.match(old,/上次目标/);assert.match(old,/等待最新状态/);
 assert.doesNotMatch(old,/pill positive|通道健康|aria-current="step"/);
 assert.match(render(SetupPage,{data:d,navigate:()=>{},observationCurrent:true}),/当前隧道检查通过/);
 const setup=render(SetupPage,{data:d,navigate:()=>{},observationCurrent:false});
 assert.match(setup,/等待最新连接状态/);assert.doesNotMatch(setup,/当前隧道检查通过/);
 const health=new StatusReadHealth();health.success(health.begin(),d,0,0);
 const read=render(StatusReadStrip,{view:health.view(4000)});
 assert.match(read,/status-read-strip delayed/);assert.match(read,/状态更新延迟/);
 assert.match(read,/4 秒前/);assert.doesNotMatch(read,/后台不可用|隧道已断开/);
 health.failure(health.begin(),'Bearer private-sentinel',5000);
 assert.doesNotMatch(render(StatusReadStrip,{view:health.view(5000)}),/private-sentinel|Bearer/);
 console.log('status presentation: fresh/stale recovery, setup, observed age and private-error suppression PASS');
} finally { await server.close(); }
