import assert from "node:assert/strict";
import { canCreateDevice } from "../desktop/src/device-creation.ts";

const data={account:{authenticated:true,devices:[{}]},public_key:"active-public-key",device_draft:null};
assert.equal(canCreateDevice(data,false),true);
assert.equal(canCreateDevice({...data,account:{...data.account,devices:Array(5).fill({})}},false),false);
assert.equal(canCreateDevice({...data,account:{...data.account,authenticated:false}},false),false);
assert.equal(canCreateDevice(data,true),false);
assert.equal(canCreateDevice({...data,device_draft:{state:"created",public_key:"active-public-key"}},false),true);
assert.equal(canCreateDevice({...data,device_draft:{state:"created",public_key:"not-activated-key"}},false),false);
for(const state of ["submitted","unknown","invalid"]){
  assert.equal(canCreateDevice({...data,device_draft:{state,public_key:"active-public-key"}},false),false);
}
assert.equal(canCreateDevice({...data,device_draft:{state:"prepared",public_key:"new-saved-key"}},false),true);
console.log("device creation guards: 10 assertions PASS");
