// Unit tests for extension/bg.js – the privacy-critical PAC logic.
// bg.js runs in a vm context with fully mocked chrome.* globals so no
// browser is needed: node --test jstest/
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const SRC=readFileSync(
 join(dirname(fileURLToPath(import.meta.url)),'../extension/bg.js'),'utf8')
 +'\nglobalThis.__bg={syncProxy,setProxy,tick,badge,pacData,portsFor,'+
 'fetchStatus,ensureServer,errSync};';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

// The fake daemon world: Brave-Tor (active, ready, dynamic port),
// Tor Browser (ready), System-Tor (not ready).
const status=()=>({daemon:'Brave-Tor 127.0.0.1:60432',
 daemons:[
  {name:'Brave-Tor',addr:'127.0.0.1:60432',socks:'127.0.0.1:60431',ready:true},
  {name:'Tor Browser',addr:'127.0.0.1:9151',socks:'127.0.0.1:9150',ready:true},
  {name:'System-Tor',addr:'127.0.0.1:9051',socks:'127.0.0.1:9050',ready:false}]});
const ok=()=>Promise.resolve({json:()=>Promise.resolve(status())});
const off=()=>Promise.reject(new Error('offline'));

function makeWorld(){
 const store={},alarms={},calls={set:[],nm:0,fetch:0,badge:[]},
  ls={msg:[],startup:[],installed:[],alarm:[],proxyErr:[]};
 let proxy={levelOfControl:'not_controlled',value:{}},
  fetchImpl=off,setThrow=false;
 const chrome={
  storage:{local:{
   get:d=>Promise.resolve(Object.fromEntries(
    Object.entries(d).map(([k,v])=>[k,k in store?store[k]:v]))),
   set:o=>{Object.assign(store,o);return Promise.resolve();}}},
  proxy:{
   settings:{
    get:()=>Promise.resolve({levelOfControl:proxy.levelOfControl,
     value:JSON.parse(JSON.stringify(proxy.value))}),
    set:async({value})=>{
     if(setThrow)throw new Error('controlled by another extension');
     calls.set.push(value);
     proxy={levelOfControl:'controlled_by_this_extension',value};},
    clear:async()=>{proxy={levelOfControl:'not_controlled',value:{}};}},
   onProxyError:{addListener:f=>ls.proxyErr.push(f)}},
  privacy:{network:{webRTCIPHandlingPolicy:{set:()=>{},clear:()=>{}}}},
  alarms:{
   get:(n,cb)=>{cb(alarms[n]);},
   create:(n,o)=>{alarms[n]=o;},
   onAlarm:{addListener:f=>ls.alarm.push(f)}},
  runtime:{
   onMessage:{addListener:f=>ls.msg.push(f)},
   onStartup:{addListener:f=>ls.startup.push(f)},
   onInstalled:{addListener:f=>ls.installed.push(f)},
   sendNativeMessage:(h,m,cb)=>{calls.nm++;if(cb)cb();},
   lastError:null},
  action:{
   setBadgeBackgroundColor:()=>{},
   setBadgeText:o=>calls.badge.push(o.text)}};
 const ctx=vm.createContext({chrome,console,setTimeout,clearTimeout,
  fetch:(...a)=>{calls.fetch++;return fetchImpl(...a);}});
 vm.runInContext(SRC,ctx);
 return{store,alarms,calls,ls,chrome,bg:ctx.__bg,
  pac:()=>proxy.value.pacScript&&proxy.value.pacScript.data,
  controlled:()=>proxy.levelOfControl=='controlled_by_this_extension'&&
   proxy.value.mode=='pac_script',
  setFetch:f=>{fetchImpl=f;},
  setThrow:v=>{setThrow=v;},
  send:m=>new Promise(res=>ls.msg[0](m,{},res)),
  reset:()=>{calls.set.length=0;calls.fetch=0;calls.nm=0;calls.badge.length=0;}};
}

// bg.js boots with tick(); let it settle, then start each case clean.
const world=async()=>{const w=makeWorld();await sleep(25);w.reset();return w;};

test('enable: PAC installed, active ready daemon first, others follow',async()=>{
 const w=await world();w.setFetch(ok);
 const r=await w.send({proxy:true});
 assert.equal(r.on,true);
 const pac=w.pac();
 assert.ok(pac.includes('SOCKS5 127.0.0.1:60431'));
 assert.ok(pac.includes('SOCKS5 127.0.0.1:9150'));
 assert.ok(!pac.includes('9050'),'not-ready daemon must be excluded');
 assert.ok(pac.indexOf('60431')<pac.indexOf('9150'),
  'active daemon port must come first');
 assert.equal(w.store.noTor,false);});

test('disable then enable with same ports: PAC installed again',async()=>{
 const w=await world();w.setFetch(ok);
 await w.send({proxy:true});
 const n=w.calls.set.length;
 await w.send({proxy:false});
 assert.equal(w.controlled(),false);
 const r=await w.send({proxy:true});
 assert.equal(r.on,true);
 assert.equal(w.calls.set.length,n+1,'PAC must be re-installed');
 assert.ok(w.controlled());});

test('reload case: storage on:true, proxy not controlled -> PAC installed',async()=>{
 const w=await world();w.setFetch(ok);
 w.store.on=true;w.store.ports=[9050];
 await w.bg.tick();
 assert.ok(w.controlled(),'sync must restore our PAC after reload');
 assert.ok(w.pac().includes('SOCKS5'));});

test('offline + no stored ports: PAC falls back to 9050, noTor set',async()=>{
 const w=await world();w.setFetch(off);
 w.store.on=true;
 const r=await w.bg.syncProxy();
 assert.equal(r.on,true,'fail closed, never direct');
 assert.equal(r.noTor,true);
 assert.ok(w.pac().includes('SOCKS5 127.0.0.1:9050'));});

test('PAC is fail closed: DIRECT only for loopback',async()=>{
 const w=await world();
 const pac=w.bg.pacData([60431,9150]);
 assert.equal((pac.match(/DIRECT/g)||[]).length,1,
  'only the loopback branch may return DIRECT');
 assert.ok(pac.includes("return 'DIRECT'"));
 const proxyPart=pac.slice(pac.lastIndexOf("return '"));
 assert.ok(!proxyPart.includes('DIRECT'));
 assert.ok(proxyPart.includes('SOCKS5'));});

test('onProxyError burst: at most one status fetch per 5 s',async()=>{
 const w=await world();w.setFetch(ok);
 w.store.on=true;
 for(let i=0;i<10;i++)w.ls.proxyErr[0]();
 await sleep(30);
 assert.ok(w.calls.fetch<=1,`fetch count ${w.calls.fetch} > 1`);});

test('toggle off during in-flight sync: stays off, no stale re-set',async()=>{
 const w=await world();w.setFetch(ok);
 w.store.on=true;
 const p=w.bg.syncProxy();
 await w.send({proxy:false});
 await p;
 assert.equal(w.controlled(),false,'stale sync must not re-install PAC');
 assert.equal(w.store.on,false);});

test('replies carry gen: newer toggle wins over stale sync',async()=>{
 const w=await world();w.setFetch(ok);
 const r1=await w.send({proxy:true});
 const r2=await w.send({proxy:false});
 assert.ok(r1.gen<r2.gen,'gen must increase per intent change');
 assert.equal(r2.on,false);});

test('set() rejected by another extension: on:false + error',async()=>{
 const w=await world();w.setFetch(ok);w.setThrow(true);
 const r=await w.send({proxy:true});
 assert.equal(r.on,false);
 assert.equal(r.error,'controlled_by_other');
 assert.equal(w.store.on,false);});
