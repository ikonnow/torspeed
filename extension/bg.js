const API='http://127.0.0.1:8765';

// ---------- badge ----------
// Show the more recent of best/last, but only while it is fresh (<30 min).
function setBadge(t){chrome.action.setBadgeBackgroundColor({color:'#2b6'});
 chrome.action.setBadgeText({text:t});}
const badgeText=v=>v<10?v.toFixed(1):String(Math.round(v));
function badge(s){
 if(!s){setBadge('');return;}
 // during a hunt the leading value is always fresh – show it live
 if(s.hunting&&s.hunt_best_mbps){setBadge(badgeText(s.hunt_best_mbps));return;}
 const bestNewer=(s.best_at||0)>=(s.last_at||0);
 const v=bestNewer?s.best_mbps:s.last_mbps,t=bestNewer?s.best_at:s.last_at;
 setBadge(v&&t&&Date.now()/1000-t<30*60?badgeText(v):'');}

// ---------- dynamic browser proxy (PAC, fail closed) ----------
// Ports list: the active daemon's SOCKS first (only when that daemon is
// ready), then all other ready daemons' SOCKS ports, deduped. Chrome
// fails over to the next entry when one is refused – so a restarted
// browser/daemon with a new dynamic port never leaves pages dead.
// Loopback stays DIRECT (the extension must reach the API); NEVER add
// DIRECT for other hosts – fail closed, no clearnet leak.
function pacData(ports){
 return "function FindProxyForURL(u,h){ if(h=='127.0.0.1'||h=='localhost'||h=='[::1]'||h=='::1') return 'DIRECT'; return '"+
  ports.map(p=>'SOCKS5 127.0.0.1:'+p).join('; ')+"'; }";}
function portsFor(s){
 const out=[],seen={},dl=s.daemons||[];
 const add=x=>{if(x&&x.ready&&x.socks){
  const p=+String(x.socks).split(':').pop();
  if(p>0&&!seen[p]){seen[p]=1;out.push(p);}}};
 dl.forEach(x=>{if(s.daemon&&s.daemon.indexOf(x.addr)>=0)add(x)});
 dl.forEach(add);
 return out;}

async function fetchStatus(){
 try{const r=await fetch(API+'/api/status');return await r.json();}
 catch(e){return null;}}
async function proxyInfo(){
 const d=await chrome.proxy.settings.get({incognito:false});
 const v=d&&d.value||{};
 return{controlled:!!(d&&d.levelOfControl=='controlled_by_this_extension'),
  mode:v.mode||''};}

const fail=st=>{st.on=false;st.noTor=false;st.error='controlled_by_other';
 chrome.storage.local.set({on:false});return st;};

// Serialize every proxy-state operation: tick, popup polls, toggles and
// proxy-error retries must never interleave storage reads with settings
// writes – a stale run could otherwise re-set what a newer toggle just
// cleared, or un-check the popup switch after it was turned on.
let pq=Promise.resolve();
const enqueue=f=>{const r=pq.then(f);pq=r.then(()=>{},()=>{});return r;};
const syncProxy=s=>enqueue(()=>syncProxyRun(s));
const setProxy=on=>enqueue(()=>setProxyRun(on));

// Intent on = stored flag OR we already control the proxy (legacy
// fixed_servers counts – it is migrated to PAC below).
async function syncProxyRun(status){
 const st=await chrome.storage.local.get({on:false,ports:[],noTor:false,gen:0});
 if(status===undefined)status=await fetchStatus();
 const info=await proxyInfo();
 const havePac=info.controlled&&info.mode=='pac_script';
 const legacy=info.controlled&&info.mode=='fixed_servers';
 if(!(st.on||havePac||legacy)){st.on=false;st.noTor=false;return st;}
 let ports=status?portsFor(status):[];
 st.noTor=!ports.length;
 // fail closed: never leave the browser unproxied while intent is on –
 // fall back to the last known ports, then to the own-daemon port 9050.
 if(!ports.length)ports=st.ports.length?st.ports:[9050];
 if(!havePac||legacy||JSON.stringify(ports)!==JSON.stringify(st.ports)){
  try{await chrome.proxy.settings.set({scope:'regular',
   value:{mode:'pac_script',
    pacScript:{data:pacData(ports),mandatory:true}}});
  }catch(e){return fail(st);}
  const after=await proxyInfo();
  if(!(after.controlled&&after.mode=='pac_script'))return fail(st);
  st.ports=ports;}
 // reached only with our pac_script active → toggle = intent && control
 st.on=true;st.error='';
 await chrome.storage.local.set({on:true,ports:st.ports,noTor:st.noTor});
 return st;}

async function setProxyRun(on){
 // gen marks each intent change; replies carrying an older gen are stale.
 const g=(await chrome.storage.local.get({gen:0})).gen+1;
 if(on){
  chrome.privacy.network.webRTCIPHandlingPolicy.set({value:'disable_non_proxied_udp'});
  await chrome.storage.local.set({on:true,gen:g});
  return syncProxyRun();}
 await chrome.proxy.settings.clear({scope:'regular'});
 chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
 await chrome.storage.local.set({on:false,ports:[],noTor:false,gen:g});
 return{on:false,ports:[],noTor:false,gen:g};}

// onProxyError fires per failed request (every failover off a dead
// port) – throttle to one sync per 5 s, reusing an in-flight run.
let lastErrSync=0,errSyncing=null;
function errSync(){
 if(errSyncing)return errSyncing;
 if(Date.now()-lastErrSync<5000)return Promise.resolve(null);
 lastErrSync=Date.now();
 errSyncing=syncProxy().finally(()=>{errSyncing=null;});
 return errSyncing;}

// Native host starts 'torspeed --serve' if it is not running. Only on
// browser/extension start and when the status fetch fails – throttled
// to one spawn per 60 s (service workers wake every ~30 s).
async function ensureServer(){
 const st=await chrome.storage.local.get({lastNm:0});
 if(Date.now()-st.lastNm<60000)return;
 await chrome.storage.local.set({lastNm:Date.now()});
 try{chrome.runtime.sendNativeMessage('com.torspeed.host',{ensure:1},()=>{
  if(chrome.runtime.lastError)console.log('NM host missing: torspeed --install-ext');
 });}catch(e){}}

// MV3 workers get suspended: alarms instead of setInterval/EventSource.
// One status fetch per tick feeds both badge and proxy sync.
const tick=async()=>{
 const s=await fetchStatus();
 badge(s);
 if(!s)await ensureServer();
 await syncProxy(s);};
chrome.runtime.onStartup.addListener(()=>{ensureServer();tick();});
chrome.runtime.onInstalled.addListener(()=>{ensureServer();tick();});
chrome.alarms.get('tick',a=>{if(!a)
 chrome.alarms.create('tick',{periodInMinutes:0.5});});
chrome.alarms.onAlarm.addListener(a=>{if(a.name=='tick')tick();});
chrome.proxy.onProxyError.addListener(()=>{errSync();});
chrome.runtime.onMessage.addListener((m,q,reply)=>{
 if(!m)return;
 if(m.badge!=null){setBadge(badgeText(m.badge));return;}
 if('proxy'in m){setProxy(!!m.proxy).then(reply);return true;}
 if(m.sync){syncProxy().then(reply);return true;}});
tick();
