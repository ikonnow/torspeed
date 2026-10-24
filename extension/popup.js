const de=(navigator.language||'en').toLowerCase().startsWith('de');
const L=de?{cap:'Live-Traffic · Mbit/s',dir:'direkt',pin:'Gepinnt: ',
 fast:'Bisher schnellster · Mbit/s — ',search:'Suche…',live:'Live-Traffic ',
 rand:'Zufälliger Exit (kein Pin)',run:'Suche läuft…',
 off:'offline – torspeed --serve starten',probe:'Probe ',
 dm:'Tor-Daemon',vs:'Vergleichen',nr:' (nicht bereit)',
 bt:'Browser über Tor',vp:'Systemproxy → Tor',
 nt:'Kein Tor-Daemon erreichbar – Seiten laden nicht',
 hunt:'Schnellsten Exit suchen',stop:'Stoppen & Besten behalten',
 unpin:'Exit-Pin lösen',cancel:'Abbrechen (Pin lösen)',meas:'Messen',
 other:'Eine andere Erweiterung steuert den Proxy',err:'Fehler',eip:'Exit-IP ',
 bl:'Im Hintergrund weiter optimieren'}:
{cap:'live traffic · Mbit/s',dir:'direct',pin:'Pinned: ',
 fast:'fastest so far · Mbit/s — ',search:'searching…',live:'live traffic ',
 rand:'Random exit (not pinned)',run:'Hunting…',
 off:'offline – run torspeed --serve',probe:'Probe ',
 dm:'Tor daemon',vs:'Compare',nr:' (not ready)',
 bt:'Route browser via Tor',vp:'System proxy → Tor',
 nt:"No Tor daemon reachable – pages won't load",
 hunt:'Find fastest exit',stop:'Stop & keep best',
 unpin:'Unpin exit',cancel:'Cancel (unpin)',meas:'Measure',
 other:'Another extension controls the proxy',err:'Error',eip:'exit IP ',
 bl:'Keep improving in background'};
const $=i=>document.getElementById(i);
const SV=$('sv'),S=$('s'),LV=$('lv'),R=$('r'),T=$('st'),LG=$('lg'),H=$('h'),
 Q=$('p'),TC=$('tc'),VC=$('vc'),BC=$('bc'),NB=$('n'),MB=$('m'),DS=$('ds'),
 VS=$('vs');
const API='http://127.0.0.1:8765';
$('cap').textContent=L.cap;$('tl').textContent=L.bt;$('vl').textContent=L.vp;
$('dl').textContent=L.dm;$('bl').textContent=L.bl;VS.textContent=L.vs;
MB.textContent=L.meas;
let hunting=false,dkey='',noTor=false,lastS=null,progAt=0,
 live='–',huntBest={v:0,n:''},liveProbe={v:0,n:''},
 shownV=0,anim=0,lastGen=-1;
// While a hunt runs, the big number behaves like a speedometer needle:
// a faster probe pushes it up instantly, then it glides back down to
// the true mean – the settled value is the one that gets pinned.
const truth=()=>Math.max(huntBest.v,liveProbe.v);
const truthName=()=>liveProbe.v>huntBest.v?liveProbe.n:huntBest.n;
const renderBig=()=>{
 if(!hunting){if(anim)cancelAnimationFrame(anim);anim=0;shownV=0;
  S.classList.remove('hunt');SV.textContent=live;
  $('cap').textContent=L.cap;LV.style.display='none';return;}
 S.classList.add('hunt');
 SV.textContent=shownV?shownV.toFixed(1):'–';
 $('cap').textContent=shownV?L.fast+truthName():L.search;
 LV.textContent=L.live+live+' Mbit/s';LV.style.display='';};
const settle=()=>{anim=0;
 const t=truth();
 if(Math.abs(shownV-t)<=0.05){shownV=t;renderBig();return;}
 shownV+=(t-shownV)*0.15;renderBig();
 anim=requestAnimationFrame(settle);};
const push=()=>{
 const t=truth();
 if(t>shownV+0.04){shownV=t;pulse();}
 renderBig();
 if(!anim)anim=requestAnimationFrame(settle);};
const post=p=>fetch(API+'/api/'+p,{method:'POST'}).then(()=>poll())
 .catch(()=>{T.textContent=L.off});
H.onclick=()=>post(hunting?'stop':'hunt');
NB.onclick=()=>post(hunting?'abort':'unpin');
MB.onclick=()=>post('measure');
DS.onchange=()=>post('daemon?addr='+encodeURIComponent(DS.value));
VS.onclick=()=>post('compare');
VC.onchange=()=>fetch(API+'/api/proxy?on='+(VC.checked?1:0),{method:'POST'})
 .then(r=>r.json()).then(d=>{VC.checked=d.proxy})
 .catch(()=>{T.textContent=L.err;VC.checked=!VC.checked});
BC.onchange=()=>fetch(API+'/api/boost?on='+(BC.checked?1:0),{method:'POST'})
 .then(r=>r.json()).then(d=>{BC.checked=d.boost_auto})
 .catch(()=>{T.textContent=L.err;BC.checked=!BC.checked});
// Browser routing lives in bg.js – the popup only sends messages.
const msg=(o,cb)=>{try{chrome.runtime.sendMessage(o,r=>{
 if(!chrome.runtime.lastError&&r)cb(r);});}catch(e){}};
const applyProxy=r=>{
 // ignore replies older than the newest intent change (stale sync races)
 if(r.gen!=null){if(r.gen<lastGen)return;lastGen=r.gen;}
 noTor=!!r.noTor;TC.checked=!!r.on;
 if(r.error)T.textContent=L.other;else renderStat();};
TC.onchange=()=>msg({proxy:TC.checked},applyProxy);
function renderStat(){
 let t;
 if(TC.checked&&noTor)t=L.nt;
 else if(lastS&&lastS.pinned_exit)
  t=L.pin+(lastS.pinned_name||lastS.pinned_exit.slice(0,12)+'…');
 else t=L.rand;
 if(hunting)t=L.run+' '+t;
 T.textContent=t;}
const fmtRes=s=>{
 const bN=(s.best_at||0)>=(s.last_at||0);
 const v=bN?s.best_mbps:s.last_mbps,t=bN?s.best_at:s.last_at;
 const parts=[];
 if(v){let x='Tor '+v.toFixed(1);
  if(t){const m=Math.max(0,Math.round((Date.now()/1000-t)/60));
   x+=de?' (vor '+m+' Min)':' ('+m+' min ago)';}
  parts.push(x);}
 if(s.direct_mbps>0)parts.push(L.dir+' '+Math.round(s.direct_mbps)+' Mbit/s');
 return parts.length?parts.join(' · '):'–';};
function poll(){fetch(API+'/api/status').then(r=>r.json()).then(s=>{
 lastS=s;
 const dl=s.daemons||[],key=dl.map(x=>x.addr+(x.ready?1:0)).join();
 if(key!==dkey){dkey=key;DS.innerHTML='';
  dl.forEach(x=>{const o=document.createElement('option');
   o.value=x.addr;o.textContent=x.name+(x.ready?'':L.nr);DS.appendChild(o)});}
 dl.forEach(x=>{if(s.daemon&&s.daemon.indexOf(x.addr)>=0)DS.value=x.addr});
 VC.checked=!!s.proxy;
 BC.checked=!!s.boost_auto;
 hunting=!!s.hunting;
 // boost status in #p, but never over an active probe line
 if(Date.now()-progAt>2000)
  Q.textContent=(s.boost&&!hunting)?
   'Boost: '+(s.boost_probes||0)+(de?' Tests':' probes')+' · '+
   (s.boost_switches||0)+' '+
   (de?'Wechsel':((s.boost_switches||0)==1?'switch':'switches')):'';
 huntBest={v:s.hunt_best_mbps||0,n:s.hunt_best_name||''};
 if(!hunting)liveProbe={v:0,n:''};
 renderBig();
 H.textContent=hunting?L.stop:L.hunt;
 H.className=hunting?'sec':'';
 NB.textContent=hunting?L.cancel:L.unpin;
 MB.disabled=hunting;
 R.textContent=fmtRes(s);
 $('eip').textContent=s.exit_ip?L.eip+s.exit_ip+
  (s.exit_name?' ('+s.exit_name+')':''):'';
 renderStat();}).catch(()=>{T.textContent=L.off;R.textContent='–'});}
const bws=[];
const pulse=()=>{S.classList.remove('pulse');void S.offsetWidth;
 S.classList.add('pulse');};
// "best" = leading candidate's mean; "prog" = the running probe's rate.
// Both feed the badge via the background worker so it stays current.
try{const es=new EventSource(API+'/events');
es.onmessage=e=>{const d=JSON.parse(e.data);
 if(d.type=='bw'){bws.push(d.down);if(bws.length>3)bws.shift();
  live=(bws.reduce((a,b)=>a+b,0)/bws.length*8/1e6).toFixed(1);renderBig();}
 if(d.type=='best'){huntBest={v:d.v,n:d.name};push();
  msg({badge:d.v});}
 if(d.type=='prog'){liveProbe={v:d.v,n:d.name};progAt=Date.now();
  Q.textContent=L.probe+(d.name?d.name+': ':'')+d.v.toFixed(1)+' Mbit/s';
  push();if(d.v>huntBest.v)msg({badge:d.v});}
 if(d.type=='mbps'){Q.textContent='';poll();msg({badge:d.v});}
 // last log line only; poll() never touches #lg
 if(d.type=='log'){LG.textContent=d.msg.slice(0,120);poll();}};
es.onerror=()=>{};}catch(e){}
poll();msg({sync:1},applyProxy);setInterval(poll,5000);
