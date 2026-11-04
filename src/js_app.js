/* ============================================================
   APP CONTROLLER
   ============================================================ */
let VENDOR_MAP=null;   // oui6 -> name
let MODEL=null, R=null;

/* ---- vendor DB decode (gzip base64 embedded) ---- */
let VENDOR_CAT=null; // oui6 -> category ('n'|'o'|'v'|'')
async function loadVendors(){
  if(VENDOR_MAP) return VENDOR_MAP;
  const bin=Uint8Array.from(atob(OUI_B64),c=>c.charCodeAt(0));
  const ds=new DecompressionStream('gzip');
  const buf=await new Response(new Blob([bin]).stream().pipeThrough(ds)).arrayBuffer();
  const text=new TextDecoder().decode(buf);
  const z=text.indexOf('\x00');
  const names=text.slice(0,z).split('\n');  // each "name\x1fcat"
  const rows=text.slice(z+1).split(',');
  VENDOR_MAP={}; VENDOR_CAT={};
  for(const r of rows){ const c=r.indexOf(':'); const entry=names[parseInt(r.slice(c+1),16)];
    const sep=entry.indexOf('\x1f'); const oui=r.slice(0,c);
    VENDOR_MAP[oui]=sep>=0?entry.slice(0,sep):entry;
    VENDOR_CAT[oui]=sep>=0?entry.slice(sep+1):''; }
  return VENDOR_MAP;
}
function vendorLookup(mac){
  if(!mac||!VENDOR_MAP) return null;
  const b1=parseInt(mac.slice(0,2),16);
  if(b1&0x02) return null; // locally administered / random MAC
  return VENDOR_MAP[mac.replace(/:/g,'').slice(0,6).toUpperCase()]||null;
}
function vendorCategory(mac){
  if(!mac||!VENDOR_CAT) return '';
  const b1=parseInt(mac.slice(0,2),16); if(b1&0x02) return '';
  return VENDOR_CAT[mac.replace(/:/g,'').slice(0,6).toUpperCase()]||'';
}

/* ---- UI refs ---- */
const $=s=>document.querySelector(s);
const dropEl=$('#drop'), prog=$('#progress'), progBar=$('#prog-bar'), progLbl=$('#prog-lbl');
const asideBody=$('#aside-body'), aside=$('#aside');
let curTab='overview';

function setProg(p,label){ prog.classList.add('on'); progBar.style.width=Math.round(p*100)+'%'; if(label)progLbl.textContent=label; }
function hideProg(){ prog.classList.remove('on'); }

/* ---- file handling ---- */
async function handleFile(file){
  // session file? (.cscope.json) — reopen a saved view instead of parsing a pcap
  if(/\.cscope\.json$/i.test(file.name)||/\.cscope$/i.test(file.name)){ return loadSession(file); }
  dropEl.style.display='none';
  setProg(0.01,'reading '+file.name+' …');
  await loadVendors();
  try{
    const builder=ModelBuilder();
    let lastPaint=0;
    const stats=await parseCaptureStreaming(file,(dv,base,caplen,wirelen,ts,link)=>{
      const r=dissect(dv,base,caplen,wirelen,ts,link);
      builder.add(dv,r);
    },p=>{ setProg(p*0.8,'parsing '+file.name+' — '+Math.round(p*100)+'%'); });
    if(!stats.packets) throw new Error('No packets found in file.');
    setProg(0.84,'reconstructing topology ('+stats.packets.toLocaleString()+' packets) …');
    await new Promise(r=>setTimeout(r,10));
    MODEL=builder.finalize(vendorLookup,vendorCategory);
    MODEL.format=stats.format; MODEL.link=stats.link; MODEL.fileName=file.name; MODEL.fileSize=file.size;
    setProg(0.9,'laying out '+MODEL.nodeCount+' hosts …');
    await new Promise(r=>setTimeout(r,10));
    layout(MODEL,{w:1600,h:1000,iters:MODEL.nodeCount>600?140:MODEL.nodeCount>200?200:260});
    setProg(0.99,'rendering …');
    R=Renderer($('#graph'),MODEL,host);
    window._R=R; window._MODEL=MODEL;
    buildLegend(); switchTab('overview');
    enableExports(true); updateHeaderStat(); hideProg();
  }catch(e){
    hideProg(); dropEl.style.display='flex';
    dropEl.querySelector('.card').innerHTML='<div class="big mono" style="color:var(--bad)">couldn\'t read that file</div>'+
      '<div class="sub">'+esc(e.message)+'</div><button class="primary" id="btn-choose2">Try another file</button>';
    $('#btn-choose2').onclick=()=>$('#filein').click();
    console.error(e);
  }
}
function enableExports(on){ ['#btn-png','#btn-pdf','#btn-save'].forEach(s=>{const b=$(s);if(b)b.disabled=!on;}); }

function updateHeaderStat(){
  const m=MODEL; const dur=m.tmax-m.tmin;
  $('#hdrstat').innerHTML=
    `<span><b>${m.nodeCount}</b> hosts</span>`+
    `<span><b>${m.edgeArr.length}</b> links</span>`+
    `<span><b>${m.total.toLocaleString()}</b> pkts</span>`+
    (dur>0?`<span><b>${fmtDur(dur)}</b></span>`:'');
}

/* ---- host callbacks for renderer ---- */
const host={
  showTip(n,x,y){ showNodeTip(n,x,y); },
  hideTip(){ $('#tip').classList.remove('show'); },
  onSelect(n){ if(n){ switchTab('detail'); renderDetail(n); } else if(curTab==='detail'){ switchTab('overview'); } },
  onMultiSelect(ids){ updateMultiBar(ids); }
};
function updateMultiBar(ids){
  const bar=$('#multibar'); if(!bar)return;
  if(ids.length<2){ bar.style.display='none'; return; }
  bar.style.display='flex';
  $('#multi-count').textContent=ids.length+' selected';
}

/* ---- tooltip ---- */
function showNodeTip(n,x,y){
  const tip=$('#tip'); const fam=FAMILY[n.fam]||FAMILY.other;
  const topProtos=Object.entries(n.protos).sort((a,b)=>b[1]-a[1]).slice(0,4).map(p=>p[0]).join(', ');
  tip.innerHTML=
    `<div class="tt-title"><span style="width:9px;height:9px;border-radius:2px;background:${fam.color};display:inline-block"></span>${esc(n.label)}</div>`+
    `<div class="tt-row"><span class="k">role</span><span class="v">${KIND_LABEL[n.kind]||'host'}</span></div>`+
    (n.vendor?`<div class="tt-row"><span class="k">vendor</span><span class="v">${esc(n.vendor)}</span></div>`:'')+
    (n.primaryIp?`<div class="tt-row"><span class="k">ip</span><span class="v">${esc(n.primaryIp)}</span></div>`:'')+
    (n.macs.size?`<div class="tt-row"><span class="k">mac</span><span class="v">${esc([...n.macs][0])}</span></div>`:'')+
    `<div class="tt-row"><span class="k">talks to</span><span class="v">${n.deg} host${n.deg!==1?'s':''}</span></div>`+
    `<div class="tt-row"><span class="k">protocols</span><span class="v">${esc(topProtos||'—')}</span></div>`+
    (n.deg>12?`<div class="tt-expl">Hub with many links — click the <b>+</b> badge to show all peers.</div>`:'')+
    `<div class="tt-expl">${n.rx+n.tx} packets · ${fmtBytes(n.bytes)}. Click to inspect.</div>`;
  tip.classList.add('show');
  const tw=tip.offsetWidth,th=tip.offsetHeight;
  let px=x+14,py=y+14; if(px+tw>innerWidth)px=x-tw-14; if(py+th>innerHeight)py=y-th-14;
  tip.style.left=px+'px'; tip.style.top=py+'px';
}
/* edge/proto tooltip when hovering legend handled separately */

/* ---- panel tabs ---- */
document.querySelectorAll('.aside-tabs button').forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
function switchTab(t){ curTab=t; document.querySelectorAll('.aside-tabs button').forEach(b=>b.classList.toggle('on',b.dataset.tab===t)); renderTab(t); }
function renderTab(t){ if(!MODEL){asideBody.innerHTML='<div class="empty">Load a capture to begin.</div>';return;}
  if(t==='overview')renderOverview(); else if(t==='protocols')renderProtocols();
  else if(t==='assets')renderAssets();
  else if(t==='alerts')renderAlerts(); else if(t==='detail'){ if(!R||!R._model)return; asideBody.innerHTML='<div class="empty">Click a host in the graph to inspect it.</div>'; } }

let assetFilter={role:'',subnet:'',q:''};
function renderAssets(){
  const m=MODEL;
  const roles=[...new Set(m.nodeArr.map(n=>n.kind))];
  const subnets=[...new Set(m.nodeArr.map(n=>n.subnet))].filter(Boolean);
  let rows=m.nodeArr.slice().sort((a,b)=>b.deg-a.deg);
  if(assetFilter.role) rows=rows.filter(n=>n.kind===assetFilter.role);
  if(assetFilter.subnet) rows=rows.filter(n=>n.subnet===assetFilter.subnet);
  if(assetFilter.q){ const q=assetFilter.q.toLowerCase();
    rows=rows.filter(n=>(n.label+' '+[...n.ips].join(' ')+' '+[...n.macs].join(' ')+' '+(n.vendor||'')).toLowerCase().includes(q)); }
  let html=`<div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
    <select id="af-role" style="flex:1;min-width:92px;background:var(--panel2);border:1px solid var(--line2);border-radius:6px;color:var(--ink);font-size:12px;padding:5px"><option value="">All roles</option>${roles.map(r=>`<option value="${r}"${assetFilter.role===r?' selected':''}>${KIND_LABEL[r]||r}</option>`).join('')}</select>
    <select id="af-subnet" style="flex:1;min-width:92px;background:var(--panel2);border:1px solid var(--line2);border-radius:6px;color:var(--ink);font-size:12px;padding:5px"><option value="">All subnets</option>${subnets.map(s=>`<option value="${esc(s)}"${assetFilter.subnet===s?' selected':''}>${esc(s)}</option>`).join('')}</select>
    <button id="af-csv" title="Export this inventory as CSV">CSV</button></div>
    <div style="font-size:11px;color:var(--ink3);margin-bottom:8px">${rows.length} of ${m.nodeCount} assets</div>`;
  html+='<div class="asset-list">';
  rows.forEach(n=>{ const fam=FAMILY[n.fam]||FAMILY.other;
    const ports=[...n.servesPorts].filter(p=>PORTS[p]).slice(0,5).map(p=>PORTS[p].name).join(', ');
    const vers=Object.keys(n.versions||{});
    const insecure=vers.some(v=>n.versions[v]===false);
    html+=`<div class="asset-row" data-id="${n.id}">
      <div class="ar-top"><span class="ar-ic" style="border-color:${fam.color}"></span>
        <span class="ar-name">${esc(n.label)}</span>
        <span class="ar-role" style="color:${fam.color}">${KIND_LABEL[n.kind]||n.kind}${n.roleConf==='low'?' ?':''}</span></div>
      <div class="ar-meta">
        ${n.vendor?`<span>🏷 ${esc(n.vendor)}</span>`:''}
        ${n.primaryIp?`<span class="mono">${esc(n.primaryIp)}</span>`:''}
        ${[...n.macs][0]?`<span class="mono" style="color:var(--ink3)">${esc([...n.macs][0])}</span>`:''}
        <span>${n.deg} peers</span>
        ${ports?`<span style="color:var(--ink3)">serves ${esc(ports)}</span>`:''}
        ${n.announce&&n.announce.model?`<span style="color:var(--accent)">📢 ${esc(n.announce.model)}</span>`:(n.announce&&n.announce.sysName?`<span style="color:var(--accent)">📢 ${esc(n.announce.sysName)}</span>`:'')}
        ${n.announce&&n.announce.portId?`<span style="color:var(--ink3)">port ${esc(n.announce.portId)}</span>`:''}
        ${insecure?`<span style="color:var(--warn)">⚠ plaintext</span>`:''}
      </div></div>`; });
  html+='</div>';
  asideBody.innerHTML=html;
  $('#af-role').onchange=e=>{assetFilter.role=e.target.value;renderAssets();};
  $('#af-subnet').onchange=e=>{assetFilter.subnet=e.target.value;renderAssets();};
  $('#af-csv').onclick=()=>exportAssetsCSV(rows);
  asideBody.querySelectorAll('.asset-row').forEach(r=>r.onclick=()=>R.selectById(r.dataset.id));
}
function exportAssetsCSV(rows){
  const cols=['label','role','role_confidence','role_reason','vendor','ips','macs','subnet','class','peers','packets_tx','packets_rx','bytes','serves_ports','client_ports','protocols','versions','announced_name','announced_model','announced_port','announced_mgmt_ip','announced_desc','physical_neighbors'];
  const esc2=v=>{ v=String(v==null?'':v); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; };
  let csv=cols.join(',')+'\n';
  rows.forEach(n=>{
    const line=[n.label,KIND_LABEL[n.kind]||n.kind,n.roleConf||'',n.roleWhy||'',n.vendor||'',
      [...n.ips].join(' '),[...n.macs].join(' '),n.subnet||'',n.class||'',n.deg,n.tx,n.rx,n.bytes,
      [...n.servesPorts].filter(p=>PORTS[p]).map(p=>PORTS[p].name+'/'+p).join(' '),
      [...n.clientPorts].filter(p=>PORTS[p]).map(p=>PORTS[p].name+'/'+p).join(' '),
      Object.keys(n.protos).join(' '),Object.keys(n.versions||{}).join(' '),
      (n.announce&&n.announce.sysName)||'',(n.announce&&n.announce.model)||'',(n.announce&&n.announce.portId)||'',
      (n.announce&&n.announce.mgmtIp)||'',(n.announce&&n.announce.sysDesc)||'',
      (MODEL.physical||[]).filter(p=>p.a===n||p.b===n).map(p=>(p.a===n?p.b:p.a).label).join(' ')];
    csv+=line.map(esc2).join(',')+'\n';
  });
  dl(new Blob([csv],{type:'text/csv'}),(MODEL.fileName||'capture').replace(/\.[^.]+$/,'')+'-assets.csv');
}

function renderOverview(){
  const m=MODEL; const dur=m.tmax-m.tmin;
  // device type tally
  const kinds={}; m.nodeArr.forEach(n=>kinds[n.kind]=(kinds[n.kind]||0)+1);
  const vendors={}; m.nodeArr.forEach(n=>{if(n.vendor)vendors[n.vendor]=(vendors[n.vendor]||0)+1;});
  const topVend=Object.entries(vendors).sort((a,b)=>b[1]-a[1]).slice(0,6);
  const high=m.findings.filter(f=>f.sev==='high').length, med=m.findings.filter(f=>f.sev==='med').length;
  asideBody.innerHTML=
    `<div class="sumgrid">
      <div class="cell"><div class="n">${m.nodeCount}</div><div class="l">hosts</div></div>
      <div class="cell"><div class="n">${m.edgeArr.length}</div><div class="l">conversations</div></div>
      <div class="cell"><div class="n">${Object.keys(m.protoCount).length}</div><div class="l">protocols</div></div>
      <div class="cell"><div class="n" style="color:${high?'var(--bad)':med?'var(--warn)':'var(--good)'}">${m.findings.length}</div><div class="l">findings</div></div>
    </div>`+
    `<h3>Capture</h3><dl class="kv">
      <dt>file</dt><dd>${esc(m.fileName)}</dd>
      <dt>format</dt><dd>${m.format} · ${m.link}</dd>
      <dt>packets</dt><dd>${m.total.toLocaleString()}</dd>
      ${dur>0?`<dt>duration</dt><dd>${fmtDur(dur)}</dd>`:''}
      ${m.badCount?`<dt>malformed</dt><dd style="color:var(--warn)">${m.badCount}</dd>`:''}
    </dl>`+
    `<h3>Device types seen</h3><div class="pills">`+
      Object.entries(kinds).sort((a,b)=>b[1]-a[1]).map(([k,c])=>
        `<span class="pill"><span class="dot" style="background:var(--ink3)"></span>${KIND_LABEL[k]||k} ·&nbsp;${c}</span>`).join('')+
    `</div>`+
    (topVend.length?`<h3>Top vendors</h3><dl class="kv">`+topVend.map(([v,c])=>`<dt>${esc(v)}</dt><dd>${c}</dd>`).join('')+`</dl>`:'')+
    (m.controlEvents.length?`<h3>Control activity</h3><div class="alert sev-high"><div class="hd">⚠ ${m.controlEvents.length} OT write/command action${m.controlEvents.length!==1?'s':''}</div><div class="desc">Device-changing operations were seen (writes, stops, resets). See <a class="lnk" onclick="switchTab('alerts')">Findings</a>.</div></div>`:'');
}

function renderProtocols(){
  const m=MODEL;
  const items=Object.entries(m.protoCount).sort((a,b)=>b[1]-a[1]);
  // group by family
  const byFam={}; items.forEach(([nm,c])=>{ const f=(PORTS_BYNAME[nm]||{}).fam||famOf(nm); (byFam[f]=byFam[f]||[]).push([nm,c]); });
  let html='<h3>Protocols by family <span style="color:var(--ink3);font-weight:400;text-transform:none;letter-spacing:0">· click to toggle</span></h3>';
  const order=['ot','ot_info','mgmt','web','transfer','name','infra','other'];
  order.forEach(f=>{ if(!byFam[f])return; const fam=FAMILY[f];
    html+=`<div style="margin:12px 0 4px;font-size:11px;color:${fam.color};font-weight:600">${fam.name.toUpperCase()}</div>`;
    byFam[f].forEach(([nm,c])=>{ const off=R&&R.hiddenFams.has(f);
      const why=(PORTS_BYNAME[nm]||{}).why||'';
      html+=`<div class="proto-row ${off?'off':''}" data-fam="${f}" title="${esc(why)}">
        <span class="sw" style="background:${fam.color}"></span>
        <span class="nm">${esc(nm)}</span><span class="ct">${c.toLocaleString()}</span></div>`; });
  });
  asideBody.innerHTML=html;
  asideBody.querySelectorAll('.proto-row').forEach(row=>row.onclick=()=>{ R.toggleFam(row.dataset.fam); renderProtocols(); buildLegend(); });
}

function renderAlerts(){
  const m=MODEL;
  if(!m.findings.length){ asideBody.innerHTML='<div class="empty">No anomalies flagged.<br>The capture looks ordinary — but always verify manually.</div>'; return; }
  let html='<h3>Findings <span style="color:var(--ink3);font-weight:400;text-transform:none;letter-spacing:0">· initial signals, verify manually</span></h3>';
  m.findings.forEach(f=>{
    html+=`<div class="alert sev-${f.sev==='high'?'high':f.sev==='med'?'med':'low'}">
      <div class="hd"><span class="sev">${f.sev.toUpperCase()}</span>${esc(f.title)}</div>
      <div class="desc">${esc(f.desc)}</div>
      ${f.ref?`<div class="ref" data-ref="${esc(f.ref)}">↪ ${esc(f.ref)}</div>`:''}</div>`;
  });
  asideBody.innerHTML=html;
  asideBody.querySelectorAll('.ref').forEach(r=>r.onclick=()=>{ const id=r.dataset.ref.split(' | ')[0].trim();
    const nid = MODEL.nodes[id]?id : MODEL.nodes['ip:'+id]?'ip:'+id : MODEL.nodes['mac:'+id]?'mac:'+id : null;
    if(nid) R.selectById(nid); });
}

function renderDetail(n){
  const fam=FAMILY[n.fam]||FAMILY.other;
  const peers=MODEL.edgeArr.filter(e=>e.a===n||e.b===n).sort((a,b)=>b.count-a.count);
  const protos=Object.entries(n.protos).sort((a,b)=>b[1]-a[1]);
  let html=`<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
     <div class="nl-ic" style="width:34px;height:34px;border:1.5px solid ${fam.color};background:var(--panel2)"></div>
     <div><div style="font-family:var(--fontmono);font-size:15px">${esc(n.label)}</div>
     <div style="font-size:12px;color:var(--ink3)">${KIND_LABEL[n.kind]||'host'}</div></div>
     <div style="flex:1"></div><button onclick="R.clearSel()" title="Clear focus" style="padding:4px 9px">✕ clear</button></div>`;
  // special address note (broadcast / multicast / link-local)
  if(n.special) html+=`<div class="alert sev-low" style="border-left-color:${fam.color}"><div class="desc">${esc(n.special.note)}</div></div>`;
  // role reasoning + confidence
  if(n.roleWhy){ const conf=n.roleConf||'medium'; const cc=conf==='high'?'var(--good)':conf==='low'?'var(--bad)':'var(--warn)';
    html+=`<div class="alert sev-low" style="border-left-color:var(--accent)"><div class="hd" style="font-size:12px">Why "${KIND_LABEL[n.kind]||n.kind}"? <span class="pill" style="border-color:${cc};color:${cc};margin-left:auto">${conf} confidence</span></div><div class="desc">${esc(n.roleWhy)}</div></div>`; }
  html+=`<dl class="kv">`+
    (n.hostname?`<dt>hostname</dt><dd>${esc(n.hostname)}</dd>`:'')+
    (n.primaryIp?`<dt>IP</dt><dd>${esc(n.primaryIp)}</dd>`:'')+
    ([...n.ips].filter(x=>x!==n.primaryIp&&x).slice(0,3).map(x=>`<dt>also</dt><dd>${esc(x)}</dd>`).join(''))+
    ([...n.macs].slice(0,2).map(x=>`<dt>MAC</dt><dd>${esc(x)}</dd>`).join(''))+
    (n.vendor?`<dt>vendor</dt><dd>${esc(n.vendor)}</dd>`:'')+
    `<dt>packets</dt><dd>${(n.rx+n.tx).toLocaleString()} (↑${n.tx} ↓${n.rx})</dd>`+
    `<dt>bytes</dt><dd>${fmtBytes(n.bytes)}</dd>`+
    `<dt>peers</dt><dd>${n.deg}</dd>`+
    (n.servesPorts&&n.servesPorts.size?`<dt>serves ports</dt><dd>${[...n.servesPorts].filter(p=>PORTS[p]).slice(0,6).join(', ')||'—'}</dd>`:'')+
    `</dl>`;
  html+=`<h3>Protocols</h3><div>`+protos.map(([nm,c])=>{ const f=(PORTS_BYNAME[nm]||{}).fam||famOf(nm);const fc=FAMILY[f]?FAMILY[f].color:'#667';
    const secInfo=PROTO_SECURITY[nm]; const secBadge=secInfo? (secInfo.secure===true?'<span class="pill" style="border-color:var(--good);color:var(--good)">secure</span>':secInfo.secure===false?'<span class="pill" style="border-color:var(--warn);color:var(--warn)">plaintext</span>':''):'';
    return `<div class="proto-row" title="${esc((PORTS_BYNAME[nm]||{}).why||'')}"><span class="sw" style="background:${fc}"></span><span class="nm">${esc(nm)}</span>${secBadge}<span class="ct">${c}</span></div>`;}).join('')+`</div>`;
  // device self-announcement from LLDP/CDP — enriches this same asset
  if(n.announce){ const a=n.announce;
    html+=`<h3>Announced via ${esc(a._via||'LLDP/CDP')}</h3><dl class="kv">`+
      (a.sysName?`<dt>name</dt><dd>${esc(a.sysName)}</dd>`:'')+
      (a.model?`<dt>model</dt><dd>${esc(a.model)}</dd>`:'')+
      (a.sysDesc?`<dt>description</dt><dd style="text-align:left">${esc(a.sysDesc.slice(0,120))}</dd>`:'')+
      (a.portId?`<dt>its port</dt><dd>${esc(a.portId)}</dd>`:'')+
      (a.portDesc?`<dt>port desc</dt><dd>${esc(a.portDesc)}</dd>`:'')+
      (a.mgmtIp?`<dt>mgmt IP</dt><dd>${esc(a.mgmtIp)}</dd>`:'')+
      (a.caps&&a.caps.length?`<dt>capabilities</dt><dd>${esc(a.caps.join(', '))}</dd>`:'')+
      (a.chassisId?`<dt>chassis</dt><dd>${esc(a.chassisId)}</dd>`:'')+
      `</dl>`;
  }
  // physical links discovered from LLDP/CDP
  const phys=(MODEL.physical||[]).filter(p=>p.a===n||p.b===n);
  if(phys.length){ html+=`<h3>Physically connected (cabling)</h3><div class="node-list">`;
    phys.forEach(p=>{ const o=p.a===n?p.b:p.a; const of=FAMILY[o.fam]||FAMILY.other;
      html+=`<div class="nl-row" data-id="${o.id}"><div class="nl-ic" style="border:1.5px solid ${of.color};background:var(--panel2)"></div>
        <div class="nl-main"><div class="nl-name">${esc(o.label)}</div><div class="nl-sub">via ${esc(p.via)}${p.ports.length?' · port '+esc(p.ports.join(', ')):''}</div></div></div>`; });
    html+=`</div>`; }
  // detected versions / security posture from the wire
  const vers=Object.keys(n.versions||{});
  if(vers.length){ html+=`<h3>Versions &amp; security seen</h3><div>`;
    vers.forEach(v=>{ const sec=n.versions[v]; const col=sec===true?'var(--good)':sec==='partial'?'var(--warn)':'var(--bad)';
      const lbl=sec===true?'secure':sec==='partial'?'partial':'insecure';
      html+=`<div class="proto-row"><span class="sw" style="background:${col}"></span><span class="nm" style="font-family:var(--fontmono);font-size:12px">${esc(v)}</span><span class="ct" style="color:${col}">${lbl}</span></div>`; });
    html+=`</div>`; }
  // decoded samples across this node's edges
  const samples=[]; peers.forEach(e=>e.samples&&e.samples.forEach(s=>{if(!samples.some(x=>x.txt===s.txt))samples.push(s);}));
  if(samples.length){ html+=`<h3>What it's doing</h3>`;
    samples.slice(0,8).forEach(s=>{ html+=`<div class="alert sev-low" style="border-left-color:${fam.color}"><div class="hd" style="font-family:var(--fontmono);font-size:12.5px">${esc(s.txt)}</div><div class="desc">${esc(s.expl)}</div></div>`; }); }
  html+=`<h3>Talks to (${peers.length})</h3><div class="node-list">`;
  peers.slice(0,40).forEach(e=>{ const o=e.a===n?e.b:e.a; const of=FAMILY[o.fam]||FAMILY.other;
    // port/transport detail: show each service port and direction relative to n
    let portInfo='';
    if(e.portList&&e.portList.length){ portInfo=e.portList.slice(0,4).map(p=>{
      const arrow = p.to===o.id? '→' : '←';  // n connects TO o, or o TO n
      return `${arrow}${p.tp.toUpperCase()}/${p.port}`; }).join(' '); }
    html+=`<div class="nl-row" data-id="${o.id}"><div class="nl-ic" style="border:1.5px solid ${of.color};background:var(--panel2)"></div>
      <div class="nl-main"><div class="nl-name">${esc(o.label)}</div>
        <div class="nl-sub">${esc(e.topProto)}${portInfo?' · '+esc(portInfo):''} · ${e.count} pkts</div></div>
      <div class="nl-deg">${o.deg}</div></div>`; });
  html+=`</div>`;
  asideBody.innerHTML=html;
  asideBody.querySelectorAll('.nl-row').forEach(r=>r.onclick=()=>R.selectById(r.dataset.id));
}

/* ---- legend ---- */
function buildLegend(){
  const used=new Set(); MODEL.edgeArr.forEach(e=>used.add(e.fam)); MODEL.nodeArr.forEach(n=>used.add(n.fam));
  const order=['ot','ot_info','mgmt','web','transfer','name','infra','other'];
  let html='<h4>Protocol family</h4>';
  order.forEach(f=>{ if(!used.has(f))return; const fam=FAMILY[f]; const off=R&&R.hiddenFams.has(f);
    html+=`<div class="lg ${off?'off':''}" data-fam="${f}"><span class="sw" style="background:${fam.color}"></span>${fam.name}</div>`; });
  $('#legend').innerHTML=html;
  $('#legend').querySelectorAll('.lg').forEach(l=>l.onclick=()=>{R.toggleFam(l.dataset.fam);buildLegend();if(curTab==='protocols')renderProtocols();});
}

/* ---- exports ---- */
$('#btn-png').onclick=()=>{ const el=$('#expmenu'); if(el&&el.style.display==='block')closeExpMenu(); else openExpMenu(); };
$('#btn-pdf').onclick=()=>exportPDF();
document.addEventListener('click',e=>{ if(!e.target.closest('#expmenu')&&e.target.id!=='btn-png')closeExpMenu(); });

function exportPNG(scalePick){
  // high-resolution export: pick a long edge in pixels
  const longEdge=scalePick||4096;
  const b=MODEL.bounds; const ar=((b.maxx-b.minx)||1)/((b.maxy-b.miny)||1);
  let W,H; if(ar>=1){ W=longEdge; H=Math.round(longEdge/ar); } else { H=longEdge; W=Math.round(longEdge*ar); }
  W=Math.min(W, 12000); H=Math.min(H, 12000);
  const titleH=Math.round(H*0.05);
  const cv=document.createElement('canvas'); cv.width=W;cv.height=H+titleH;
  const c=cv.getContext('2d'); c.imageSmoothingEnabled=true; c.imageSmoothingQuality='high';
  const bg=getComputedStyle(document.documentElement).getPropertyValue('--bg').trim();
  c.fillStyle=bg; c.fillRect(0,0,W,H+titleH);
  // title strip
  c.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--ink').trim();
  const ts=Math.round(titleH*0.42); c.font='bold '+ts+'px monospace'; c.textAlign='left'; c.textBaseline='middle';
  c.fillText('CaptureScope — '+(MODEL.fileName||'topology'),titleH*0.4,titleH*0.4);
  c.font=Math.round(titleH*0.26)+'px monospace'; c.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--ink3').trim();
  c.fillText(MODEL.nodeCount+' hosts · '+MODEL.edgeArr.length+' links · '+MODEL.total.toLocaleString()+' packets',titleH*0.4,titleH*0.75);
  c.save(); c.translate(0,titleH);
  R.renderToContext(c,W,H);
  c.restore();
  cv.toBlob(bl=>{ dl(bl,(MODEL.fileName||'capture').replace(/\.[^.]+$/,'')+'-topology-'+W+'px.png'); },'image/png');
  closeExpMenu();
}

function dl(blob,name){ const u=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=u;a.download=name;a.click(); setTimeout(()=>URL.revokeObjectURL(u),2000); }

/* ---- SVG export: true vector, infinite zoom, ideal for print ---- */
function exportSVG(){
  const m=MODEL; const b=m.bounds; const pad=60;
  const W=(b.maxx-b.minx)+pad*2, H=(b.maxy-b.miny)+pad*2;
  const ox=b.minx-pad, oy=b.miny-pad;
  const famCol=f=>(FAMILY[f]||FAMILY.other).color;
  const cssv=k=>getComputedStyle(document.documentElement).getPropertyValue(k).trim();
  const bg=cssv('--bg'),ink=cssv('--ink'),ink3=cssv('--ink3'),panel=cssv('--panel');
  const X=x=>(x-ox).toFixed(1), Y=y=>(y-oy).toFixed(1);
  const vis=new Set(); m.nodeArr.forEach(n=>vis.add(n.id)); // SVG shows all (no truncation)
  let s='<?xml version="1.0" encoding="UTF-8"?>\n';
  s+=`<svg xmlns="http://www.w3.org/2000/svg" width="${W.toFixed(0)}" height="${H.toFixed(0)}" viewBox="0 0 ${W.toFixed(0)} ${H.toFixed(0)}" font-family="monospace">\n`;
  s+=`<rect width="100%" height="100%" fill="${bg}"/>\n`;
  // edges
  m.edgeArr.forEach(e=>{ const col=famCol(e.fam); const w=Math.min(6,0.6+Math.log2(1+e.count)*0.7);
    s+=`<line x1="${X(e.a.x)}" y1="${Y(e.a.y)}" x2="${X(e.b.x)}" y2="${Y(e.b.y)}" stroke="${col}" stroke-width="${w.toFixed(1)}" stroke-opacity="0.7" stroke-linecap="round"/>\n`; });
  // port labels
  if(R.showPorts) m.edgeArr.forEach(e=>{ if(!e.portLabel)return; const mx=(e.a.x+e.b.x)/2,my=(e.a.y+e.b.y)/2;
    s+=`<text x="${X(mx)}" y="${Y(my)}" font-size="10" fill="${famCol(e.fam)}" text-anchor="middle" dominant-baseline="middle">${esc(e.portLabel)}</text>\n`; });
  // nodes
  m.nodeArr.forEach(n=>{ const R2=11*(0.8+Math.min(1.6,Math.log2(2+n.deg)*0.3)); const col=famCol(n.fam);
    s+=`<circle cx="${X(n.x)}" cy="${Y(n.y)}" r="${R2.toFixed(1)}" fill="${panel}" stroke="${col}" stroke-width="2.2"/>\n`;
    s+=`<text x="${X(n.x)}" y="${(Y(n.y)*1+R2+13).toFixed(1)}" font-size="12" fill="${ink}" text-anchor="middle">${esc(n.label)}</text>\n`;
    s+=`<text x="${X(n.x)}" y="${(Y(n.y)*1+R2+26).toFixed(1)}" font-size="10" fill="${ink3}" text-anchor="middle" font-family="sans-serif">${esc((KIND_LABEL[n.kind]||'host')+(n.vendor?' · '+n.vendor:''))}</text>\n`; });
  s+='</svg>\n';
  dl(new Blob([s],{type:'image/svg+xml'}),(m.fileName||'capture').replace(/\.[^.]+$/,'')+'-topology.svg');
  closeExpMenu();
}
function openExpMenu(){ const el=$('#expmenu'); if(!el)return;
  el.innerHTML=`<div class="exp-title">Export image</div>
    <button data-png="2048">PNG · 2048px</button>
    <button data-png="4096">PNG · 4096px (high)</button>
    <button data-png="8192">PNG · 8192px (max)</button>
    <button data-svg="1">SVG · vector (print)</button>`;
  el.style.display='block';
  el.querySelectorAll('button').forEach(btn=>btn.onclick=()=>{ if(btn.dataset.png)exportPNG(+btn.dataset.png); else exportSVG(); });
}
function closeExpMenu(){ const el=$('#expmenu'); if(el)el.style.display='none'; }

/* ---- session save / load ----
   Saves the computed topology (not the raw pcap) so it reopens instantly
   and can be shared. Sets, which don't JSON-serialise, are converted. */
function saveSession(){
  if(!MODEL) return;
  const m=MODEL;
  const nodes=m.nodeArr.map(n=>({id:n.id,label:n.label,x:n.x,y:n.y,kind:n.kind,fam:n.fam,
    deg:n.deg,rx:n.rx,tx:n.tx,bytes:n.bytes,vendor:n.vendor,vendorCat:n.vendorCat,hostname:n.hostname,primaryIp:n.primaryIp,
    subnet:n.subnet,class:n.class,roleWhy:n.roleWhy,roleConf:n.roleConf,special:n.special,pinned:n.pinned,
    announce:n.announce,
    ips:[...n.ips],macs:[...n.macs],protos:n.protos,versions:n.versions,
    servesPorts:[...n.servesPorts],clientPorts:[...n.clientPorts]}));
  const idx={}; m.nodeArr.forEach((n,i)=>idx[n.id]=i);
  const edges=m.edgeArr.map(e=>({a:idx[e.a.id],b:idx[e.b.id],count:e.count,bytes:e.bytes,
    fam:e.fam,topProto:e.topProto,portLabel:e.portLabel,portList:e.portList,protos:e.protos,samples:e.samples,versions:e.versions}));
  const session={__capturescope:1,version:SESSION_VERSION,savedAt:new Date().toISOString(),
    meta:{fileName:m.fileName,fileSize:m.fileSize,format:m.format,link:m.link,total:m.total,
      nodeCount:m.nodeCount,tmin:m.tmin,tmax:m.tmax,badCount:m.badCount,badKinds:m.badKinds},
    protoCount:m.protoCount,findings:m.findings,controlEvents:m.controlEvents,
    bounds:m.bounds,view:R?{x:R.view.x,y:R.view.y,s:R.view.s}:null,
    groupBy:R?R.groupBy:null,hiddenFams:R?[...R.hiddenFams]:[],
    physical:(m.physical||[]).map(p=>({a:idx[p.a.id],b:idx[p.b.id],via:p.via,ports:p.ports})),
    nodes,edges};
  dl(new Blob([JSON.stringify(session)],{type:'application/json'}),
     (m.fileName||'capture').replace(/\.[^.]+$/,'')+'.cscope.json');
}
async function loadSession(file){
  dropEl.style.display='none'; setProg(0.3,'loading session …');
  try{
    const s=JSON.parse(await file.text());
    if(!s.__capturescope) throw new Error('Not a CaptureScope session file.');
    await loadVendors();
    // rebuild a model-like object
    const nodes={}, nodeArr=s.nodes.map(d=>{ const n=Object.assign({},d);
      n.ips=new Set(d.ips); n.macs=new Set(d.macs); n.peers=new Set();
      n.servesPorts=new Set(d.servesPorts||[]); n.clientPorts=new Set(d.clientPorts||[]);
      n.distinctDstPorts=new Set(); nodes[n.id]=n; return n; });
    const edgeArr=s.edges.map(e=>{ const a=nodeArr[e.a],b=nodeArr[e.b];
      a.peers.add(b.id); b.peers.add(a.id);
      return {a,b,count:e.count,bytes:e.bytes,fam:e.fam,topProto:e.topProto,portLabel:e.portLabel,portList:e.portList,protos:e.protos,samples:e.samples||[],versions:e.versions||{}}; });
    const physical=(s.physical||[]).map(p=>({a:nodeArr[p.a],b:nodeArr[p.b],via:p.via,ports:p.ports||[]})).filter(p=>p.a&&p.b);
    MODEL={nodes,nodeArr,edgeArr,edges:edgeArr,physical,protoCount:s.protoCount,findings:s.findings||[],
      controlEvents:s.controlEvents||[],bounds:s.bounds,arpMap:{},unknownPorts:{},
      badCount:s.meta.badCount,badKinds:s.meta.badKinds||{},total:s.meta.total,
      nodeCount:s.meta.nodeCount,tmin:s.meta.tmin,tmax:s.meta.tmax,
      format:s.meta.format,link:s.meta.link,fileName:s.meta.fileName,fileSize:s.meta.fileSize};
    setProg(0.8,'rendering …');
    R=Renderer($('#graph'),MODEL,host);
    if(s.view){ R.view.x=s.view.x;R.view.y=s.view.y;R.view.s=s.view.s; }
    if(s.groupBy) R.setGroup(s.groupBy);
    (s.hiddenFams||[]).forEach(f=>R.hiddenFams.add(f));
    R.draw();
    buildLegend(); switchTab('overview'); enableExports(true); updateHeaderStat(); hideProg();
  }catch(e){ hideProg(); dropEl.style.display='flex';
    dropEl.querySelector('.card').innerHTML='<div class="big mono" style="color:var(--bad)">couldn\'t load session</div><div class="sub">'+esc(e.message)+'</div>';
    console.error(e); }
}
const SESSION_VERSION=1;

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function fmtBytes(b){ if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(1)+' KB'; if(b<1073741824)return (b/1048576).toFixed(1)+' MB'; return (b/1073741824).toFixed(2)+' GB'; }
function fmtDur(s){ if(s<1)return (s*1000).toFixed(0)+' ms'; if(s<60)return s.toFixed(1)+' s'; if(s<3600)return Math.floor(s/60)+'m '+Math.round(s%60)+'s'; return Math.floor(s/3600)+'h '+Math.round(s%3600/60)+'m'; }

/* ---- controls ---- */
$('#zin').onclick=()=>R&&R.zoomBy(1.3);
$('#zout').onclick=()=>R&&R.zoomBy(1/1.3);
$('#btn-fit').onclick=()=>R&&R.fit();
$('#btn-relayout').onclick=()=>R&&R.relayout();
$('#groupsel').onchange=e=>R&&R.setGroup(e.target.value);
$('#btn-deoverlap').onclick=()=>R&&R.deOverlap();
$('#btn-ports').onclick=()=>{ if(!R)return; const on=R.togglePorts(); $('#btn-ports').textContent='Ports: '+(on?'on':'off'); };
$('#btn-labels').onclick=()=>{ if(!R)return; const m=R.cycleLabels(); $('#btn-labels').textContent='Labels: '+(m==='always'?'all':m==='hubs'?'hubs':'off'); };
$('#btn-phys').onclick=()=>{ if(!R)return; const on=R.togglePhysical(); $('#btn-phys').textContent='Cabling: '+(on?'on':'off'); };
$('#multi-pin').onclick=()=>R&&R.pinSelected(true);
$('#multi-unpin').onclick=()=>R&&R.pinSelected(false);
$('#multi-clear').onclick=()=>R&&R.clearMulti();
$('#btn-save').onclick=()=>saveSession();
$('#search').oninput=e=>R&&R.setSearch(e.target.value.trim());
$('#btn-panel').onclick=()=>aside.classList.toggle('collapsed');
$('#btn-open').onclick=()=>$('#filein').click();
$('#btn-choose').onclick=()=>$('#filein').click();
$('#filein').onchange=e=>{ if(e.target.files[0]) handleFile(e.target.files[0]); };

// drag & drop
['dragenter','dragover'].forEach(ev=>document.addEventListener(ev,e=>{e.preventDefault();dropEl.style.display='flex';dropEl.classList.add('hot');}));
['dragleave','drop'].forEach(ev=>document.addEventListener(ev,e=>{e.preventDefault();if(ev==='dragleave'&&e.relatedTarget)return;dropEl.classList.remove('hot');if(ev!=='drop'&&MODEL)dropEl.style.display='none';}));
document.addEventListener('drop',e=>{e.preventDefault();dropEl.classList.remove('hot');const f=e.dataTransfer.files[0];if(f)handleFile(f);else if(MODEL)dropEl.style.display='none';});

renderTab('overview');
