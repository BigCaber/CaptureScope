/* ============================================================
   MODEL BUILDER  — streaming aggregation into a host graph
   Fed one packet at a time; keeps only per-node and per-edge
   aggregates plus a bounded decoded-sample set. Memory stays
   O(hosts + conversations), not O(packets), so 500 MB+ is fine.
   ============================================================ */

function isMulticastMac(m){ if(!m)return false; const f=parseInt(m.slice(0,2),16); return (f&1)===1; }
function isBroadcastMac(m){ return m==='ff:ff:ff:ff:ff:ff'; }
function isBroadcast(ip){ return ip==='255.255.255.255'||(ip&&ip.endsWith('.255')); }
function isMulticastIp(ip){ if(!ip)return false; if(ip.indexOf('.')>=0){const f=parseInt(ip.split('.')[0],10);return f>=224&&f<=239;} return ip.startsWith('ff'); }
function privClass(ip){
  if(!ip||ip.indexOf('.')<0){ if(ip&&ip.indexOf(':')>=0)return 'ip6'; return 'other'; }
  const o=ip.split('.').map(Number);
  if(o[0]===10) return 'priv'; if(o[0]===172&&o[1]>=16&&o[1]<=31) return 'priv';
  if(o[0]===192&&o[1]===168) return 'priv'; if(o[0]===169&&o[1]===254) return 'link';
  if(o[0]===127) return 'local'; return 'pub';
}
function subnet24(ip){ if(!ip||ip.indexOf('.')<0)return ip&&ip.indexOf(':')>=0?'IPv6':'other';
  const o=ip.split('.'); return o[0]+'.'+o[1]+'.'+o[2]+'.0/24'; }

/* A streaming model accumulator. Call .add(dv, record) per packet,
   then .finalize(vendorLookup) once. */
function ModelBuilder(){
  const nodes={}, edges={};
  const protoCount={}, unknownPorts={}, arpMap={};
  const controlEvents=[]; let badCount=0; const badKinds={};
  const dnsNames={}; let tmin=Infinity,tmax=-Infinity,total=0;
  const MAX_EDGES=60000, MAX_CONTROL=400;
  const physical={};  // "a~b" -> {a,b,via,ports:Set} discovered cabling

  function recordPhysical(aId,bId,via,port){
    if(aId===bId) return;
    const key=aId<bId?aId+'~'+bId:bId+'~'+aId;
    let p=physical[key]; if(!p){ p=physical[key]={aId,bId,via,ports:new Set()}; }
    if(port) p.ports.add(port);
  }

  function node(id){
    let n=nodes[id];
    if(!n) n=nodes[id]={id,label:id,macs:new Set(),ips:new Set(),vendor:null,
      peers:new Set(),rx:0,tx:0,bytes:0,protos:{},distinctDstPorts:new Set(),
      servesPorts:new Set(),clientPorts:new Set(),hostname:null,
      firstTs:Infinity,lastTs:-Infinity,versions:{}};
    return n;
  }
  function endpointId(ip,mac){
    if(ip&&!isBroadcast(ip)&&!isMulticastIp(ip)) return 'ip:'+ip;
    if(ip) return 'grp:'+ip;
    if(mac&&!isMulticastMac(mac)) return 'mac:'+mac;
    if(mac) return 'grp:'+mac;
    return null;
  }

  function add(dv,r){
    total++;
    if(r.ts){ if(r.ts<tmin)tmin=r.ts; if(r.ts>tmax)tmax=r.ts; }
    if(r.bad){ badCount++; badKinds[r.bad]=(badKinds[r.bad]||0)+1; }

    const cls=classify(dv,r);
    protoCount[cls.name]=(protoCount[cls.name]||0)+1;
    if(cls.unknownPort) unknownPorts[cls.unknownPort]=(unknownPorts[cls.unknownPort]||0)+1;

    let aid=endpointId(r.src,r.smac), bid=endpointId(r.dst,r.dmac);
    if(!aid&&r.smac) aid='mac:'+r.smac;
    if(!bid&&r.dmac) bid='mac:'+r.dmac;
    if(!aid||!bid) return;

    const A=node(aid), B=node(bid);
    if(r.src)A.ips.add(r.src); if(r.dst)B.ips.add(r.dst);
    if(r.smac)A.macs.add(r.smac); if(r.dmac)B.macs.add(r.dmac);
    A.tx++; B.rx++; A.bytes+=r.len; B.bytes+=r.len;
    A.peers.add(bid); B.peers.add(aid);
    A.protos[cls.name]=(A.protos[cls.name]||0)+1;
    B.protos[cls.name]=(B.protos[cls.name]||0)+1;
    if(r.ts){A.firstTs=Math.min(A.firstTs,r.ts);A.lastTs=Math.max(A.lastTs,r.ts);
             B.firstTs=Math.min(B.firstTs,r.ts);B.lastTs=Math.max(B.lastTs,r.ts);}
    if(r.dport){ A.distinctDstPorts.add(r.dport);
      if(PORTS[r.dport]&&(!PORTS[r.sport]||r.dport<=r.sport)){ B.servesPorts.add(r.dport); A.clientPorts.add(r.dport); }
      else if(PORTS[r.sport]&&(!PORTS[r.dport]||r.sport<r.dport)){ A.servesPorts.add(r.sport); B.clientPorts.add(r.sport); } }

    const ek=aid<bid?aid+'~'+bid:bid+'~'+aid;
    let e=edges[ek];
    if(!e){ if(Object.keys(edges).length>=MAX_EDGES){ /* cap edges in huge captures */ }
      else e=edges[ek]={a:A,b:B,count:0,bytes:0,protos:{},fams:{},samples:[],versions:{},dir:{}}; }
    if(e){ e.count++; e.bytes+=r.len;
      e.protos[cls.name]=(e.protos[cls.name]||0)+1;
      if(cls.fam)e.fams[cls.fam]=(e.fams[cls.fam]||0)+1;
      e.dir[aid]=(e.dir[aid]||0)+1;
      // record the service port + transport + direction for this conversation
      if((r.proto==='tcp'||r.proto==='udp')&&r.dport){
        const tp=r.proto; let svcPort,toId;
        if(PORTS[r.dport]&&(!PORTS[r.sport]||r.dport<=r.sport)){ svcPort=r.dport; toId=bid; }
        else if(PORTS[r.sport]&&(!PORTS[r.dport]||r.sport<r.dport)){ svcPort=r.sport; toId=aid; }
        else { svcPort=Math.min(r.sport,r.dport); toId=(r.dport<=r.sport)?bid:aid; }
        const pk=tp+'/'+svcPort;
        e.ports=e.ports||{}; if(!e.ports[pk]) e.ports[pk]={tp,port:svcPort,to:toId,count:0};
        e.ports[pk].count++;
      } }

    if(r.arp&&r.arp.op===2&&r.arp.sip&&r.arp.smac&&!isMulticastMac(r.arp.smac))
      (arpMap[r.arp.sip]=arpMap[r.arp.sip]||new Set()).add(r.arp.smac);

    // deep decode + version/security
    if(r.l2&&r.proto&&r.proto.indexOf('PROFINET')>=0&&r.l2off!==undefined){
      try{ const d=profinetL2(dv,r.l2off,r.l2end);
        if(d&&e&&e.samples.length<6&&!e.samples.some(s=>s.txt===d.txt)) e.samples.push(d);
        if(d&&d.write&&controlEvents.length<MAX_CONTROL) controlEvents.push({txt:d.txt,expl:d.expl.replace(' ⚠',''),src:A.label||aid,dst:B.label||bid}); }catch(_){}
    }
    // LLDP / CDP: device self-announcement -> fold into the SENDER's asset.
    if(r.l2&&r.l2.dec&&r.l2off!==undefined){
      try{
        let d=null;
        if(r.l2.dec==='lldp') d=decodeLLDP(dv,r.l2off,r.l2end);
        else if(r.l2.dec==='cdp') d=decodeCDP(dv,r.l2off,r.l2end);
        if(d&&d.announce){ A.announce=Object.assign(A.announce||{}, d.announce); A.announce._via=r.l2.name;
          if(e&&e.samples.length<6&&!e.samples.some(s=>s.txt===d.txt)) e.samples.push(d);
          // physical neighbour: the frame's DESTINATION (dmac) is the directly
          // wired neighbour that received this announcement. Record a physical link.
          if(r.dmac&&!isMulticastMac(r.dmac)){ recordPhysical(aid, 'mac:'+r.dmac, r.l2.name, d.announce.portId); }
          else if(d.announce.chassisMac){ recordPhysical(aid, 'mac:'+d.announce.chassisMac, r.l2.name, d.announce.portId); }
        }
      }catch(_){}
    }
    if(cls.dec&&DECODERS[cls.dec]&&r.payloadLen>0){
      try{
        const d=DECODERS[cls.dec](dv,r);
        if(d){
          if(d.txt&&e&&e.samples.length<6&&!e.samples.some(s=>s.txt===d.txt)) e.samples.push(d);
          if((d.write||/⚠/.test(d.expl))&&controlEvents.length<MAX_CONTROL)
            controlEvents.push({txt:d.txt,expl:d.expl.replace(' ⚠',''),src:r.src||aid,dst:r.dst||bid});
          if(d.sni)dnsNames[r.dst]=d.sni; if(d.host)dnsNames[r.dst]=d.host;
        }
      }catch(_){}
      // version/security
      const v=detectVersion(dv,r,cls.name);
      if(v){ A.versions[v.label]=v.secure; B.versions[v.label]=v.secure;
        if(e) e.versions[v.label]=v.secure; }
    }
  }

  function finalize(vendorLookup, vendorCategory){
    vendorCategory=vendorCategory||(()=>'');
    for(const id in nodes){
      const n=nodes[id];
      for(const m of n.macs){ if(!isMulticastMac(m)){ const v=vendorLookup(m); if(v){n.vendor=v;n.vendorCat=vendorCategory(m);break;} } }
      for(const ip of n.ips){ if(dnsNames[ip]){n.hostname=dnsNames[ip];break;} }
      // a device's own LLDP/CDP sysName is a strong hostname signal
      if(!n.hostname && n.announce && n.announce.sysName) n.hostname=n.announce.sysName;
      // announced mgmt IP counts as one of its IPs
      if(n.announce && n.announce.mgmtIp) n.ips.add(n.announce.mgmtIp);
      let ip=null; for(const x of n.ips){ if(x&&!isBroadcast(x)&&!isMulticastIp(x)){ip=x;break;} }
      n.primaryIp=ip;
      n.label=n.hostname||ip||[...n.macs][0]||id.replace(/^\w+:/,'');
      n.deg=n.peers.size;
      const roleInfo=assignRole(n);
      n.kind=roleInfo.kind; n.roleWhy=roleInfo.why; n.roleConf=roleInfo.conf||'medium';
      n.subnet=ip?subnet24(ip):(isMulticastIp(id.replace(/^\w+:/,''))?'multicast':'layer-2');
      n.class=ip?privClass(ip):(isMulticastIp(id.replace(/^\w+:/,''))?'mcast':isBroadcast(id.replace(/^\w+:/,''))?'bcast':'l2');
      n.special=nodeSpecial(n,id);
      let bf='other',bc=0; for(const pk in n.protos){const f=famOf(pk);if(n.protos[pk]>bc){bc=n.protos[pk];bf=f;}}
      n.fam=bf;
    }
    const nodeArr=Object.values(nodes);
    const edgeArr=Object.values(edges);
    edgeArr.forEach(e=>{ let bf='other',bc=0; for(const f in e.fams){if(e.fams[f]>bc){bc=e.fams[f];bf=f;}} e.fam=bf;
      let pn='',pc=0; for(const pk in e.protos){if(e.protos[pk]>pc){pc=e.protos[pk];pn=pk;}} e.topProto=pn;
      // top service port for the edge label (e.g. "TCP/502")
      if(e.ports){ let bp=null,bpc=0; for(const pk in e.ports){ if(e.ports[pk].count>bpc){bpc=e.ports[pk].count;bp=e.ports[pk];} }
        if(bp){ e.portLabel=bp.tp.toUpperCase()+'/'+bp.port; e.portList=Object.values(e.ports).sort((a,b)=>b.count-a.count); } } });

    // resolve physical links to node objects (only where both ends are known nodes)
    const physArr=[];
    for(const k in physical){ const pl=physical[k]; const a=nodes[pl.aId], b=nodes[pl.bId];
      if(a&&b&&a!==b){ physArr.push({a,b,via:pl.via,ports:[...pl.ports]}); } }
    const model={nodes,edgeArr,nodeArr,protoCount,unknownPorts,arpMap,controlEvents,
      badCount,badKinds,total,nodeCount:nodeArr.length,tmin:isFinite(tmin)?tmin:0,tmax:isFinite(tmax)?tmax:0,
      edges:edgeArr,physical:physArr};
    model.findings=detectAnomalies(model);
    return model;
  }
  return {add,finalize};
}

function famOf(pk){ const p=PORTS_BYNAME[pk]; if(p)return p.fam;
  if(/GOOSE|Sampled|PROFINET/.test(pk))return 'ot';
  if(/ARP|ICMP|IGMP|OSPF|VRRP|GRE|ESP|LLDP/.test(pk))return 'infra'; return 'other'; }

/* ---- explain broadcast/multicast/special addresses ---- */
function nodeSpecial(n,id){
  const raw=id.replace(/^\w+:/,'');
  if(isBroadcast(raw)) return {kind:'broadcast',note:'Broadcast address — traffic sent to every host on the local network (e.g. ARP who-has, DHCP discover). Not a single device.'};
  if(isMulticastIp(raw)) {
    const known={'224.0.0.1':'all hosts','224.0.0.2':'all routers','224.0.0.22':'IGMP','224.0.0.251':'mDNS','224.0.0.252':'LLMNR','239.255.255.250':'SSDP/UPnP','224.0.0.102':'HSRP/GLBP'};
    return {kind:'multicast',note:'Multicast group'+(known[raw]?' ('+known[raw]+')':'')+' — one sender, many subscribed receivers. Common for discovery and OT publish/subscribe (e.g. GOOSE, PROFINET). Not a single device.'};
  }
  if(/^mac:/.test(id)&&isMulticastMac(raw)) return {kind:'multicast',note:'Layer-2 multicast MAC — frames delivered to a group (e.g. IEC-61850 GOOSE/SV, PROFINET). Not a single device.'};
  if(n.class==='link') return {kind:'link-local',note:'Link-local / APIPA address (169.254.x.x) — self-assigned when no DHCP was available. Often indicates a misconfigured or unprovisioned device.'};
  return null;
}

/* ============================================================
   ROLE ASSIGNMENT  — explicit, explainable, scales to big nets
   Returns {kind, why}. "why" is shown in the detail panel so the
   operator can trust or override the call.
   ============================================================ */
const OT_SERVER_PORTS=[502,44818,20000,102,4840,3480,34964,34962,34963,2404,47808,5094,1217,11740,20547,48898,18245,18246,1324,4000,789,1962,9600,5007,1911];
function assignRole(n){
  const has=k=>n.protos[k];
  const hasFam=f=>{for(const pk in n.protos){if(famOf(pk)===f)return true;}return false;};
  const serves=p=>n.servesPorts.has(p);
  const servedOt=[...n.servesPorts].filter(p=>OT_SERVER_PORTS.includes(p));
  const speaksOt=hasFam('ot');
  const clientOt=[...n.clientPorts].filter(p=>OT_SERVER_PORTS.includes(p));
  const vcat=n.vendorCat||''; // 'n'=network infra, 'o'=OT vendor, 'v'=virtualization

  // --- strongest evidence first: actual protocol behaviour ---
  // device told us what it is via LLDP/CDP — strongest signal.
  if(n.announce){
    const a=n.announce; const c=a.caps||[];
    const desc=((a.sysDesc||'')+' '+(a.model||'')).toLowerCase();
    const via=a._via||'LLDP';
    // explicit capability flags first
    if(c.includes('Bridge/Switch')||c.includes('Switch')) return {kind:'switch',conf:'high',why:'Announced itself as a switch via '+via+(a.model?' (model '+a.model+')':'')+'.'};
    if(c.includes('Router')) return {kind:'router',conf:'high',why:'Announced itself as a router via '+via+(a.model?' (model '+a.model+')':'')+'.'};
    if(c.includes('WLAN AP')) return {kind:'router',conf:'high',why:'Announced itself as a wireless access point via '+via+'.'};
    if(c.includes('Phone')) return {kind:'workstation',conf:'high',why:'Announced itself as an IP phone via '+via+'.'};
    // fall back to keywords in the description/model string
    if(/\bswitch\b|catalyst|nexus|\bsw-|procurve|aruba\s*\d/.test(desc)) return {kind:'switch',conf:'high',why:'Its '+via+' description identifies a switch'+(a.model?' ('+a.model+')':'')+'.'};
    if(/\brouter\b|\bisr\b|\basr\b|mikrotik|routeros/.test(desc)) return {kind:'router',conf:'high',why:'Its '+via+' description identifies a router'+(a.model?' ('+a.model+')':'')+'.'};
    if(/firewall|palo alto|fortigate|\basa\b|checkpoint/.test(desc)) return {kind:'router',conf:'high',why:'Its '+via+' description identifies a firewall'+(a.model?' ('+a.model+')':'')+'.'};
    if(/camera|\bnvr\b|axis/.test(desc)) return {kind:'host',conf:'medium',why:'Its '+via+' description identifies a camera/NVR.'};
    if(c.includes('Station')||c.includes('Host')) return {kind:'workstation',conf:'medium',why:'Announced itself as an end station via '+via+'.'};
  }
  // IEC-61850 bay devices
  if(has('GOOSE')||has('Sampled Values'))
    return {kind:'ied',conf:'high',why:'Sends IEC-61850 '+(has('GOOSE')?'GOOSE':'Sampled Values')+' — a protection relay / merging unit (IED).'};
  // field controller: its OT control port was connected to
  if(servedOt.length){
    const pn=(PORTS[servedOt[0]]||{}).name||('port '+servedOt[0]);
    return {kind:'plc',conf:'high',why:'Answers control requests on '+pn+' from '+n.peers.size+' peer(s) — a field controller (PLC/RTU/DCS)'+(vcat==='o'?'; vendor ('+n.vendor+') is an industrial maker, consistent with this.':'.')};
  }
  // SCADA / engineering master
  if(speaksOt&&clientOt.length&&n.deg>=3)
    return {kind:'scada',conf:'high',why:'Initiates OT connections to '+n.deg+' devices on '+clientOt.map(p=>(PORTS[p]||{}).name||p).slice(0,3).join(', ')+' but serves none — a SCADA/engineering master.'};
  if(speaksOt&&clientOt.length)
    return {kind:'controller',conf:'medium',why:'Uses OT protocols ('+clientOt.map(p=>(PORTS[p]||{}).name||p).slice(0,2).join(', ')+') toward '+n.deg+' peer(s).'};
  if(speaksOt)
    return {kind:'controller',conf:'low',why:'Uses OT protocols; exact role unclear from traffic.'};

  // --- infrastructure: vendor + behaviour ---
  // A network-equipment vendor that talks management/discovery and fans out = switch/router
  if(vcat==='n'){
    if(serves(67)||has('DHCP-server')||serves(53)) return {kind:'router',conf:'high',why:n.vendor+' is a network-equipment maker and this host runs gateway services (DHCP/DNS) — a router/gateway.'};
    if(has('LLDP')||has('STP')||has('SNMP')||n.ips.size===0) return {kind:'switch',conf:'high',why:n.vendor+' is a network-equipment maker'+(has('LLDP')?' and the host sends LLDP topology frames':'')+' — a switch or managed infrastructure device.'};
    return {kind:'switch',conf:'medium',why:n.vendor+' is a network-equipment maker; most likely a switch/router. Role inferred from the hardware vendor, not from traffic — verify.'};
  }

  // --- IT roles by served ports (high conf: it actually answered) ---
  if(serves(53)||(has('DNS')&&n.tx>n.rx)) return {kind:'server',conf:'high',why:'Answers DNS queries — a name server.'};
  if(serves(67)||has('DHCP-server')) return {kind:'router',conf:'high',why:'Runs DHCP — a gateway/DHCP server.'};
  if(serves(80)||serves(443)||serves(8080)) return {kind:'server',conf:'high',why:'Serves HTTP/HTTPS — a web server or HMI.'};
  if(serves(445)||serves(139)||serves(2049)) return {kind:'server',conf:'high',why:'Serves file shares (SMB/NFS).'};
  if(serves(1433)||serves(3306)||serves(5432)) return {kind:'server',conf:'high',why:'Serves a database — likely a historian.'};
  if(serves(22)||serves(3389)||serves(5900)) return {kind:'server',conf:'high',why:'Accepts remote admin sessions (SSH/RDP/VNC).'};
  // client-side IT (lower conf — inferred from initiating)
  if(hasFam('mgmt')||has('HTTP')||has('HTTPS/TLS')) return {kind:'workstation',conf:'medium',why:'Initiates web/admin sessions — likely an operator workstation or client.'};
  if(n.class==='pub') return {kind:'cloud',conf:'medium',why:'A public-internet host this network talked to.'};
  if(n.class==='mcast') return {kind:'multicast',conf:'high',why:'A multicast group address, not a single device.'};
  if(n.class==='bcast') return {kind:'broadcast',conf:'high',why:'A broadcast address, not a single device.'};
  if(n.ips.size===0&&n.macs.size) return {kind:'l2dev',conf:'low',why:'Seen only at Layer-2 (no IP)'+(vcat==='n'?' from a network vendor':'')+' — a switch, bridge, or L2-only device.'};
  return {kind:'host',conf:'low',why:'Not enough protocol evidence to classify; generic host.'+(n.vendor?' Vendor: '+n.vendor+'.':'')};
}

/* ============================================================
   FORCE-DIRECTED LAYOUT  (unchanged core; leaf-tightening)
   ============================================================ */
function layout(model, opts={}){
  const nodes=model.nodeArr, edges=model.edgeArr;
  const n=nodes.length||1;
  const W=opts.w||1600, H=opts.h||1000;
  // base spacing scaled up so there's room for label boxes, and grows a
  // little with network size so big graphs don't cram.
  const k=Math.sqrt(W*H/n)*1.15 + 26;
  nodes.forEach((d,i)=>{ if(d.x===undefined){ const a=i*2.399963, rr=Math.sqrt(i/n)*Math.min(W,H)*0.46;
    d.x=W/2+rr*Math.cos(a); d.y=H/2+rr*Math.sin(a); d.vx=0;d.vy=0; } d.m=1+Math.log2(1+d.deg); });
  const iters=opts.iters||260; let temp=Math.min(W,H)*0.12; const cool=Math.pow(0.02,1/iters);
  for(let it=0;it<iters;it++){
    const cell=k, grid=new Map();
    nodes.forEach(d=>{ const key=Math.floor(d.x/cell)+','+Math.floor(d.y/cell);(grid.get(key)||grid.set(key,[]).get(key)).push(d);d.dx=0;d.dy=0; });
    nodes.forEach(d=>{ const cx=Math.floor(d.x/cell),cy=Math.floor(d.y/cell);
      for(let gx=cx-1;gx<=cx+1;gx++)for(let gy=cy-1;gy<=cy+1;gy++){ const b=grid.get(gx+','+gy); if(!b)continue;
        for(const o of b){ if(o===d)continue; let dx=d.x-o.x,dy=d.y-o.y,dist=Math.sqrt(dx*dx+dy*dy)||0.01;
          // hubs repel each other and everything else much more strongly, so
          // dense clusters spread out instead of piling labels in the centre.
          const hubBoost=1+Math.min(d.deg,o.deg)*0.08;
          if(dist<k*3.2){ const f=k*k/dist*hubBoost; d.dx+=dx/dist*f; d.dy+=dy/dist*f; } } } });
    edges.forEach(e=>{ const a=e.a,b=e.b; let dx=a.x-b.x,dy=a.y-b.y,dist=Math.sqrt(dx*dx+dy*dy)||0.01;
      const w=1+Math.log2(1+e.count);
      // a leaf hanging off a hub gets pushed OUT to a larger radius that grows
      // with the hub's degree, so 30 spokes fan onto a big ring with room for
      // their labels rather than crushing together near the hub.
      const hub=a.deg>=b.deg?a:b, leafn=a.deg>=b.deg?b:a;
      const isLeaf=leafn.deg<=2 && hub.deg>=6;
      const ideal=isLeaf ? k*(0.9+Math.min(hub.deg,40)*0.055) : k;
      const f=dist*dist/ideal/(2+Math.max(a.m,b.m)); const fx=dx/dist*f*w,fy=dy/dist*f*w;
      a.dx-=fx;a.dy-=fy;b.dx+=fx;b.dy+=fy; });
    // dedicated long-range repulsion between hubs (deg>=5) so cluster centres
    // push far apart and their label fields don't merge.
    const hubs=nodes.filter(d=>d.deg>=5);
    for(let a=0;a<hubs.length;a++)for(let b2=a+1;b2<hubs.length;b2++){
      const d=hubs[a],o=hubs[b2]; let dx=d.x-o.x,dy=d.y-o.y,dist=Math.sqrt(dx*dx+dy*dy)||0.01;
      const f=k*k*6*(d.deg+o.deg)/40/dist; d.dx+=dx/dist*f; d.dy+=dy/dist*f; o.dx-=dx/dist*f; o.dy-=dy/dist*f;
    }
    // centre gravity: hubs feel it less so they can spread; leaves feel it more.
    nodes.forEach(d=>{ const g=d.deg>=5?0.004:0.014; d.dx+=(W/2-d.x)*g*d.m; d.dy+=(H/2-d.y)*g*d.m; });
    nodes.forEach(d=>{ const disp=Math.sqrt(d.dx*d.dx+d.dy*d.dy)||0.01; d.x+=d.dx/disp*Math.min(disp,temp); d.y+=d.dy/disp*Math.min(disp,temp); });
    temp*=cool;
    // in the back third, run a few box-separation passes each tick so the
    // attractive forces and the de-overlap settle together instead of the
    // separation being a jarring one-shot at the very end.
    if(it>iters*0.6 && (it&1)===0) separate(model, 4, 16);
  }
  separate(model, 200, 18);  // strong final convergence on label boxes
  computeBounds(model);
  return model;
}

/* Each node occupies a rectangle: the disc plus its two label lines below.
   We separate these *boxes*, because that footprint is what the user sees
   and what actually collides on screen. Half-extents (hw, hh) + the node's
   label offset below centre. */
function nodeFootprint(n){
  const R=11*(0.8+Math.min(1.6,Math.log2(2+n.deg)*0.3));
  const labLen=Math.min((n.label||'').length, 26);
  const hw=Math.max(R, labLen*3.6+6);        // half width — label text dominates
  const topExt=R;                             // above centre: just the disc
  const botExt=R+30;                          // below centre: disc + 2 label lines
  return {hw, topExt, botExt, cy:(botExt-topExt)/2}; // cy = how far the box centre sits below the node
}

/* Box collision separation. Pushes apart any two nodes whose label boxes
   overlap, with a gap. Grid-accelerated using a cell sized to the largest
   box so neighbours are never missed. Many short passes converge cleanly.
   Pinned nodes stay fixed. */
function separate(model, passes=120, gap=18){
  const nodes=model.nodeArr;
  if(nodes.length<2) return;
  const fp=nodes.map(nodeFootprint);
  // cell must be >= the largest box dimension so a 3x3 scan catches all overlaps
  let maxDim=40; fp.forEach(f=>{ maxDim=Math.max(maxDim, f.hw*2, f.topExt+f.botExt); });
  const cell=maxDim+gap;
  for(let it=0;it<passes;it++){
    const grid=new Map();
    for(let i=0;i<nodes.length;i++){ const d=nodes[i], f=fp[i];
      const gx=Math.floor(d.x/cell), gy=Math.floor((d.y+f.cy)/cell);
      const key=gx+','+gy; (grid.get(key)||grid.set(key,[]).get(key)).push(i); }
    let worst=0;
    for(let i=0;i<nodes.length;i++){ const d=nodes[i], fd=fp[i];
      const gx=Math.floor(d.x/cell), gy=Math.floor((d.y+fd.cy)/cell);
      for(let ax=gx-1;ax<=gx+1;ax++)for(let ay=gy-1;ay<=gy+1;ay++){
        const bucket=grid.get(ax+','+ay); if(!bucket)continue;
        for(const j of bucket){ if(j<=i)continue; const o=nodes[j], fo=fp[j];
          // overlap of two axis-aligned boxes (box centres include the label offset)
          const dcx=d.x-o.x;
          const dcy=(d.y+fd.cy)-(o.y+fo.cy);
          const ox=(fd.hw+fo.hw+gap)-Math.abs(dcx);                 // needed x separation
          const halfH_d=(fd.topExt+fd.botExt)/2, halfH_o=(fo.topExt+fo.botExt)/2;
          const oy=(halfH_d+halfH_o+gap*0.5)-Math.abs(dcy);         // needed y separation
          if(ox>0&&oy>0){ // overlapping — push along the axis of least penetration
            worst=Math.max(worst,Math.min(ox,oy));
            if(ox<oy){ const push=ox/2*(dcx<0?-1:1);
              if(!d.pinned)d.x+=push; if(!o.pinned)o.x-=push; }
            else { const push=oy/2*(dcy<0?-1:1);
              if(!d.pinned)d.y+=push; if(!o.pinned)o.y-=push; }
          }
        } }
    }
    if(worst<0.5) break; // converged: no meaningful overlap left
  }
}
function computeBounds(model){
  let minx=Infinity,miny=Infinity,maxx=-Infinity,maxy=-Infinity;
  model.nodeArr.forEach(d=>{minx=Math.min(minx,d.x);miny=Math.min(miny,d.y);maxx=Math.max(maxx,d.x);maxy=Math.max(maxy,d.y);});
  model.bounds={minx,miny,maxx,maxy};
}

