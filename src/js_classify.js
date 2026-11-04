/* ============================================================
   CLASSIFIER + DEEP DECODERS + ANOMALY DETECTION
   ============================================================ */

function u8(dv,o){return dv.getUint8(o);}
function u16(dv,o){return dv.getUint16(o,false);}

/* identify the application protocol for a dissected packet.
   returns {key, name, fam, dec} where key is stable per protocol. */
function classify(dv,r){
  if(r.l2) return {key:'l2:'+r.l2.name,name:r.l2.name,fam:r.l2.fam,note:r.l2.note};
  if(r.proto==='arp') return {key:'arp',name:'ARP',fam:'infra'};
  if(r.proto==='icmp'||r.proto==='icmp6') return {key:r.proto,name:r.proto.toUpperCase(),fam:'infra'};
  if(r.proto==='igmp') return {key:'igmp',name:'IGMP',fam:'infra'};
  if(['ospf','vrrp','gre','esp'].includes(r.proto)) return {key:r.proto,name:r.proto.toUpperCase(),fam:'infra'};
  if(r.proto==='tcp'||r.proto==='udp'){
    // TCP control packets with no payload (SYN/SYN-ACK/RST/bare-ACK) carry no
    // application data — don't label them as a real service (avoids scan SYNs
    // looking like FTP/SSH/Telnet sessions). Still counted, just generically.
    const isTcp=r.proto==='tcp';
    const synOnly = isTcp && (r.flags&0x02) && !(r.flags&0x10); // SYN w/o ACK
    const rstOnly = isTcp && (r.flags&0x04);
    const noPayload = (r.payloadLen||0)===0;
    const a=PORTS[r.dport], b=PORTS[r.sport];
    let svc,port;
    if(a&&b){ svc = (r.dport<=r.sport)?a:b; port=(r.dport<=r.sport)?r.dport:r.sport; }
    else if(a){svc=a;port=r.dport;} else if(b){svc=b;port=r.sport;}
    if(svc && !(isTcp && noPayload && (synOnly||rstOnly)))
      return {key:svc.name,name:svc.name,fam:svc.fam,dec: noPayload?null:svc.dec, port,why:svc.why};
    // handshake/control toward a known port: note the intent but keep generic family
    if(svc && synOnly)
      return {key:r.proto.toUpperCase(),name:r.proto.toUpperCase()+' setup',fam:'other',handshakePort:port};
    return {key:r.proto.toUpperCase(),name:r.proto.toUpperCase(),fam:'other',
            unknownPort: Math.min(r.sport,r.dport)};
  }
  if(r.proto&&r.proto.startsWith('eth:')) return {key:r.proto,name:'Eth '+r.proto.slice(4),fam:'other'};
  if(r.proto&&r.proto.startsWith('ipproto-')) return {key:r.proto,name:'IP/'+r.proto.slice(8),fam:'other'};
  return {key:r.proto||'?',name:(r.proto||'unknown'),fam:'other'};
}

/* ---- deep decoders: return short human sentence, or null ---- */
const DECODERS = {
  modbus(dv,r){
    const o=r.payloadOff; if(r.payloadLen<8) return null;
    const pid=u16(dv,o+2); if(pid!==0) return null; // protocol id must be 0
    const fc=u8(dv,o+7); const ex=(fc&0x80);
    const base=MODBUS_FC[fc&0x7f];
    if(!base) return {txt:'Modbus function '+(fc&0x7f),expl:'Non-standard/vendor Modbus function code.'};
    if(ex) return {txt:'Modbus '+base[0]+' — EXCEPTION',expl:'Device rejected a '+base[0]+' request (returned an error).'};
    let detail='';
    if(r.payloadLen>=12 && (fc===1||fc===2||fc===3||fc===4||fc===5||fc===6||fc===15||fc===16)){
      const addr=u16(dv,o+8); const qty=u16(dv,o+10);
      const reg = (fc>=3? 40001:0) + addr;
      detail = (fc===5||fc===6)? ' @'+(addr) : ' '+qty+'×@'+addr;
    }
    const write = (fc===5||fc===6||fc===15||fc===16);
    return {txt:'Modbus: '+base[0]+detail, expl:base[1]+(write?'. ⚠ This changes device state.':''), write};
  },
  s7(dv,r){
    const o=r.payloadOff; if(r.payloadLen<2) return null;
    // TPKT(4) + COTP. COTP DT has code 0xf0
    if(u8(dv,o)!==3) return null; // TPKT version 3
    const cotpLen=u8(dv,o+4); const pdutype=u8(dv,o+5)>>4;
    if(pdutype===0xe) return {txt:'S7/COTP: Connection Request',expl:'Opening a connection to a Siemens PLC.'};
    if(pdutype===0xd) return {txt:'S7/COTP: Connection Confirm',expl:'PLC accepted the connection.'};
    const s7off=o+4+1+cotpLen;
    if(s7off+10>o+r.payloadLen) return {txt:'S7comm (COTP)',expl:'Siemens S7 session traffic.'};
    if(u8(dv,s7off)!==0x32) return {txt:'S7 / COTP data',expl:'Siemens control traffic.'};
    const ros=u8(dv,s7off+1); // 1 job,3 ack-data,7 userdata
    const fn=u8(dv,s7off+ (ros===7?12:12));
    // function byte sits after param header; use offset 17/19 heuristic
    let func=null;
    for(const probe of [s7off+17,s7off+19,s7off+12]){ if(probe<o+r.payloadLen){const f=S7_FUNC[u8(dv,probe)]; if(f){func=f;break;}}}
    const rn={1:'Job',2:'Ack',3:'Ack-Data',7:'Userdata'}[ros]||'msg';
    if(func) return {txt:'S7comm: '+func[0], expl:func[1]+(/(STOP|download|program)/i.test(func[0]+func[1])?' ⚠':''), write:/write|stop|download|control/i.test(func[0])};
    return {txt:'S7comm '+rn, expl:'Siemens S7 PLC '+rn.toLowerCase()+' message.'};
  },
  enip(dv,r){
    const o=r.payloadOff; if(r.payloadLen<24) return null;
    const cmd=u16LE(dv,o); const c=ENIP_CMD[cmd];
    // try to find embedded CIP service for RR/Unit data
    let svc=null;
    if((cmd===0x6f||cmd===0x70)&&r.payloadLen>40){
      // crude scan for a CIP service byte in the item data
      for(let i=o+40;i<o+Math.min(r.payloadLen,80);i++){
        const s=CIP_SVC[u8(dv,i)&0x7f]; if(s){svc=s;break;}
      }
    }
    if(svc) return {txt:'EtherNet/IP · CIP '+svc[0], expl:svc[1]+(/write|reset|stop|start/i.test(svc[0])?' ⚠':''), write:/write|reset|stop|start/i.test(svc[0])};
    if(c) return {txt:'EtherNet/IP: '+c[0], expl:c[1]};
    return {txt:'EtherNet/IP cmd 0x'+cmd.toString(16),expl:'CIP/EtherNet/IP control traffic.'};
  },
  dnp3(dv,r){
    const o=r.payloadOff; if(r.payloadLen<10) return null;
    if(u8(dv,o)!==0x05||u8(dv,o+1)!==0x64) return null; // DNP3 start bytes
    const src=u16LE(dv,o+6), dst=u16LE(dv,o+4);
    // app layer func at offset ~12 (after transport header)
    const fc=u8(dv,o+12); const base=DNP3_FC[fc];
    if(base) return {txt:'DNP3: '+base[0]+' ('+src+'→'+dst+')',expl:base[1]+(/(operate|restart|write|stop)/i.test(base[0])?' ⚠':''), write:/operate|write|restart|stop/i.test(base[0])};
    return {txt:'DNP3 ('+src+'→'+dst+')',expl:'SCADA tele-control message.'};
  },
  iec104(dv,r){
    const o=r.payloadOff; if(r.payloadLen<6) return null;
    if(u8(dv,o)!==0x68) return null; // start byte
    const c1=u8(dv,o+2);
    if((c1&1)===0){ // I-format
      const typ=u8(dv,o+6); const t=IEC104_TYPE[typ];
      if(t) return {txt:'IEC-104: '+t[0],expl:t[1]+(/command|set-point|reset/i.test(t[0])?' ⚠':''), write:/command|set-point|reset/i.test(t[0])};
      return {txt:'IEC-104 type '+typ,expl:'Substation tele-control data.'};
    }
    if((c1&3)===1) return {txt:'IEC-104: S-format',expl:'Acknowledgement of received data.'};
    if((c1&3)===3){ const f=u8(dv,o+2);
      const m={0x07:'STARTDT act',0x0b:'STARTDT con',0x13:'STOPDT act',0x23:'TESTFR act'}[f]||'U-frame';
      return {txt:'IEC-104: '+m,expl:'Link control (start/stop/test).'};}
    return null;
  },
  bacnet(dv,r){
    const o=r.payloadOff; if(r.payloadLen<6) return null;
    if(u8(dv,o)!==0x81) return null; // BVLC type
    const npdu=o+4; const apdu=npdu+2;
    const pt=u8(dv,apdu)>>4;
    const m={0:'Confirmed request',1:'Unconfirmed request',2:'Simple ACK',3:'Complex ACK',5:'Error',6:'Reject',7:'Abort'}[pt]||'BACnet';
    return {txt:'BACnet: '+m,expl:'Building automation (HVAC/metering) message.'};
  },
  opcua(dv,r){
    const o=r.payloadOff; if(r.payloadLen<8) return null;
    const t=String.fromCharCode(u8(dv,o),u8(dv,o+1),u8(dv,o+2));
    const m={HEL:'Hello (open connection)',ACK:'Acknowledge',OPN:'Open secure channel',MSG:'Message (service call)',CLO:'Close'}[t];
    if(m) return {txt:'OPC-UA: '+m,expl:'OPC-UA '+m.toLowerCase()+' — modern OT data exchange.'};
    return null;
  },
  dns(dv,r){
    const o=r.payloadOff; if(r.payloadLen<12) return null;
    const flags=u16(dv,o+2); const qr=flags>>15; const qd=u16(dv,o+4);
    // read first qname
    let p=o+12,name='',guard=0;
    try{ while(p<o+r.payloadLen&&guard++<40){const l=u8(dv,p);if(l===0){p++;break;}if(l>=0xc0){p+=2;break;}
      name+=String.fromCharCode.apply(null,new Uint8Array(dv.buffer,p+1,l))+'.';p+=l+1;}}catch(e){}
    name=name.replace(/\.$/,'');
    if(qr===0) return {txt:'DNS query '+(name||''),expl:'Looks up '+(name||'a name')+'.',dnsq:name};
    return {txt:'DNS response '+(name||''),expl:'Answer for '+(name||'a name')+'.',dnsq:name};
  },
  dhcp(dv,r){ return {txt:'DHCP',expl:'Dynamic address assignment.'}; },
  http(dv,r){
    const o=r.payloadOff; if(r.payloadLen<6) return null;
    const s=ascii(dv,o,Math.min(r.payloadLen,64));
    const m=s.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)/);
    if(m) return {txt:'HTTP '+m[1]+' '+m[2].slice(0,40),expl:'Plaintext web request.',host:null};
    if(/^HTTP\/1/.test(s)) return {txt:'HTTP '+s.slice(0,20),expl:'Plaintext web response.'};
    return null;
  },
  tls(dv,r){
    const o=r.payloadOff; if(r.payloadLen<6) return null;
    if(u8(dv,o)!==0x16) return {txt:'TLS (encrypted)',expl:'Encrypted session.'};
    const ht=u8(dv,o+5);
    if(ht===1){ const sni=extractSNI(dv,o,r.payloadLen);
      return {txt:'TLS ClientHello'+(sni?' → '+sni:''),expl:'Starts an encrypted session'+(sni?' to '+sni:'')+'.',sni};}
    if(ht===2) return {txt:'TLS ServerHello',expl:'Server side of encrypted handshake.'};
    return {txt:'TLS handshake',expl:'Encrypted session setup.'};
  },
  snmp(dv,r){ return {txt:'SNMP',expl:'Device monitoring/config poll.'}; },
  mqtt(dv,r){
    const o=r.payloadOff; if(r.payloadLen<2) return null;
    const t=u8(dv,o)>>4;
    const m={1:'CONNECT',2:'CONNACK',3:'PUBLISH',8:'SUBSCRIBE',9:'SUBACK',12:'PINGREQ',14:'DISCONNECT'}[t];
    if(m) return {txt:'MQTT '+m,expl:'Pub/sub telemetry ('+m.toLowerCase()+').'};
    return null;
  },
  profinet(dv,r){
    // PROFINET over UDP (DCP/CM). L2 RT handled in profinetL2().
    const o=r.payloadOff; if(r.payloadLen<2) return null;
    return {txt:'PROFINET (UDP)',expl:'PROFINET context/alarm channel — device setup or alarms.'};
  },
};

/* ---- LLDP TLV decoder ----
   Returns a self-announcement object for the SENDER:
   {sysName, sysDesc, portId, portDesc, mgmtIp, caps, chassisId, neighborChassis}
   LLDP is the local device describing itself; the "neighbor" in a traffic
   sense is whoever receives it, but the frame's source MAC IS the announcer. */
function decodeLLDP(dv,off,end){
  const info={};
  let p=off;
  try{
    while(p+2<=end){
      const h=u16(dv,p); const type=h>>9; const len=h&0x1ff; p+=2;
      if(type===0) break; // end of LLDPDU
      if(p+len>end) break;
      if(type===1){ // Chassis ID: subtype(1) + id
        const sub=u8(dv,p);
        if(sub===4) info.chassisMac=macFrom(dv,p+1,len-1);
        else info.chassisId=asciiClean(dv,p+1,len-1);
      } else if(type===2){ // Port ID
        const sub=u8(dv,p);
        if(sub===3) info.portMac=macFrom(dv,p+1,len-1);
        else info.portId=asciiClean(dv,p+1,len-1);
      } else if(type===4){ info.portDesc=asciiClean(dv,p,len); }
      else if(type===5){ info.sysName=asciiClean(dv,p,len); }
      else if(type===6){ info.sysDesc=asciiClean(dv,p,len); }
      else if(type===7){ // capabilities: sysCap(2) enabledCap(2)
        const en=u16(dv,p+2); info.caps=lldpCaps(en);
      } else if(type===8){ // management address
        const alen=u8(dv,p); const atype=u8(dv,p+1);
        if(atype===1&&alen>=5) info.mgmtIp=dv.getUint8(p+2)+'.'+dv.getUint8(p+3)+'.'+dv.getUint8(p+4)+'.'+dv.getUint8(p+5);
      } else if(type===127){ // org-specific: may carry model/firmware (e.g. 802.1/802.3, or vendor)
        // many OT vendors put model/serial here; grab printable tail as a hint
        const txt=asciiClean(dv,p+4,len-4);
        if(txt&&txt.length>2&&!info.model&&/[A-Za-z]{3}/.test(txt)) info.model=txt.slice(0,40);
      }
      p+=len;
    }
  }catch(e){}
  if(Object.keys(info).length===0) return null;
  const bits=[]; if(info.sysName)bits.push(info.sysName); if(info.portId)bits.push('port '+info.portId); if(info.mgmtIp)bits.push('mgmt '+info.mgmtIp);
  return {txt:'LLDP: '+(bits.join(', ')||'device announcement'),
          expl:'Device announced itself via LLDP'+(info.sysDesc?': '+info.sysDesc.slice(0,60):'')+'.',
          announce:info};
}
function lldpCaps(bits){ // IEEE 802.1AB system capability bits
  const m=[[0x01,'Other'],[0x02,'Repeater'],[0x04,'Bridge/Switch'],[0x08,'WLAN AP'],[0x10,'Router'],[0x20,'Phone'],[0x40,'DOCSIS'],[0x80,'Station']];
  return m.filter(x=>bits&x[0]).map(x=>x[1]).filter(x=>x!=='Other'); }

/* ---- CDP (Cisco Discovery) TLV decoder ---- */
function decodeCDP(dv,off,end){
  const info={}; let p=off+4; // skip version(1)+ttl(1)+checksum(2)
  try{
    while(p+4<=end){
      const type=u16(dv,p); const len=u16(dv,p+2);
      if(len<4||p+len>end) break;
      const vs=p+4, vl=len-4;
      if(type===0x0001) info.sysName=asciiClean(dv,vs,vl);          // Device ID
      else if(type===0x0002){ /* addresses */ if(vl>=9){ info.mgmtIp=dv.getUint8(vs+5)+'.'+dv.getUint8(vs+6)+'.'+dv.getUint8(vs+7)+'.'+dv.getUint8(vs+8);} }
      else if(type===0x0003) info.portId=asciiClean(dv,vs,vl);       // Port ID
      else if(type===0x0004){ const c=dv.getUint32(vs,false); info.caps=cdpCaps(c); } // Capabilities
      else if(type===0x0005) info.sysDesc=asciiClean(dv,vs,vl);      // Software version
      else if(type===0x0006) info.model=asciiClean(dv,vs,vl);        // Platform/model
      p+=len;
    }
  }catch(e){}
  if(Object.keys(info).length===0) return null;
  const bits=[]; if(info.sysName)bits.push(info.sysName); if(info.model)bits.push(info.model); if(info.portId)bits.push('port '+info.portId);
  return {txt:'CDP: '+(bits.join(', ')||'device announcement'),
          expl:'Device announced itself via CDP'+(info.model?' — model '+info.model:'')+'.',
          announce:info};
}
function cdpCaps(bits){ const m=[[0x01,'Router'],[0x02,'Bridge'],[0x04,'Src-route'],[0x08,'Switch'],[0x10,'Host'],[0x20,'IGMP'],[0x40,'Repeater'],[0x80,'Phone']];
  return m.filter(x=>bits&x[0]).map(x=>x[1]); }

function macFrom(dv,o,len){ if(len<6)return null; const h=i=>dv.getUint8(o+i).toString(16).padStart(2,'0'); return h(0)+':'+h(1)+':'+h(2)+':'+h(3)+':'+h(4)+':'+h(5); }
function asciiClean(dv,o,len){ let s=''; for(let i=0;i<len;i++){ const c=dv.getUint8(o+i); if(c>=32&&c<127)s+=String.fromCharCode(c); else if(c===0)break; else s+=' '; } return s.trim(); }

function decodeEtherCAT(dv,off,end){ return {txt:'EtherCAT',expl:'EtherCAT real-time fieldbus frame — cyclic motion/I/O.'}; }

/* PROFINET Layer-2 RT decoder — called for ethertype 0x8892 frames.
   dv/off point at the start of the PN-RT payload (after the ethertype). */
function profinetL2(dv,off,end){
  if(off+2>end) return {txt:'PROFINET RT',expl:'Real-time I/O frame.'};
  const fid=u16(dv,off);
  const m=profinetFrameMeaning(fid);
  const danger=/config|assignment|set/i.test(m[1]);
  return {txt:'PROFINET: '+m[0], expl:m[1].charAt(0).toUpperCase()+m[1].slice(1)+'.'+(danger?' ⚠ changes device identity.':''),
          write:danger, frameId:fid};
}

/* Detect protocol version / security posture from a decoded packet.
   Returns {label, secure} or null. Accumulated per edge. */
function detectVersion(dv,r,clsName){
  const o=r.payloadOff;
  try{
    if(clsName==='S7comm / COTP' && r.payloadLen>7 && u8(dv,o)===3){
      // find S7 protocol id: 0x32 = classic, 0x72 = S7comm-Plus
      for(let i=o+4;i<o+Math.min(r.payloadLen,30);i++){
        if(u8(dv,i)===0x72) return {label:'S7comm-Plus (S7-1200/1500)',secure:'partial'};
        if(u8(dv,i)===0x32) return {label:'S7comm classic (S7-300/400)',secure:false};
      }
    }
    if(clsName==='OPC-UA' && r.payloadLen>8){
      const t=String.fromCharCode(u8(dv,o),u8(dv,o+1),u8(dv,o+2));
      if(t==='OPN'){
        // security policy URI appears as a string after a few header fields
        const txt=ascii(dv,o+8,Math.min(r.payloadLen-8,200));
        if(/#None/.test(txt)) return {label:'OPC-UA SecurityPolicy: None',secure:false};
        if(/Basic256Sha256|Aes\d+/.test(txt)) return {label:'OPC-UA SecurityPolicy: '+(txt.match(/(Basic256Sha256|Aes128[^\s,"]*|Aes256[^\s,"]*)/)||[])[1],secure:true};
        if(/#Sign/.test(txt)) return {label:'OPC-UA: Sign',secure:'partial'};
      }
    }
    if(clsName==='SNMP' && r.payloadLen>4 && u8(dv,o)===0x30){
      // SEQUENCE { version INTEGER ... }
      let i=o+2; if(u8(dv,i)===0x02){ const vlen=u8(dv,i+1); const ver=u8(dv,i+2);
        const vmap={0:'v1',1:'v2c',3:'v3'}; const vv=vmap[ver]||('v'+ver);
        return {label:'SNMP '+vv,secure:ver===3?'partial':false}; }
    }
    if(clsName==='HTTP'){
      const s=ascii(dv,o,Math.min(r.payloadLen,80));
      const m=s.match(/HTTP\/(1\.[01]|2)/); if(m) return {label:'HTTP/'+m[1],secure:false};
    }
    if(clsName==='HTTPS/TLS' || clsName==='TLS'){
      // TLS record version is misleading; use ClientHello supported_versions when present
      if(r.payloadLen>3 && u8(dv,o)===0x16){ const maj=u8(dv,o+1),min=u8(dv,o+2);
        const vmap={ '3,1':'TLS 1.0','3,2':'TLS 1.1','3,3':'TLS 1.2','3,4':'TLS 1.3' };
        return {label:vmap[maj+','+min]||'TLS',secure:true}; }
    }
    if(clsName==='DNP3' && r.payloadLen>14){
      // SAv5 aggressive mode / auth objects use group 120
      for(let i=o+10;i<o+Math.min(r.payloadLen,40);i++){ if(u8(dv,i)===120) return {label:'DNP3 with Secure Auth (SAv5)',secure:'partial'}; }
      return {label:'DNP3 (no secure auth)',secure:false};
    }
  }catch(e){}
  return null;
}
function u16LE(dv,o){return dv.getUint16(o,true);}
function ascii(dv,o,n){let s='';for(let i=0;i<n;i++){const c=dv.getUint8(o+i);s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function extractSNI(dv,o,len){
  try{ // walk ClientHello to extensions → server_name
    let p=o+5+4+2+32; const sid=dv.getUint8(p);p+=1+sid;
    const cs=dv.getUint16(p,false);p+=2+cs; const cm=dv.getUint8(p);p+=1+cm;
    const extlen=dv.getUint16(p,false);p+=2; const extend=p+extlen;
    while(p+4<=extend&&p+4<=o+len){const et=dv.getUint16(p,false);const el=dv.getUint16(p+2,false);p+=4;
      if(et===0){ // server_name
        let q=p+2; q+=1; const nl=dv.getUint16(q,false);q+=2;
        return ascii(dv,q,nl);
      } p+=el;}
  }catch(e){} return null;
}

/* ============================================================
   ANOMALY DETECTION
   Builds findings from aggregate stats after the walk.
   ============================================================ */
function detectAnomalies(model){
  const F=[];
  const add=(sev,title,desc,ref)=>F.push({sev,title,desc,ref});
  const edges=model.edgeArr||model.edges||[];

  // 1. malformed / truncated frames
  if(model.badCount>0){
    const sev = model.badCount/model.total>0.02 ? 'med':'low';
    add(sev,'Malformed or truncated frames',
      model.badCount+' of '+model.total+' packets failed to dissect cleanly ('+
      Object.entries(model.badKinds).sort((a,b)=>b[1]-a[1]).slice(0,4).map(x=>x[0]+'×'+x[1]).join(', ')+
      '). Could be capture truncation, corruption, or a protocol this tool doesn\'t parse.');
  }
  // 2. plaintext control / credentials (dedup per protocol)
  const plainSeen=new Set();
  edges.forEach(e=>{
    for(const pk in e.protos){
      if((pk==='Telnet'||pk==='FTP'||pk==='HTTP')&&!plainSeen.has(pk)){
        plainSeen.add(pk);
        add('med','Plaintext '+pk+' in use',
          pk+' traffic (e.g. '+e.a.label+' ↔ '+e.b.label+') exposes content and credentials in clear text. On an OT network this is a common weak point.',
          e.a.id+' | '+e.b.id);
      }
    }
  });
  // 2b. insecure protocol versions detected on the wire
  const verSeen=new Set();
  model.nodeArr&&model.nodeArr.forEach(n=>{ for(const v in n.versions){
    const sec=n.versions[v];
    if(sec===false && /None|v1|v2c|HTTP\/1|classic/.test(v) && !verSeen.has(v)){
      verSeen.add(v);
      add('low','Insecure configuration — '+v,
        v+' offers no authentication or encryption. Seen on '+n.label+'. Consider the secure variant where the device supports it.',n.id);
    }
  }});
  // 3. OT writes / dangerous control functions
  model.controlEvents.slice(0,12).forEach(ev=>{
    add('high','OT control action — '+ev.txt,
      ev.expl+'  Seen '+ev.src+' → '+ev.dst+'.', ev.src+' | '+ev.dst);
  });
  // 4. unknown OT-range ports (possible custom/proprietary protocol)
  const otRange=Object.entries(model.unknownPorts).filter(([p,c])=>c>=4 && (+p<10000 || (+p>=18000&&+p<=20010)));
  otRange.sort((a,b)=>b[1]-a[1]).slice(0,5).forEach(([p,c])=>{
    add('low','Unrecognised service on port '+p,
      c+' packets use TCP/UDP port '+p+', which isn\'t a known protocol here. On an OT segment this may be a proprietary or custom controller protocol worth confirming manually.');
  });
  // 5. scan behaviour: one src touching many dst ports or many hosts
  for(const id in (model.nodes||{})){
    const nd=model.nodes[id];
    if(nd.distinctDstPorts && nd.distinctDstPorts.size>=20){
      add('high','Possible port scan from '+nd.label,
        nd.label+' contacted '+nd.distinctDstPorts.size+' distinct destination ports across '+nd.peers.size+' host(s) — a pattern consistent with scanning/reconnaissance.',id);
    } else if(nd.peers.size>=Math.max(15, model.nodeCount*0.6) && model.nodeCount>6){
      add('med','High fan-out from '+nd.label,
        nd.label+' talks to '+nd.peers.size+' hosts — could be a legitimate server/SCADA master, or sweeping behaviour. Worth confirming its role.',id);
    }
  }
  // 6. ARP anomalies: multiple MACs claiming one IP (spoofing)
  for(const ip in model.arpMap){
    const macs=model.arpMap[ip];
    if(macs.size>1){
      add('high','Possible ARP spoofing for '+ip,
        ip+' was announced by '+macs.size+' different MAC addresses ('+[...macs].join(', ')+'). This can indicate ARP poisoning / a man-in-the-middle.',ip);
    }
  }
  // 7. plaintext OT (all OT except OPC-UA/MQTT-TLS is unauthenticated plaintext by default) — informational
  const otUnenc=new Set();
  edges.forEach(e=>{for(const pk in e.protos){const f=(PORTS_BYNAME[pk]||{}).fam;if(f==='ot')otUnenc.add(pk);}});
  if(otUnenc.size){
    add('low','Unauthenticated OT protocols present',
      [...otUnenc].join(', ')+' typically run without authentication or encryption. Anyone on the segment can read process data and, for write-capable functions, issue commands. This is normal for these protocols but worth noting for the risk picture.');
  }

  // severity order
  const rank={high:0,med:1,low:2};
  F.sort((a,b)=>rank[a.sev]-rank[b.sev]);
  return F;
}
const PORTS_BYNAME={}; for(const p in PORTS){PORTS_BYNAME[PORTS[p].name]=PORTS[p];}
