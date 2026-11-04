/* ============================================================
   CAPTURE PARSER  —  pcap (classic) + pcapng  (STREAMING)
   Zero dependencies. Reads the file in chunks via a Blob slice
   reader so we never hold the whole capture in memory. Each
   packet is dissected and handed to a callback; the bytes are
   then dropped. This lets 500 MB+ captures run in a browser.
   ============================================================ */

const LINKTYPE = {0:'null',1:'en10mb',101:'raw',113:'linux_sll',276:'linux_sll2',
  127:'radiotap',105:'ieee80211',12:'raw',14:'raw',228:'ipv4',229:'ipv6'};

/* Read a File/Blob in slices, yielding a rolling DataView window.
   We keep a small carry buffer so packet records that straddle a
   chunk boundary are handled. onPacket(dv, recOff, caplen, wirelen,
   ts, link) is called for every packet. Returns summary stats. */
async function parseCaptureStreaming(file, onPacket, onProgress){
  const total=file.size;
  if(total<24) throw new Error('File too small to be a capture.');
  const headBuf=await file.slice(0,Math.min(total,65536)).arrayBuffer();
  const hdv=new DataView(headBuf);
  const magic=hdv.getUint32(0,false);

  let mode,le=false,nano=false,link='en10mb',headerLen=24;
  const ifaces=[]; // pcapng
  if(magic===0x0a0d0d0a){ mode='pcapng'; }
  else if(magic===0xa1b2c3d4){ mode='pcap'; le=false; }
  else if(magic===0xd4c3b2a1){ mode='pcap'; le=true; }
  else if(magic===0xa1b23c4d){ mode='pcap'; le=false; nano=true; }
  else if(magic===0x4d3cb2a1){ mode='pcap'; le=true; nano=true; }
  else throw new Error('Not a pcap/pcapng file (bad magic 0x'+magic.toString(16)+').');

  const stats={format:mode,link:'en10mb',packets:0,bytes:total};

  if(mode==='pcap'){
    link=LINKTYPE[hdv.getUint32(20,le)&0xffff]||'en10mb';
    stats.link=link;
    await streamRecords(file,24,total,async(dv,base,pos)=>{
      // pcap record header is 16 bytes
      if(pos+16>dv.byteLength) return -1; // need more
      const ts_s=dv.getUint32(pos,le), ts_f=dv.getUint32(pos+4,le);
      const incl=dv.getUint32(pos+8,le);
      if(incl>262144) return -2; // corrupt
      if(pos+16+incl>dv.byteLength) return -1; // packet body spans chunk
      const ts=ts_s+(nano?ts_f/1e9:ts_f/1e6);
      onPacket(dv,pos+16,incl,dv.getUint32(pos+12,le),ts,link);
      stats.packets++;
      return 16+incl;
    },onProgress);
  } else {
    // pcapng
    await streamRecords(file,0,total,async(dv,base,pos)=>{
      if(pos+12>dv.byteLength) return -1;
      // determine endianness from the SHB that precedes everything
      const btypeLE=dv.getUint32(pos,true);
      let blockLE=le;
      if(btypeLE===0x0a0d0d0a){ // SHB — byte order magic at pos+8
        blockLE = (dv.getUint32(pos+8,true)===0x1a2b3c4d); le=blockLE;
      }
      const btype=dv.getUint32(pos,le);
      const blen=dv.getUint32(pos+4,le);
      if(blen<12||blen>64*1024*1024) return -2;
      if(pos+blen>dv.byteLength) return -1;
      if(btype===0x00000001){ // IDB
        const lt=dv.getUint16(pos+8,le); let tsresol=6;
        let o=pos+16; const e=pos+blen-4;
        while(o+4<=e){ const code=dv.getUint16(o,le), olen=dv.getUint16(o+2,le);
          if(code===0)break; if(code===9&&olen>=1){const v=dv.getUint8(o+4);tsresol=(v&0x80)?(v&0x7f):v;}
          o+=4+((olen+3)&~3); }
        ifaces.push({link:LINKTYPE[lt]||'en10mb',div:Math.pow(10,tsresol)});
        if(ifaces.length===1) stats.link=ifaces[0].link;
      } else if(btype===0x00000006){ // EPB
        const ifid=dv.getUint32(pos+8,le);
        const th=dv.getUint32(pos+12,le), tl=dv.getUint32(pos+16,le);
        const incl=dv.getUint32(pos+20,le);
        const inf=ifaces[ifid]||{link:'en10mb',div:1e6};
        if(pos+28+incl<=pos+blen){
          const ts=(th*4294967296+tl)/inf.div;
          onPacket(dv,pos+28,incl,dv.getUint32(pos+24,le),ts,inf.link);
          stats.packets++;
        }
      } else if(btype===0x00000003){ // SPB
        const inf=ifaces[0]||{link:'en10mb'};
        const incl=blen-16;
        if(incl>0&&pos+8+incl<=pos+blen){ onPacket(dv,pos+8,incl,incl,0,inf.link); stats.packets++; }
      }
      return (blen+3)&~3;
    },onProgress);
  }
  return stats;
}

/* Slice-reader: walks the file in CHUNK windows. The step callback
   returns the number of bytes consumed, -1 if it needs the record
   re-presented at the start of a larger window (straddles boundary),
   or -2 to abort (corruption). */
async function streamRecords(file,start,total,step,onProgress){
  const CHUNK=4*1024*1024;      // 4 MB windows
  let filer=start;              // absolute file offset of window start
  let carry=new Uint8Array(0);  // leftover bytes from previous window
  while(filer<total){
    const end=Math.min(filer+CHUNK,total);
    const chunk=new Uint8Array(await file.slice(filer,end).arrayBuffer());
    // prepend carry
    let win;
    if(carry.length){ win=new Uint8Array(carry.length+chunk.length); win.set(carry,0); win.set(chunk,carry.length); }
    else win=chunk;
    const dv=new DataView(win.buffer,win.byteOffset,win.byteLength);
    let pos=0; let aborted=false;
    while(pos<win.length){
      const consumed=await step(dv,filer-carry.length,pos);
      if(consumed===-1){ break; }          // record straddles end — carry remainder
      if(consumed===-2){ aborted=true; break; } // corrupt; stop cleanly
      if(consumed<=0){ aborted=true; break; }
      pos+=consumed;
    }
    if(aborted){ break; }
    // carry the unconsumed tail
    const tail=win.length-pos;
    if(pos<win.length){ carry=win.slice(pos); }
    else carry=new Uint8Array(0);
    filer=end;
    if(onProgress) onProgress(Math.min(1,filer/total));
    // yield to the event loop so the UI can paint the progress bar
    await new Promise(r=>setTimeout(r,0));
    // safety: if carry grows beyond a record cap, file is malformed
    if(carry.length>64*1024*1024){ break; }
  }
}

/* ---------- per-packet dissection (unchanged API) ----------
   dissect(dv, base, caplen, wirelen, ts, link) -> record view */
function macStr(dv,o){
  const h=i=>dv.getUint8(o+i).toString(16).padStart(2,'0');
  return h(0)+':'+h(1)+':'+h(2)+':'+h(3)+':'+h(4)+':'+h(5);
}
function ip4Str(dv,o){return dv.getUint8(o)+'.'+dv.getUint8(o+1)+'.'+dv.getUint8(o+2)+'.'+dv.getUint8(o+3);}
function ip6Str(dv,o){
  const p=[];for(let i=0;i<8;i++)p.push(dv.getUint16(o+i*2,false).toString(16));
  let best=-1,bl=0,cur=-1,cl=0;
  for(let i=0;i<8;i++){if(p[i]==='0'){if(cur<0){cur=i;cl=1}else cl++;if(cl>bl){bl=cl;best=cur}}else cur=-1}
  if(bl>1){p.splice(best,bl,'');if(best===0)p.unshift('');if(best+bl===8)p.push('')}
  return p.join(':').replace(/:::+/,'::');
}

function dissect(dv, base, caplen, wirelen, ts, link){
  const r={ts,len:wirelen,cap:caplen,l2:null,src:null,dst:null,
           smac:null,dmac:null,proto:null,sport:0,dport:0,ethtype:0,
           vlan:null,flags:0,payloadOff:0,payloadLen:0,bad:null,note:null};
  let o=base; const end=base+caplen;
  let etype=0;
  try{
    if(link==='en10mb'){
      if(o+14>end){r.bad='short-eth';return r;}
      r.dmac=macStr(dv,o); r.smac=macStr(dv,o+6);
      etype=dv.getUint16(o+12,false); o+=14;
      while(etype===0x8100||etype===0x88a8){
        if(o+4>end){r.bad='short-vlan';return r;}
        r.vlan=dv.getUint16(o,false)&0x0fff; etype=dv.getUint16(o+2,false); o+=4;
      }
    } else if(link==='linux_sll'){
      if(o+16>end){r.bad='short-sll';return r;} etype=dv.getUint16(o+14,false); o+=16;
    } else if(link==='linux_sll2'){
      if(o+20>end){r.bad='short-sll2';return r;} etype=dv.getUint16(o,false); o+=20;
    } else if(link==='raw'||link==='ipv4'||link==='ipv6'){
      const v=dv.getUint8(o)>>4; etype=(v===6)?0x86dd:0x0800;
    } else if(link==='null'){
      const fam=dv.getUint32(o,true); o+=4; etype=(fam===2)?0x0800:(fam===24||fam===28||fam===30)?0x86dd:0;
    } else { r.bad='link-'+link; return r; }
    r.ethtype=etype;

    // 802.3 LLC frame: the "ethertype" field is actually a length (<=1500).
    // These carry STP (DSAP/SSAP 0x42) and SNAP-encapsulated protocols (CDP,
    // VTP, EDP, FDP) identified by OUI+PID after an AA-AA-03 LLC header.
    if(etype<=1500 && link==='en10mb'){
      if(o+3<=end){
        const dsap=dv.getUint8(o), ssap=dv.getUint8(o+1);
        if(dsap===0x42&&ssap===0x42){ r.l2={name:STP_NOTE.name,fam:STP_NOTE.fam,note:STP_NOTE.note}; r.proto='l2:'+STP_NOTE.name; return r; }
        if(dsap===0xaa&&ssap===0xaa&&o+8<=end){ // SNAP
          const oui=dv.getUint8(o+3).toString(16).padStart(2,'0')+dv.getUint8(o+4).toString(16).padStart(2,'0')+dv.getUint8(o+5).toString(16).padStart(2,'0');
          const pid=dv.getUint16(o+6,false).toString(16).padStart(4,'0');
          const snap=SNAP_PROTO[oui+':'+pid];
          if(snap){ r.l2={name:snap.name,fam:snap.fam,note:snap.note,dec:snap.dec}; r.proto='l2:'+snap.name; r.l2off=o+8; r.l2end=end; return r; }
          // unknown SNAP — still mark as L2
          r.l2={name:'LLC/SNAP',fam:'infra',note:'802.3 LLC/SNAP frame.'}; r.proto='l2:snap'; return r;
        }
        // other LLC
        r.l2={name:'LLC',fam:'infra',note:'802.3 LLC control frame.'}; r.proto='l2:llc'; return r;
      }
    }

    const et=ETHERTYPE[etype];
    if(typeof et==='object'){ r.l2={name:et.name,fam:et.fam,note:et.note,dec:et.dec}; r.proto='l2:'+et.name; r.l2off=o; r.l2end=end; return r; }
    if(etype===0x0806){ r.proto='arp';
      if(o+28<=end){ const op=dv.getUint16(o+6,false);
        r.note=op===1?'ARP who-has (request)':op===2?'ARP is-at (reply)':'ARP op '+op;
        r.src=ip4Str(dv,o+14); r.dst=ip4Str(dv,o+24);
        r.arp={op,sip:r.src,tip:r.dst,smac:macStr(dv,o+8),tmac:macStr(dv,o+18)}; }
      return r;
    }
    let proto,l3end;
    if(etype===0x0800){
      if(o+20>end){r.bad='short-ip4';return r;}
      const ihl=(dv.getUint8(o)&0x0f)*4; if(ihl<20){r.bad='bad-ihl';return r;}
      const tot=dv.getUint16(o+2,false); proto=dv.getUint8(o+9);
      r.src=ip4Str(dv,o+12); r.dst=ip4Str(dv,o+16);
      const frag=dv.getUint16(o+6,false); r.frag=(frag&0x2000)||(frag&0x1fff);
      l3end=Math.min(end,o+(tot||(end-o))); o+=ihl;
    } else if(etype===0x86dd){
      if(o+40>end){r.bad='short-ip6';return r;}
      proto=dv.getUint8(o+6); r.src=ip6Str(dv,o+8); r.dst=ip6Str(dv,o+24);
      const plen=dv.getUint16(o+4,false); l3end=Math.min(end,o+40+plen); o+=40;
      let g=0; while((proto===0||proto===43||proto===44||proto===60)&&o+8<=end&&g++<8){
        const nh=dv.getUint8(o); o+=(dv.getUint8(o+1)+1)*8; proto=nh; }
    } else { r.proto='eth:0x'+etype.toString(16); return r; }

    r.ipproto=proto;
    if(proto===6){
      if(o+20>l3end){r.bad='short-tcp';return r;}
      r.sport=dv.getUint16(o,false); r.dport=dv.getUint16(o+2,false);
      const doff=(dv.getUint8(o+12)>>4)*4; r.flags=dv.getUint8(o+13);
      if(doff<20){r.bad='bad-tcp-doff';return r;}
      r.proto='tcp'; r.payloadOff=o+doff; r.payloadLen=Math.max(0,l3end-(o+doff)); r.seq=dv.getUint32(o+4,false);
    } else if(proto===17){
      if(o+8>l3end){r.bad='short-udp';return r;}
      r.sport=dv.getUint16(o,false); r.dport=dv.getUint16(o+2,false);
      const ul=dv.getUint16(o+4,false);
      r.proto='udp'; r.payloadOff=o+8; r.payloadLen=Math.max(0,Math.min(l3end,o+ul)-(o+8));
    } else if(proto===1){ r.proto='icmp'; r.icmptype=o<l3end?dv.getUint8(o):-1; r.note='ICMP type '+r.icmptype;
    } else if(proto===58){ r.proto='icmp6'; r.icmptype=o<l3end?dv.getUint8(o):-1; r.note='ICMPv6 type '+r.icmptype;
    } else if(proto===2){ r.proto='igmp'; r.note='IGMP';
    } else if(proto===89){ r.proto='ospf'; } else if(proto===112){ r.proto='vrrp'; }
    else if(proto===47){ r.proto='gre'; } else if(proto===50){ r.proto='esp'; }
    else { r.proto='ipproto-'+proto; r.note='IP protocol '+proto; }
  }catch(e){ r.bad='exception'; }
  return r;
}
