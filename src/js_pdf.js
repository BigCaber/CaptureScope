/* ============================================================
   MINIMAL PDF WRITER  (no deps)
   Objects are either a dict string, or {dict, bytes} for a stream.
   ============================================================ */
function PDFDoc(){
  const objs=[];
  const pages=[];
  const W=842,H=595;
  const enc=new TextEncoder();
  function add(data){ objs.push(data); return objs.length; }

  const fontId  = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const fontBId = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>');
  const fontMId = add('<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>');

  function pesc(s){ return String(s).replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)').replace(/[^\x20-\x7e]/g,' '); }

  function page(){
    const content=[]; const images=[];
    const api={ W,H,
      text(x,y,s,size,font,color){ size=size||11;font=font||'F1';color=color||[0.1,0.13,0.17];
        content.push('BT /'+font+' '+size+' Tf '+color.map(c=>c.toFixed(3)).join(' ')+' rg '+x.toFixed(1)+' '+(H-y).toFixed(1)+' Td ('+pesc(s)+') Tj ET'); return api; },
      wrap(x,y,s,size,font,color,maxw,lh){
        const words=String(s).split(/\s+/); let line='',yy=y;
        const perLine=Math.max(8,Math.floor(maxw/(size*0.5)));
        words.forEach(w=>{ if(line && (line+' '+w).length>perLine){ api.text(x,yy,line,size,font,color); yy+=lh; line=w; } else line=line?line+' '+w:w; });
        if(line) api.text(x,yy,line,size,font,color); return yy; },
      rect(x,y,w,h,fill){ content.push(fill.map(c=>c.toFixed(3)).join(' ')+' rg '+x.toFixed(1)+' '+(H-y-h).toFixed(1)+' '+w.toFixed(1)+' '+h.toFixed(1)+' re f'); return api; },
      line(x1,y1,x2,y2,col,wd){ col=col||[0.8,0.85,0.9];wd=wd||0.6;
        content.push(col.map(c=>c.toFixed(3)).join(' ')+' RG '+wd+' w '+x1.toFixed(1)+' '+(H-y1).toFixed(1)+' m '+x2.toFixed(1)+' '+(H-y2).toFixed(1)+' l S'); return api; },
      image(imgData,x,y,w,h){ images.push({imgData,x,y,w,h}); return api; },
      _content:content,_images:images };
    pages.push(api); return api;
  }

  function build(){
    const kids=[]; const pageIds=[];
    pages.forEach(pg=>{
      const resImgs=[];
      pg._images.forEach((im,i)=>{
        const xo=pngRGBAtoXObject(im.imgData);
        const smaskId=add({dict:xo.smaskDict,bytes:xo.smaskBytes});
        const dict=xo.dict.replace('>>',' /SMask '+smaskId+' 0 R >>');
        const imgId=add({dict,bytes:xo.bytes});
        resImgs.push({imgId,name:'Im'+i,im});
      });
      const cs=pg._content.slice();
      resImgs.forEach(r=>{ const im=r.im;
        cs.push('q '+im.w.toFixed(1)+' 0 0 '+im.h.toFixed(1)+' '+im.x.toFixed(1)+' '+(H-im.y-im.h).toFixed(1)+' cm /'+r.name+' Do Q'); });
      const streamBytes=enc.encode(cs.join('\n'));
      const contentId=add({dict:'<< /Length '+streamBytes.length+' >>',bytes:streamBytes});
      const xobj=resImgs.length? ' /XObject << '+resImgs.map(r=>'/'+r.name+' '+r.imgId+' 0 R').join(' ')+' >>':'';
      const pid=add('<< /Type /Page /Parent __PAGES__ /MediaBox [0 0 '+W+' '+H+'] /Resources << /Font << /F1 '+fontId+' 0 R /F2 '+fontBId+' 0 R /F3 '+fontMId+' 0 R >>'+xobj+' >> /Contents '+contentId+' 0 R >>');
      pageIds.push(pid); kids.push(pid+' 0 R');
    });
    const pagesId=add('<< /Type /Pages /Kids ['+kids.join(' ')+'] /Count '+pages.length+' >>');
    pageIds.forEach(pid=>{ objs[pid-1]=objs[pid-1].replace('__PAGES__',pagesId+' 0 R'); });
    const catId=add('<< /Type /Catalog /Pages '+pagesId+' 0 R >>');

    const chunks=[]; let pos=0; const offsets=new Array(objs.length+1);
    const push=d=>{ const b=(typeof d==='string')?enc.encode(d):d; chunks.push(b); pos+=b.length; };
    push('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n');
    objs.forEach((o,i)=>{ const id=i+1; offsets[id]=pos; push(id+' 0 obj\n');
      if(typeof o==='string'){ push(o); } else { push(o.dict+'\nstream\n'); push(o.bytes); push('\nendstream'); }
      push('\nendobj\n'); });
    const xref=pos;
    push('xref\n0 '+(objs.length+1)+'\n0000000000 65535 f \n');
    for(let id=1;id<=objs.length;id++) push(String(offsets[id]).padStart(10,'0')+' 00000 n \n');
    push('trailer\n<< /Size '+(objs.length+1)+' /Root '+catId+' 0 R >>\nstartxref\n'+xref+'\n%%EOF');
    const total=chunks.reduce((a,b)=>a+b.length,0); const out=new Uint8Array(total); let k=0; chunks.forEach(b=>{out.set(b,k);k+=b.length;});
    return new Blob([out],{type:'application/pdf'});
  }
  return {page,build};
}

function pngRGBAtoXObject(img){
  const w=img.w,h=img.h,rgba=img.rgba;
  const rgb=new Uint8Array(w*h*3), alpha=new Uint8Array(w*h);
  for(let i=0,j=0,a=0;i<rgba.length;i+=4){ rgb[j++]=rgba[i];rgb[j++]=rgba[i+1];rgb[j++]=rgba[i+2];alpha[a++]=rgba[i+3]; }
  const rgbZ=zlibStore(rgb), aZ=zlibStore(alpha);
  return {
    dict:'<< /Type /XObject /Subtype /Image /Width '+w+' /Height '+h+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length '+rgbZ.length+' >>',
    bytes:rgbZ,
    smaskDict:'<< /Type /XObject /Subtype /Image /Width '+w+' /Height '+h+' /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length '+aZ.length+' >>',
    smaskBytes:aZ };
}

function zlibStore(data){
  const CH=65535, n=data.length, blocks=Math.max(1,Math.ceil(n/CH));
  const out=[0x78,0x01];
  for(let i=0;i<blocks;i++){ const s=i*CH, len=Math.min(CH,n-s), last=(i===blocks-1)?1:0;
    out.push(last, len&0xff,(len>>8)&0xff, (~len)&0xff,((~len)>>8)&0xff);
    for(let j=0;j<len;j++) out.push(data[s+j]); }
  let a=1,b=0; for(let i=0;i<n;i++){ a=(a+data[i])%65521; b=(b+a)%65521; }
  out.push((b>>8)&0xff,b&0xff,(a>>8)&0xff,a&0xff);
  return Uint8Array.from(out);
}

/* ============================================================
   REPORT BUILDER
   ============================================================ */
async function exportPDF(){
  if(!MODEL) return;
  const GW=1500,GH=940;
  const cv=document.createElement('canvas'); cv.width=GW;cv.height=GH;
  const c=cv.getContext('2d');
  c.fillStyle='#0c1016'; c.fillRect(0,0,GW,GH);
  R.renderToContext(c,GW,GH);
  const idata=c.getImageData(0,0,GW,GH);
  const graphImg={w:GW,h:GH,rgba:idata.data};

  const doc=PDFDoc(); const m=MODEL;
  const C={ink:[0.12,0.14,0.17],ink2:[0.35,0.42,0.5],ink3:[0.55,0.62,0.68],
    bad:[0.9,0.28,0.33],warn:[0.78,0.55,0.18],line:[0.84,0.87,0.9],band:[0.95,0.96,0.97]};

  let p=doc.page();
  p.rect(0,0,p.W,54,C.band);
  p.text(40,34,'CaptureScope  -  Network Topology Report',18,'F2',C.ink);
  p.text(40,48,(m.fileName||'capture')+'   -   '+m.format+'/'+m.link,10,'F3',C.ink3);
  p.text(p.W-220,48,'generated '+new Date().toISOString().replace('T',' ').slice(0,16),9,'F1',C.ink3);
  let sx=40; [[m.nodeCount,'hosts'],[m.edgeArr.length,'conversations'],[Object.keys(m.protoCount).length,'protocols'],[m.total.toLocaleString(),'packets'],[m.findings.length,'findings']]
    .forEach(a=>{ p.text(sx,86,String(a[0]),17,'F2',C.ink); p.text(sx,100,a[1],9,'F1',C.ink3); sx+=150; });
  p.line(40,112,p.W-40,112,C.line,0.8);
  const iw=p.W-80, ih=Math.min(iw*GH/GW, p.H-150);
  p.image(graphImg,40,122,iw,ih);
  p.text(40,p.H-14,'Node colour = dominant protocol family; size = peer count; icon = inferred device type. Generated locally in-browser.',8,'F1',C.ink3);

  p=doc.page(); p.rect(0,0,p.W,40,C.band); p.text(40,27,'Findings',16,'F2',C.ink);
  let y=64;
  if(!m.findings.length) p.text(40,y,'No anomalies flagged. Capture looks ordinary - verify manually.',11,'F1',C.ink2);
  m.findings.slice(0,18).forEach(f=>{
    if(y>p.H-80){ p=doc.page(); p.rect(0,0,p.W,40,C.band); p.text(40,27,'Findings (cont.)',16,'F2',C.ink); y=64; }
    const col=f.sev==='high'?C.bad:f.sev==='med'?C.warn:C.ink3;
    p.rect(40,y-10,4,36,col);
    p.text(54,y,'['+f.sev.toUpperCase()+']  '+f.title,11.5,'F2',C.ink);
    y=p.wrap(54,y+15,f.desc,9.5,'F1',C.ink2,p.W-110,12)+6;
    if(f.ref){ p.text(54,y,'ref: '+f.ref,8.5,'F3',C.ink3); y+=13; }
    y+=10;
  });

  p=doc.page(); p.rect(0,0,p.W,40,C.band); p.text(40,27,'Hosts',16,'F2',C.ink);
  const cols=[[40,'Address'],[250,'Device'],[360,'Vendor'],[525,'Peers'],[580,'Pkts'],[660,'Protocols']];
  y=60; const header=()=>{ cols.forEach(a=>p.text(a[0],y,a[1],9,'F2',C.ink2)); p.line(40,y+4,p.W-40,y+4,C.line,0.8); y+=18; };
  header();
  m.nodeArr.slice().sort((a,b)=>b.deg-a.deg).forEach(n=>{
    if(y>p.H-26){ p=doc.page(); p.rect(0,0,p.W,40,C.band); p.text(40,27,'Hosts (cont.)',16,'F2',C.ink); y=60; header(); }
    const rgb=hex2rgb((FAMILY[n.fam]||FAMILY.other).color);
    p.rect(40,y-8,3,11,rgb);
    p.text(48,y,trunc(n.label,30),9,'F3',C.ink);
    p.text(250,y,KIND_LABEL[n.kind]||'host',9,'F1',C.ink2);
    p.text(360,y,trunc(n.vendor||'-',26),9,'F1',C.ink2);
    p.text(525,y,String(n.deg),9,'F1',C.ink2);
    p.text(580,y,String(n.rx+n.tx),9,'F1',C.ink2);
    p.text(660,y,trunc(Object.keys(n.protos).slice(0,4).join(', '),28),8.5,'F1',C.ink3);
    y+=14;
  });

  dl(doc.build(),(m.fileName||'capture').replace(/\.[^.]+$/,'')+'-report.pdf');
}
function trunc(s,n){ s=String(s); return s.length>n? s.slice(0,n-1)+'\u2026':s; }
function hex2rgb(h){ h=h.replace('#',''); return [parseInt(h.slice(0,2),16)/255,parseInt(h.slice(2,4),16)/255,parseInt(h.slice(4,6),16)/255]; }
