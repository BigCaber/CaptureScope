/* ============================================================
   RENDERER  — canvas graph: zoom/pan, icons, sublabels,
   truncation, grouping, selection, tooltips, export draw
   ============================================================ */

/* Device icons — drawn centred in a -10..10 box. Cleaner glyphs. */
const ICONS = {
  plc(c){ // controller rack with terminals
    c.beginPath();c.rect(-8,-6,16,12);c.stroke();
    c.beginPath();c.moveTo(-8,-1.5);c.lineTo(8,-1.5);c.stroke();
    c.beginPath();for(let i=0;i<3;i++){const x=-5+i*5;c.moveTo(x,-6);c.lineTo(x,-9);}c.stroke();
    c.beginPath();c.arc(-4.5,2.5,0.9,0,7);c.arc(0,2.5,0.9,0,7);c.arc(4.5,2.5,0.9,0,7);c.fillStyle=c.strokeStyle;c.fill();
  },
  controller(c){ c.beginPath();c.rect(-8,-6,16,12);c.stroke();
    c.beginPath();c.moveTo(-4.5,-2.5);c.lineTo(4.5,-2.5);c.moveTo(-4.5,1.5);c.lineTo(4.5,1.5);c.stroke();
    c.beginPath();c.arc(5.5,-4,1,0,7);c.fillStyle=c.strokeStyle;c.fill(); },
  ied(c){ // shield (protection relay)
    c.beginPath();c.moveTo(0,-9);c.lineTo(7,-5.5);c.lineTo(7,2);c.quadraticCurveTo(7,7,0,9);c.quadraticCurveTo(-7,7,-7,2);c.lineTo(-7,-5.5);c.closePath();c.stroke();
    c.beginPath();c.moveTo(-2.5,0);c.lineTo(-0.5,3);c.lineTo(3,-3);c.stroke(); },
  scada(c){ // monitor with waveform
    c.beginPath();c.rect(-9,-7,18,12);c.stroke();
    c.beginPath();c.moveTo(-6,0);c.lineTo(-3,0);c.lineTo(-1.5,-3.5);c.lineTo(1.5,3.5);c.lineTo(3,0);c.lineTo(6,0);c.stroke();
    c.beginPath();c.moveTo(-3,8);c.lineTo(3,8);c.moveTo(0,5);c.lineTo(0,8);c.stroke(); },
  server(c){ c.beginPath();c.rect(-7,-9,14,18);c.stroke();
    c.beginPath();c.moveTo(-7,-3);c.lineTo(7,-3);c.moveTo(-7,3);c.lineTo(7,3);c.stroke();
    c.beginPath();c.arc(-4,-6,1,0,7);c.arc(-4,0,1,0,7);c.arc(-4,6,1,0,7);c.fillStyle=c.strokeStyle;c.fill(); },
  workstation(c){ c.beginPath();c.rect(-9,-7,18,12);c.stroke();
    c.beginPath();c.moveTo(-3,5);c.lineTo(-4,9);c.lineTo(4,9);c.lineTo(3,5);c.moveTo(-6,9);c.lineTo(6,9);c.stroke(); },
  router(c){ c.beginPath();c.rect(-9,-4,18,8);c.stroke();
    c.beginPath();c.moveTo(-5,-4);c.lineTo(-2,-9);c.moveTo(-2,-9);c.lineTo(-4,-8);c.moveTo(-2,-9);c.lineTo(-1,-7);
    c.moveTo(5,4);c.lineTo(2,9);c.moveTo(2,9);c.lineTo(4,8);c.moveTo(2,9);c.lineTo(1,7);c.stroke(); },
  cloud(c){ c.beginPath();c.arc(-4,1,4,Math.PI*0.5,Math.PI*1.5);c.arc(0,-3,5,Math.PI,0);c.arc(5,1,4,Math.PI*1.5,Math.PI*0.5);c.closePath();c.stroke(); },
  multicast(c){ c.beginPath();c.arc(0,0,2.5,0,7);c.stroke();for(let a=0;a<3;a++){const r=4.5+a*2;c.beginPath();c.arc(0,0,r,-0.9,0.9);c.stroke();c.beginPath();c.arc(0,0,r,Math.PI-0.9,Math.PI+0.9);c.stroke();} },
  broadcast(c){ c.beginPath();c.arc(0,0,2.5,0,7);c.stroke();for(let a=0;a<8;a++){const an=a/8*6.283;c.beginPath();c.moveTo(Math.cos(an)*4,Math.sin(an)*4);c.lineTo(Math.cos(an)*8,Math.sin(an)*8);c.stroke();} },
  l2dev(c){ c.beginPath();c.rect(-9,-5,18,10);c.stroke();c.beginPath();for(let i=0;i<4;i++){const x=-6+i*4;c.moveTo(x,-5);c.lineTo(x,5);}c.stroke(); },
  switch(c){ // switch: box with crossing arrows
    c.beginPath();c.rect(-9,-6,18,12);c.stroke();
    c.beginPath();c.moveTo(-5,-2);c.lineTo(5,-2);c.moveTo(3,-4);c.lineTo(5,-2);c.lineTo(3,0);
    c.moveTo(5,2);c.lineTo(-5,2);c.moveTo(-3,0);c.lineTo(-5,2);c.lineTo(-3,4);c.stroke(); },
  host(c){ c.beginPath();c.arc(0,0,6.5,0,7);c.stroke();c.beginPath();c.arc(0,0,2,0,7);c.fillStyle=c.strokeStyle;c.fill(); },
};
const KIND_LABEL={plc:'PLC',controller:'Controller',ied:'IED',scada:'SCADA',
  server:'Server',workstation:'Workstation',router:'Gateway',cloud:'External',
  switch:'Switch',multicast:'Multicast',broadcast:'Broadcast',l2dev:'L2 device',host:'Host'};

function Renderer(canvas, model, host){
  const ctx=canvas.getContext('2d');
  let DPR=Math.min(window.devicePixelRatio||1,2);
  const view={x:0,y:0,s:1};
  let hover=null, sel=null, dragNode=null, panning=false, px=0,py=0;
  const expanded=new Set();
  const hiddenFams=new Set();
  let searchHit=new Set();
  let groupBy=null;          // null | 'subnet' | 'role' | 'vendor'
  let groups=[];             // computed hulls
  const selSet=new Set();    // multi-selected node ids
  let boxSel=null;           // {x0,y0,x1,y1} in world coords during box drag
  let showPorts=true;        // draw service-port labels on edges
  let labelMode='always';    // 'always' | 'hubs' | 'off'
  let showPhysical=true;     // draw LLDP/CDP physical links
  let dragStartWorld=null;   // for group drag

  function css(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim();}
  function resize(){ DPR=Math.min(window.devicePixelRatio||1,2);
    const r=canvas.getBoundingClientRect(); canvas.width=r.width*DPR; canvas.height=r.height*DPR; draw(); }
  function worldToScreen(x,y){return [(x-view.x)*view.s,(y-view.y)*view.s];}
  function screenToWorld(sx,sy){return [sx/view.s+view.x,sy/view.s+view.y];}

  function fit(pad=70){ const b=model.bounds; const r=canvas.getBoundingClientRect();
    const bw=(b.maxx-b.minx)||1,bh=(b.maxy-b.miny)||1;
    view.s=Math.max(0.05,Math.min(Math.min((r.width-pad*2)/bw,(r.height-pad*2)/bh),3));
    view.x=b.minx-(r.width/view.s-bw)/2; view.y=b.miny-(r.height/view.s-bh)/2; draw(); }

  function nodeRadius(n){ return 11*(0.8+Math.min(1.6,Math.log2(2+n.deg)*0.3)); }

  // ---- visible set with hub truncation ----
  let vis=visibleSet();
  function visibleSet(){
    const show=new Set(); const TRUNC=12; const hiddenLeaves=new Map();
    model.nodeArr.forEach(n=>{ if(!hiddenFams.has(n.fam)) show.add(n.id); });
    model.nodeArr.forEach(n=>{
      if(n.deg>TRUNC&&!expanded.has(n.id)){
        const pe=model.edgeArr.filter(e=>e.a===n||e.b===n).sort((a,b)=>b.count-a.count);
        pe.slice(TRUNC).forEach(e=>{ const o=(e.a===n?e.b:e.a); if(o.deg===1) hiddenLeaves.set(o.id,1); });
      }
    });
    hiddenLeaves.forEach((_,id)=>show.delete(id));
    const vedges=model.edgeArr.filter(e=>show.has(e.a.id)&&show.has(e.b.id)&&!hiddenFams.has(e.fam));
    return {show,vedges,hiddenLeaves};
  }
  function recomputeVisible(){ vis=visibleSet(); if(groupBy)computeGroups(); }

  // ---- grouping: convex-hull-ish bubbles around members ----
  function groupKey(n){ if(groupBy==='subnet')return n.subnet||'—';
    if(groupBy==='role')return KIND_LABEL[n.kind]||n.kind;
    if(groupBy==='vendor')return n.vendor||'unknown vendor'; return null; }
  function computeGroups(){
    groups=[]; if(!groupBy)return;
    const by={}; model.nodeArr.forEach(n=>{ if(!vis.show.has(n.id))return; const k=groupKey(n); (by[k]=by[k]||[]).push(n); });
    const palette=['#4fd1c5','#f6b24b','#8e7bef','#5aa9e6','#7fd17f','#ff5d6c','#6cc9cf','#d98b5f','#b07fe0','#9fb0c0'];
    let i=0;
    for(const k in by){ const mem=by[k]; if(mem.length<2){i++;continue;}
      let cx=0,cy=0; mem.forEach(n=>{cx+=n.x;cy+=n.y;}); cx/=mem.length;cy/=mem.length;
      let rad=0; mem.forEach(n=>{rad=Math.max(rad,Math.hypot(n.x-cx,n.y-cy));});
      groups.push({key:k,cx,cy,r:rad+42,color:palette[i%palette.length],count:mem.length}); i++; }
  }

  function roundRect(c,x,y,w,h,r){c.beginPath();c.moveTo(x+r,y);c.arcTo(x+w,y,x+w,y+h,r);c.arcTo(x+w,y+h,x,y+h,r);c.arcTo(x,y+h,x,y,r);c.arcTo(x,y,x+w,y,r);c.closePath();}

  function draw(){
    const r=canvas.getBoundingClientRect();
    ctx.setTransform(DPR,0,0,DPR,0,0); ctx.clearRect(0,0,r.width,r.height);
    ctx.save(); ctx.translate(-view.x*view.s,-view.y*view.s); ctx.scale(view.s,view.s);

    // group bubbles behind everything
    if(groupBy){ groups.forEach(g=>{ ctx.beginPath();ctx.arc(g.cx,g.cy,g.r,0,7);
      ctx.fillStyle=g.color+'14';ctx.fill(); ctx.setLineDash([6/view.s,5/view.s]);
      ctx.strokeStyle=g.color+'66';ctx.lineWidth=1.3/view.s;ctx.stroke();ctx.setLineDash([]);
      ctx.fillStyle=g.color;ctx.font=(13/view.s>6?13:12)+'px var(--fontmono)';ctx.textAlign='left';ctx.textBaseline='bottom';
      ctx.globalAlpha=.9;ctx.fillText(g.key+'  ('+g.count+')',g.cx-g.r+8,g.cy-g.r+ (16/view.s));ctx.globalAlpha=1; }); }

    // physical links from LLDP/CDP (cabling) — drawn under traffic edges,
    // distinct dashed white-ish line so real wiring is visible.
    if(showPhysical && model.physical && model.physical.length){
      ctx.save(); ctx.setLineDash([2/view.s,4/view.s]); ctx.lineCap='round';
      model.physical.forEach(pl=>{ if(!vis.show.has(pl.a.id)||!vis.show.has(pl.b.id))return;
        ctx.strokeStyle=css('--ink3'); ctx.globalAlpha=0.55; ctx.lineWidth=2.4/Math.max(view.s,0.4);
        ctx.beginPath();ctx.moveTo(pl.a.x,pl.a.y);ctx.lineTo(pl.b.x,pl.b.y);ctx.stroke(); });
      ctx.restore(); ctx.globalAlpha=1;
    }
    // edges
    ctx.lineCap='round';
    vis.vedges.forEach(e=>{ const col=FAMILY[e.fam]?FAMILY[e.fam].color:css('--line2');
      const w=Math.min(6,0.6+Math.log2(1+e.count)*0.7)/Math.max(view.s,0.4);
      const faded=(sel&&e.a!==sel&&e.b!==sel)||(searchHit.size&&!searchHit.has(e.a.id)&&!searchHit.has(e.b.id));
      ctx.globalAlpha=faded?0.1:0.72; ctx.strokeStyle=col; ctx.lineWidth=w;
      ctx.beginPath();ctx.moveTo(e.a.x,e.a.y);ctx.lineTo(e.b.x,e.b.y);ctx.stroke(); });
    ctx.globalAlpha=1;
    // edge port labels — constant screen size so they stay readable zoomed out
    if(showPorts){ ctx.textAlign='center';ctx.textBaseline='middle';
      const pinv=1/view.s; const pf=Math.min(10*pinv,10*2.2);
      vis.vedges.forEach(e=>{ if(!e.portLabel)return;
        const faded=(sel&&e.a!==sel&&e.b!==sel);
        if(faded) return;
        const mx=(e.a.x+e.b.x)/2, my=(e.a.y+e.b.y)/2;
        ctx.font=pf.toFixed(1)+'px var(--fontmono)'; const tw=ctx.measureText(e.portLabel).width;
        ctx.globalAlpha=0.92; ctx.fillStyle=css('--bg');
        roundRect(ctx,mx-tw/2-3*pinv,my-6.5*pinv,tw+6*pinv,13*pinv,3*pinv); ctx.fill();
        ctx.globalAlpha=1; ctx.fillStyle=FAMILY[e.fam]?FAMILY[e.fam].color:css('--ink2');
        ctx.fillText(e.portLabel,mx,my); });
      ctx.globalAlpha=1; }

    // nodes
    model.nodeArr.forEach(n=>{ if(!vis.show.has(n.id))return;
      const faded=(sel&&sel!==n&&!sel.peers.has(n.id))||(searchHit.size&&!searchHit.has(n.id));
      const R=nodeRadius(n); const fam=FAMILY[n.fam]||FAMILY.other;
      const multi=selSet.has(n.id);
      ctx.globalAlpha=faded?0.22:1;
      if(multi){ ctx.beginPath();ctx.arc(n.x,n.y,R+7/view.s,0,7);ctx.fillStyle=css('--accent')+'33';ctx.fill();
        ctx.lineWidth=2/view.s;ctx.strokeStyle=css('--accent');ctx.stroke(); }
      else if(n===sel||n===hover){ ctx.beginPath();ctx.arc(n.x,n.y,R+6/view.s,0,7);ctx.fillStyle=fam.color+'22';ctx.fill(); }
      ctx.beginPath();ctx.arc(n.x,n.y,R,0,7);ctx.fillStyle=css('--panel');ctx.fill();
      ctx.lineWidth=(n.special?2.8:2.2)/Math.max(view.s,0.5)+1; ctx.strokeStyle=fam.color;
      if(n.special){ctx.setLineDash([3/view.s,2.5/view.s]);} ctx.stroke(); ctx.setLineDash([]);
      // pin indicator
      if(n.pinned){ ctx.beginPath();ctx.arc(n.x-R*0.78,n.y-R*0.78,5/view.s+1.5,0,7);ctx.fillStyle=css('--warn');ctx.fill();
        ctx.fillStyle=css('--bg');ctx.font=(7/view.s+2)+'px var(--fontui)';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('📌'.length?'•':'•',n.x-R*0.78,n.y-R*0.78); }
      const sc=R/11*0.95; ctx.save();ctx.translate(n.x,n.y);ctx.scale(sc,sc);
      ctx.lineWidth=1.4/sc/Math.max(view.s,0.6);ctx.strokeStyle=fam.color;ctx.lineJoin='round';
      (ICONS[n.kind]||ICONS.host)(ctx); ctx.restore();
      if(n.deg>12&&!expanded.has(n.id)){ ctx.beginPath();ctx.arc(n.x+R*0.78,n.y-R*0.78,6/view.s+2,0,7);
        ctx.fillStyle=css('--accent');ctx.fill(); ctx.fillStyle='#07140f';
        ctx.font=(8/view.s+3)+'px var(--fontmono)';ctx.textAlign='center';ctx.textBaseline='middle';
        ctx.fillText('+',n.x+R*0.78,n.y-R*0.78+0.5); }
      ctx.globalAlpha=1;
    });

    // labels + sublabels (type · vendor)
    ctx.textAlign='center';ctx.textBaseline='top';
    // Labels are drawn at a near-constant SCREEN size by counter-scaling the
    // font against the zoom, so they stay readable when zoomed out instead of
    // shrinking to nothing. labelMode controls how many show:
    //   'always' (default) = every visible node keeps its IP/MAC + tag
    //   'hubs'   = only hubs + focused nodes (clean overview)
    //   'off'    = none
    const inv=1/view.s;                       // world units per screen pixel
    model.nodeArr.forEach(n=>{ if(!vis.show.has(n.id))return;
      const faded=(sel&&sel!==n&&!sel.peers.has(n.id));
      const R=nodeRadius(n);
      const focused = n===sel||n===hover||selSet.has(n.id)||searchHit.has(n.id);
      let show;
      if(labelMode==='off') show=focused;
      else if(labelMode==='hubs') show=focused||n.deg>=6;
      else show=true;                          // 'always'
      if(!show)return;
      ctx.globalAlpha=faded?0.3:1;
      const txt=n.label.length>28?n.label.slice(0,27)+'…':n.label;
      // font size in world units = constant screen px * inv (clamped so it
      // doesn't get absurdly large when fully zoomed in)
      const fpx=Math.min(12*inv, 12*2.2);      // ~12px on screen, capped
      const subpx=Math.min(10*inv, 10*2.2);
      const pad=4*inv, bh=(fpx+3), ly=n.y+R+4*inv;
      ctx.font=fpx.toFixed(1)+'px var(--fontmono)'; const tw=ctx.measureText(txt).width;
      ctx.fillStyle=css('--panel');ctx.globalAlpha=faded?0.3:0.82; roundRect(ctx,n.x-tw/2-pad,ly-1*inv,tw+pad*2,bh,3*inv);ctx.fill();
      ctx.globalAlpha=faded?0.4:1;ctx.fillStyle=css('--ink');ctx.textAlign='center';ctx.textBaseline='top';ctx.fillText(txt,n.x,ly);
      // tag line (role · vendor) — bolder and tinted by family so it stands out
      const fam2=FAMILY[n.fam]||FAMILY.other;
      const q=n.roleConf==='low'?'?':''; const role=(KIND_LABEL[n.kind]||'host')+q;
      ctx.font='600 '+subpx.toFixed(1)+'px var(--fontui)';
      const rw=ctx.measureText(role).width;
      const vend=n.vendor?'  '+n.vendor:'';
      ctx.font=subpx.toFixed(1)+'px var(--fontui)'; const vw=vend?ctx.measureText(vend).width:0;
      const totalW=rw+vw; const sy=ly+fpx+3*inv;
      ctx.globalAlpha=faded?0.35:1;
      // role in family colour, bold
      ctx.font='600 '+subpx.toFixed(1)+'px var(--fontui)'; ctx.fillStyle=fam2.color; ctx.textAlign='left';
      ctx.fillText(role, n.x-totalW/2, sy);
      // vendor in muted ink
      if(vend){ ctx.font=subpx.toFixed(1)+'px var(--fontui)'; ctx.fillStyle=css('--ink2'); ctx.fillText(vend, n.x-totalW/2+rw, sy); }
      ctx.textAlign='center';
      ctx.globalAlpha=1;
    });
    // box selection rectangle
    if(boxSel){ const x=Math.min(boxSel.x0,boxSel.x1),y=Math.min(boxSel.y0,boxSel.y1);
      const w=Math.abs(boxSel.x1-boxSel.x0),h=Math.abs(boxSel.y1-boxSel.y0);
      ctx.fillStyle=css('--accent')+'1a';ctx.fillRect(x,y,w,h);
      ctx.setLineDash([5/view.s,4/view.s]);ctx.strokeStyle=css('--accent');ctx.lineWidth=1.2/view.s;ctx.strokeRect(x,y,w,h);ctx.setLineDash([]); }
    ctx.restore();
  }

  function nodeAt(sx,sy){ const [wx,wy]=screenToWorld(sx,sy); let best=null,bd=1e9;
    model.nodeArr.forEach(n=>{ if(!vis.show.has(n.id))return; const R=nodeRadius(n)+4;
      const d=(n.x-wx)**2+(n.y-wy)**2; if(d<R*R&&d<bd){bd=d;best=n;} }); return best; }

  // ---- interaction ----
  canvas.addEventListener('pointerdown',ev=>{ canvas.setPointerCapture(ev.pointerId);
    const r=canvas.getBoundingClientRect(); const sx=ev.clientX-r.left,sy=ev.clientY-r.top;
    const n=nodeAt(sx,sy);
    if(n && !ev.shiftKey){ dragNode=n; dragNode._dragged=false; dragStartWorld=screenToWorld(sx,sy); }
    else if(ev.shiftKey){ // start a box selection
      const [wx,wy]=screenToWorld(sx,sy); boxSel={x0:wx,y0:wy,x1:wx,y1:wy}; }
    else { panning=true; canvas.classList.add('dragging'); }
    px=ev.clientX;py=ev.clientY; });
  canvas.addEventListener('pointermove',ev=>{ const r=canvas.getBoundingClientRect();
    const sx=ev.clientX-r.left,sy=ev.clientY-r.top;
    if(boxSel){ const [wx,wy]=screenToWorld(sx,sy); boxSel.x1=wx;boxSel.y1=wy; draw(); return; }
    if(dragNode){ const [wx,wy]=screenToWorld(sx,sy);
      // if dragging a multi-selected node, move the whole selection
      if(selSet.has(dragNode.id)&&selSet.size>1&&dragStartWorld){ const ddx=wx-dragStartWorld[0],ddy=wy-dragStartWorld[1];
        selSet.forEach(id=>{const m=model.nodes[id];if(m){m.x+=ddx;m.y+=ddy;}}); dragStartWorld=[wx,wy]; }
      else { dragNode.x=wx;dragNode.y=wy; }
      dragNode._dragged=true; if(groupBy)computeGroups(); draw(); return; }
    if(panning){ view.x-=(ev.clientX-px)/view.s;view.y-=(ev.clientY-py)/view.s;px=ev.clientX;py=ev.clientY;draw();return; }
    const n=nodeAt(sx,sy); if(n!==hover){hover=n;canvas.style.cursor=n?'pointer':'grab';draw();}
    if(n)host.showTip(n,ev.clientX,ev.clientY); else host.hideTip(); });
  canvas.addEventListener('pointerup',ev=>{ const r=canvas.getBoundingClientRect();
    const sx=ev.clientX-r.left,sy=ev.clientY-r.top;
    if(boxSel){ // finalize box selection
      const x0=Math.min(boxSel.x0,boxSel.x1),x1=Math.max(boxSel.x0,boxSel.x1);
      const y0=Math.min(boxSel.y0,boxSel.y1),y1=Math.max(boxSel.y0,boxSel.y1);
      if(!ev.ctrlKey&&!ev.metaKey) selSet.clear();
      model.nodeArr.forEach(m=>{ if(vis.show.has(m.id)&&m.x>=x0&&m.x<=x1&&m.y>=y0&&m.y<=y1) selSet.add(m.id); });
      boxSel=null; host.onMultiSelect([...selSet]); draw(); return; }
    if(dragNode){ if(!dragNode._dragged){
      const R=nodeRadius(dragNode); const [wx,wy]=screenToWorld(sx,sy);
      const bx=dragNode.x+R*0.78,by=dragNode.y-R*0.78;
      if(dragNode.deg>12&&((wx-bx)**2+(wy-by)**2)<(10/view.s)**2){
        if(expanded.has(dragNode.id))expanded.delete(dragNode.id);else expanded.add(dragNode.id); recomputeVisible();
      } else if(ev.ctrlKey||ev.metaKey){ // toggle in multi-select
        if(selSet.has(dragNode.id))selSet.delete(dragNode.id);else selSet.add(dragNode.id); host.onMultiSelect([...selSet]);
      } else { selSet.clear(); setSel(sel===dragNode?null:dragNode); }
      draw();
    } dragNode=null; dragStartWorld=null; }
    else if(panning){ const moved=Math.abs(ev.clientX-px)+Math.abs(ev.clientY-py);
      if(moved<3){ if(selSet.size){selSet.clear();host.onMultiSelect([]);} if(sel)setSel(null); draw(); } }
    panning=false;canvas.classList.remove('dragging'); });
  canvas.addEventListener('dblclick',ev=>{ const r=canvas.getBoundingClientRect();
    const n=nodeAt(ev.clientX-r.left,ev.clientY-r.top);
    if(n){ n.pinned=!n.pinned; draw(); } });
  canvas.addEventListener('pointerleave',()=>{hover=null;host.hideTip();draw();});
  canvas.addEventListener('wheel',ev=>{ ev.preventDefault(); const r=canvas.getBoundingClientRect();
    const sx=ev.clientX-r.left,sy=ev.clientY-r.top; const [wx,wy]=screenToWorld(sx,sy);
    view.s=Math.max(0.05,Math.min(8,view.s*Math.exp(-ev.deltaY*0.0016)));
    const [nx,ny]=screenToWorld(sx,sy); view.x+=wx-nx;view.y+=wy-ny;draw(); },{passive:false});

  function setSel(n){ sel=n; host.onSelect(n); }
  function zoomBy(f){ const r=canvas.getBoundingClientRect(),cx=r.width/2,cy=r.height/2;
    const [wx,wy]=screenToWorld(cx,cy); view.s=Math.max(0.05,Math.min(8,view.s*f));
    const [nx,ny]=screenToWorld(cx,cy); view.x+=wx-nx;view.y+=wy-ny;draw(); }
  function setSearch(q){ searchHit=new Set();
    if(q){ const ql=q.toLowerCase(); model.nodeArr.forEach(n=>{ const hay=(n.label+' '+[...n.ips].join(' ')+' '+[...n.macs].join(' ')+' '+(n.vendor||'')+' '+(n.hostname||'')).toLowerCase();
      if(hay.includes(ql))searchHit.add(n.id); });
      if(searchHit.size){ let fx=0,fy=0,c=0; model.nodeArr.forEach(n=>{if(searchHit.has(n.id)){fx+=n.x;fy+=n.y;c++;}});
        if(c){const rct=canvas.getBoundingClientRect();view.x=fx/c-rct.width/view.s/2;view.y=fy/c-rct.height/view.s/2;} } }
    draw(); }
  function toggleFam(f){ if(hiddenFams.has(f))hiddenFams.delete(f);else hiddenFams.add(f); recomputeVisible();draw(); }
  function selectById(id){ const n=model.nodes[id]||null; setSel(n);
    if(n){const r=canvas.getBoundingClientRect();view.x=n.x-r.width/view.s/2;view.y=n.y-r.height/view.s/2;} draw(); }
  function relayout(){ model.nodeArr.forEach(n=>{if(!n.pinned)n.x=undefined;}); layout(model,{w:1600,h:1000}); recomputeVisible();fit(); }
  function setGroup(g){ groupBy=(g==='none'?null:g); computeGroups(); draw(); }
  function deOverlap(){ separate(model,300,18); computeBounds(model); if(groupBy)computeGroups(); fit(); }
  function togglePorts(){ showPorts=!showPorts; draw(); return showPorts; }
  function cycleLabels(){ labelMode = labelMode==='always'?'hubs':labelMode==='hubs'?'off':'always'; draw(); return labelMode; }
  function togglePhysical(){ showPhysical=!showPhysical; draw(); return showPhysical; }
  function pinSelected(v){ selSet.forEach(id=>{const m=model.nodes[id];if(m)m.pinned=v;}); draw(); }
  function clearMulti(){ selSet.clear(); host.onMultiSelect([]); draw(); }
  function selectMany(ids){ selSet.clear(); ids.forEach(id=>selSet.add(id)); draw(); }

  window.addEventListener('resize',resize); resize(); fit();

  return {draw,fit,zoomBy,setSearch,toggleFam,selectById,relayout,resize,setGroup,
    deOverlap,togglePorts,cycleLabels,togglePhysical,pinSelected,clearMulti,selectMany,
    get labelMode(){return labelMode;}, get showPhysical(){return showPhysical;},
    clearSel:()=>{setSel(null);selSet.clear();draw();},
    get view(){return view;}, get hiddenFams(){return hiddenFams;}, get groupBy(){return groupBy;},
    get selCount(){return selSet.size;}, get showPorts(){return showPorts;},
    renderToContext:(c,w,h)=>exportDraw(c,w,h), _model:model };

  function exportDraw(c,w,h){ const b=model.bounds,pad=60;
    const bw=(b.maxx-b.minx)||1,bh=(b.maxy-b.miny)||1;
    const s=Math.min((w-pad*2)/bw,(h-pad*2)/bh); const ox=b.minx-(w/s-bw)/2,oy=b.miny-(h/s-bh)/2;
    c.save();c.translate(-ox*s,-oy*s);c.scale(s,s);
    if(groupBy){ groups.forEach(g=>{c.beginPath();c.arc(g.cx,g.cy,g.r,0,7);c.fillStyle=g.color+'14';c.fill();
      c.strokeStyle=g.color+'66';c.lineWidth=1.3;c.stroke();
      c.fillStyle=g.color;c.font='13px monospace';c.textAlign='left';c.fillText(g.key+' ('+g.count+')',g.cx-g.r+8,g.cy-g.r+16);}); }
    if(showPhysical&&model.physical&&model.physical.length){ c.save();c.setLineDash([2,4]);
      model.physical.forEach(pl=>{ if(!vis.show.has(pl.a.id)||!vis.show.has(pl.b.id))return;
        c.strokeStyle=css('--ink3');c.globalAlpha=0.55;c.lineWidth=2.4;
        c.beginPath();c.moveTo(pl.a.x,pl.a.y);c.lineTo(pl.b.x,pl.b.y);c.stroke();}); c.restore();c.globalAlpha=1; }
    vis.vedges.forEach(e=>{const col=FAMILY[e.fam]?FAMILY[e.fam].color:'#445';
      c.globalAlpha=0.7;c.strokeStyle=col;c.lineWidth=Math.min(6,0.6+Math.log2(1+e.count)*0.7)/Math.max(s,0.4);
      c.beginPath();c.moveTo(e.a.x,e.a.y);c.lineTo(e.b.x,e.b.y);c.stroke();});
    c.globalAlpha=1;
    // port labels on edges
    if(showPorts){ c.textAlign='center';c.textBaseline='middle';
      vis.vedges.forEach(e=>{ if(!e.portLabel)return; const mx=(e.a.x+e.b.x)/2,my=(e.a.y+e.b.y)/2;
        c.font='10px monospace';const tw=c.measureText(e.portLabel).width;
        c.fillStyle=css('--bg');c.globalAlpha=0.9;roundRect(c,mx-tw/2-3,my-7,tw+6,13,3);c.fill();c.globalAlpha=1;
        c.fillStyle=FAMILY[e.fam]?FAMILY[e.fam].color:css('--ink2');c.fillText(e.portLabel,mx,my); }); }
    model.nodeArr.forEach(n=>{ if(!vis.show.has(n.id))return; const R=nodeRadius(n);const fam=FAMILY[n.fam]||FAMILY.other;
      c.beginPath();c.arc(n.x,n.y,R,0,7);c.fillStyle=css('--panel');c.fill();c.lineWidth=2.2;c.strokeStyle=fam.color;c.stroke();
      const sc=R/11*0.95;c.save();c.translate(n.x,n.y);c.scale(sc,sc);c.lineWidth=1.5/sc;c.strokeStyle=fam.color;c.lineJoin='round';(ICONS[n.kind]||ICONS.host)(c);c.restore();});
    c.textAlign='center';c.textBaseline='top';
    model.nodeArr.forEach(n=>{ if(!vis.show.has(n.id))return; if(n.deg<3&&s<0.5)return; const R=nodeRadius(n);
      c.font='12px monospace';c.fillStyle=css('--ink');const t=n.label.length>26?n.label.slice(0,25)+'…':n.label;c.fillText(t,n.x,n.y+R+4);
      c.font='10px sans-serif';c.fillStyle=css('--ink3');c.fillText((KIND_LABEL[n.kind]||'host')+(n.roleConf==='low'?'?':'')+(n.vendor?' · '+n.vendor:''),n.x,n.y+R+19);});
    c.restore(); }
}
