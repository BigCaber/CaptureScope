# CaptureScope

Completely AI generated. I prompted this front-end project to use on OT/ICS assignments. I could not find much useful visualization tools tailored for my needs. Or they asked money for their crappy app. So this is the outcome. Use as you wish.

src folder is only there to show you how AI developed the project. **CaptureScope.html** is the single file version.

A single-file, dependency-free, offline pcap/pcapng topology viewer for IT and OT/ICS networks.
Drop a capture in the browser and get an interactive host graph with vendor resolution,
OT protocol decoding in plain English, anomaly findings, and PNG/PDF/session export.

Nothing is uploaded — all parsing happens locally in the browser. Safe for air-gapped use.

## Build
    python3 src/assemble.py      # produces CaptureScope.html

## Source layout
- src/js_kb.js        protocol knowledge base (ports, OT function codes, families)
- src/js_parser.js    pcap/pcapng parser + link/IP/transport dissectors
- src/js_classify.js  protocol classifier, deep OT decoders, anomaly detection
- src/js_model.js     host-graph model builder, role assignment, force layout
- src/js_render.js    canvas renderer (zoom/pan/icons/labels/grouping)
- src/js_pdf.js       minimal zero-dependency PDF writer + report builder
- src/js_app.js       app controller, panels, exports, session save/load
- src/oui.b64         embedded MAC vendor database (gzip+base64)
