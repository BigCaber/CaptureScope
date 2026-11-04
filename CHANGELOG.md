# Changelog

## v0.4.0
- **Broader IT protocol coverage**: Kerberos, LDAP/LDAPS, RADIUS, TACACS+, WinRM, MS-RPC,
  SMTP/IMAP/POP3 (+TLS), SIP/H.323 VoIP, RDP, AMQP, Kafka, Redis, MongoDB, Oracle, Docker,
  Kubernetes, BGP/LDP/BFD/HSRP/GLBP, WS-Discovery/WSD, IPP/JetDirect, DoT/DoQ and more.
- **Broader L2 coverage**: STP/RSTP, CDP, VTP, DTP, UDLD, EDP, FDP, LACP, EAPOL (802.1X),
  MACsec, MRP (OT ring redundancy), EtherCAT, SERCOS III, PPPoE, RARP, and IEEE reserved
  groups — including 802.3 LLC/SNAP frame parsing, not just EtherType.
- **Device self-announcement folded into the asset (LLDP/CDP)**: the tool now parses LLDP
  and CDP TLVs and attaches what a device says about itself — hostname, model, firmware/
  description, its port, management IP, and declared capabilities — to that same asset's
  detail and the Assets tab and CSV (not as a separate node). Announced names become the
  host label; announced capabilities drive role typing (e.g. "announced itself as a switch").
- **Physical links (cabling) from LLDP/CDP neighbours**: when a device announces to a
  directly-wired neighbour, that physical connection is drawn as a distinct dashed link,
  layered under the traffic edges. Toggle with the new "Cabling" button; listed per asset
  under "Physically connected".
- **Bolder role tags**: the role label (PLC/Server/Switch...) is now semibold and tinted by
  protocol-family colour so it stands out instead of fading into grey.

## v0.3.2
- **Labels, ports and tags stay visible when zoomed out.** They are now drawn at a
  constant on-screen size (counter-scaled against zoom) instead of shrinking away, so
  IP addresses, port labels (TCP/UDP) and role/vendor tags remain readable at every zoom
  level. Added a "Labels" toggle to cycle all / hubs-only / off for when you want a clean
  shapes-only overview.

## v0.3.1
- **Fixed "Re-arrange" crowding.** The de-overlap now separates each node's full
  label footprint (disc + its two text lines), not just the circle, because the labels
  were what collided on screen. Separation is interleaved into the layout and converges
  to zero overlaps. Added strong hub-to-hub repulsion so dense clusters spread into
  distinct stars instead of piling their labels in the centre (verified: 5 hubs x 12
  nodes lay out as 5 clean, well-separated clusters). Labels are now gated by zoom and
  node importance, so the zoomed-out overview is clean shapes + colour and detail appears
  as you zoom in.

## v0.3.0
- **High-quality export**: PNG now exports at selectable resolution (2048 / 4096 / 8192 px)
  with antialiasing; added true-vector **SVG export** (infinite zoom, print-ready); PDF embeds
  the graph at higher DPI.
- **Canvas manageability**: collision separation so nodes never overlap; shift-drag **box-select**,
  ctrl-click to add to selection, **group-drag** of a multi-selection, double-click to **pin**
  a node (Re-arrange leaves pinned nodes put), and a **De-overlap** button that nudges nodes apart
  without re-running the whole layout.
- **Cleaner vendor names**: strips postal addresses and corporate suffixes and canonicalises
  aliases ("Hangzhou H3C Technologies Co., Limited" -> "H3C"). Vendors are categorised
  (network / OT / virtualization) and this feeds role inference.
- **Vendor-aware roles + confidence**: a network-equipment vendor that sends LLDP/STP/SNMP or
  has no IP is classed as a **Switch/Gateway**, not a Server. Every role now carries a
  high/medium/low **confidence** and is marked with "?" when low, so inferred guesses are
  no longer shown as fact.
- **Port labels on the canvas**: each link shows its dominant service port and transport
  (e.g. TCP/502, UDP/53). The detail panel lists every service port per peer with direction
  (-> / <-) and TCP/UDP.
- **Assets tab**: a full inventory of every host (IP/MAC/vendor/role+reason/served ports/
  protocols/versions), filterable by role and subnet, with **CSV export**.

## v0.2.0
- Streaming parser (500 MB+), node sublabels, explainable roles, protocol version/security
  detection, full OT + PROFINET decode, grouping, special-address notes, deselect, session save/load.

## v0.1.0
- Baseline: pcap/pcapng topology, embedded MAC vendor DB, OT protocol decoding, anomaly
  findings, PNG + PDF export. Single dependency-free HTML file.
