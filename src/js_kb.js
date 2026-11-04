/* ============================================================
   PROTOCOL KNOWLEDGE BASE
   Families group protocols by purpose and drive edge colour.
   Each OT protocol has a decoder that turns bytes into a plain
   English description ("Modbus: write 10 registers @40001").
   ============================================================ */

const FAMILY = {
  ot:      {name:'OT / ICS control', color:'#ff5d6c'},   // industrial control — highest interest
  ot_info: {name:'OT telemetry',     color:'#f6b24b'},   // read/monitor OT
  mgmt:    {name:'Management',        color:'#4fd1c5'},   // ssh/telnet/snmp/http admin
  name:    {name:'Naming / discovery',color:'#6cc9cf'},
  web:     {name:'Web / app',         color:'#8e7bef'},
  transfer:{name:'File / transfer',   color:'#5aa9e6'},
  infra:   {name:'Infra / net',       color:'#7fd17f'},
  other:   {name:'Other / unknown',   color:'#6c7f90'},
};

/* TCP/UDP service map.  fam = family key, ot flags industrial protocols,
   dec = optional deep decoder name. */
const PORTS = {
  // ---- OT / ICS ----
  502:   {name:'Modbus/TCP',   fam:'ot', dec:'modbus', why:'Industrial register/coil read-write — PLC process data & commands.'},
  44818: {name:'EtherNet/IP',  fam:'ot', dec:'enip',   why:'CIP over TCP — Rockwell/Allen-Bradley & ODVA device control.'},
  2222:  {name:'EtherNet/IP I/O',fam:'ot',dec:null,    why:'CIP implicit I/O messaging (UDP), real-time control data.'},
  20000: {name:'DNP3',         fam:'ot', dec:'dnp3',   why:'SCADA tele-control, common in power & water utilities.'},
  102:   {name:'S7comm / COTP',fam:'ot', dec:'s7',     why:'Siemens S7 PLC protocol — read/write/program/stop CPU.'},
  4840:  {name:'OPC-UA',       fam:'ot', dec:'opcua',  why:'Modern OT interoperability — browse/read/write/subscribe.'},
  34964: {name:'PROFINET CM',  fam:'ot', dec:null,     why:'PROFINET context manager — device setup for real-time I/O.'},
  2404:  {name:'IEC 60870-5-104',fam:'ot',dec:'iec104',why:'Tele-control for electrical substations.'},
  47808: {name:'BACnet/IP',    fam:'ot', dec:'bacnet', why:'Building automation — HVAC, access, metering.'},
  789:   {name:'Red Lion / Crimson',fam:'ot',dec:null, why:'HMI/controller config protocol.'},
  1962:  {name:'PCWorx',       fam:'ot', dec:null,     why:'Phoenix Contact PLC protocol.'},
  9600:  {name:'OMRON FINS',   fam:'ot', dec:null,     why:'Omron PLC memory read/write.'},
  5007:  {name:'Mitsubishi MELSEC',fam:'ot',dec:null,  why:'MELSEC/SLMP PLC protocol.'},
  1911:  {name:'Niagara Fox',  fam:'ot', dec:null,     why:'Tridium building-automation framework.'},
  // MMS (IEC 61850) typically 102 too; GOOSE/SV are L2
  // ---- OT telemetry / adjacent ----
  161:   {name:'SNMP',         fam:'ot_info',dec:'snmp',why:'Device monitoring & config polling.'},
  162:   {name:'SNMP-trap',    fam:'ot_info',dec:null, why:'Asynchronous device alerts.'},
  123:   {name:'NTP',          fam:'infra',dec:null,   why:'Time sync — critical for event correlation in OT.'},
  319:   {name:'PTP event',    fam:'ot_info',dec:null, why:'Precision time (IEEE-1588) for synchronised control.'},
  320:   {name:'PTP general',  fam:'ot_info',dec:null, why:'Precision time management messages.'},
  1883:  {name:'MQTT',         fam:'ot_info',dec:'mqtt',why:'Pub/sub telemetry, common in IIoT gateways.'},
  8883:  {name:'MQTT/TLS',     fam:'ot_info',dec:null, why:'Encrypted pub/sub telemetry.'},
  5683:  {name:'CoAP',         fam:'ot_info',dec:null, why:'Constrained-device REST telemetry.'},
  // ---- management ----
  22:    {name:'SSH',          fam:'mgmt',dec:null,    why:'Encrypted remote shell / admin.'},
  23:    {name:'Telnet',       fam:'mgmt',dec:null,    why:'PLAINTEXT remote shell — credentials exposed.'},
  3389:  {name:'RDP',          fam:'mgmt',dec:null,    why:'Windows remote desktop.'},
  5900:  {name:'VNC',          fam:'mgmt',dec:null,    why:'Remote framebuffer / HMI access.'},
  514:   {name:'Syslog',       fam:'mgmt',dec:null,    why:'Device log shipping.'},
  // ---- naming / discovery ----
  53:    {name:'DNS',          fam:'name',dec:'dns',   why:'Name resolution.'},
  5353:  {name:'mDNS',         fam:'name',dec:'dns',   why:'Zero-config local name discovery.'},
  137:   {name:'NetBIOS-NS',   fam:'name',dec:null,    why:'Legacy Windows name service.'},
  138:   {name:'NetBIOS-DGM',  fam:'name',dec:null,    why:'Legacy Windows datagrams.'},
  5355:  {name:'LLMNR',        fam:'name',dec:null,    why:'Link-local name resolution.'},
  1900:  {name:'SSDP',         fam:'name',dec:null,    why:'UPnP discovery.'},
  67:    {name:'DHCP-server',  fam:'name',dec:'dhcp',  why:'Address assignment.'},
  68:    {name:'DHCP-client',  fam:'name',dec:'dhcp',  why:'Address request.'},
  // ---- web / app ----
  80:    {name:'HTTP',         fam:'web',dec:'http',   why:'PLAINTEXT web / HMI / REST.'},
  443:   {name:'HTTPS/TLS',    fam:'web',dec:'tls',    why:'Encrypted web / API.'},
  8080:  {name:'HTTP-alt',     fam:'web',dec:'http',   why:'Alt web / proxy / HMI.'},
  8443:  {name:'HTTPS-alt',    fam:'web',dec:'tls',    why:'Alt encrypted web.'},
  1433:  {name:'MSSQL',        fam:'web',dec:null,     why:'Historian / database.'},
  3306:  {name:'MySQL',        fam:'web',dec:null,     why:'Database.'},
  5432:  {name:'PostgreSQL',   fam:'web',dec:null,     why:'Database.'},
  // ---- file / transfer ----
  21:    {name:'FTP',          fam:'transfer',dec:null,why:'PLAINTEXT file transfer — firmware/config.'},
  20:    {name:'FTP-data',     fam:'transfer',dec:null,why:'File transfer data channel.'},
  69:    {name:'TFTP',         fam:'transfer',dec:null,why:'Simple transfer — firmware/boot images.'},
  445:   {name:'SMB',          fam:'transfer',dec:null,why:'Windows file sharing.'},
  139:   {name:'SMB/NetBIOS',  fam:'transfer',dec:null,why:'Legacy Windows file sharing.'},
  2049:  {name:'NFS',          fam:'transfer',dec:null,why:'Unix file sharing.'},
};

/* Link-layer EtherTypes handled.  GOOSE / SV are IEC-61850 L2 OT. */
const ETHERTYPE = {
  0x0800:'ipv4',0x86dd:'ipv6',0x0806:'arp',0x8100:'vlan',0x88a8:'vlan',
  0x88b8:{name:'GOOSE',fam:'ot',note:'IEC-61850 GOOSE — fast substation trip/status, Layer-2 multicast.'},
  0x88ba:{name:'Sampled Values',fam:'ot',note:'IEC-61850 SV — raw measured current/voltage streams.'},
  0x88cc:{name:'LLDP',fam:'infra',dec:'lldp',note:'Link-layer discovery — devices announce their name, model, port and neighbours.'},
  0x8892:{name:'PROFINET RT',fam:'ot',note:'PROFINET real-time cyclic I/O, Layer-2.'},
  0x88f7:{name:'PTP (L2)',fam:'ot_info',note:'Precision time, Layer-2.'},
  0x8809:{name:'LACP/LAMP',fam:'infra',note:'Link aggregation / slow protocols (802.3ad).'},
  0x888e:{name:'EAPOL',fam:'infra',note:'802.1X port authentication (network access control).'},
  0x88e5:{name:'MACsec',fam:'infra',note:'802.1AE link-layer encryption.'},
  0x8906:'fcoe',0x8847:'mpls',0x8848:'mpls',
  0x8902:{name:'CFM',fam:'infra',note:'802.1ag connectivity fault management.'},
  0x8100:'vlan',0x9100:'vlan',
  0x22f3:{name:'TRILL',fam:'infra',note:'Transparent interconnect of lots of links.'},
  0x88e1:{name:'HomePlug',fam:'infra',note:'Powerline networking.'},
  0x8035:{name:'RARP',fam:'infra',note:'Reverse ARP (legacy address discovery).'},
  0x8863:{name:'PPPoE Disc',fam:'infra',note:'PPPoE discovery.'},0x8864:{name:'PPPoE',fam:'infra',note:'PPP over Ethernet session.'},
  0x6002:{name:'MOP',fam:'infra',note:'DEC maintenance operation protocol (legacy).'},
  0x88cd:{name:'SERCOS III',fam:'ot',note:'SERCOS III real-time motion bus, Layer-2.'},
  0x88a4:{name:'EtherCAT',fam:'ot',dec:'ethercat',note:'EtherCAT real-time fieldbus, Layer-2.'},
  0x8000:{name:'IS-IS',fam:'infra',note:'IS-IS routing.'},
  0xcccc:{name:'MRP',fam:'ot',note:'Media Redundancy Protocol — ring recovery, common in OT.'},
  0x80c4:{name:'Wellfleet/LACP',fam:'infra',note:'Legacy link control.'},
};

/* SNAP (LLC) OUI+PID -> protocol, for Cisco/Foundry L2 protocols that ride
   inside 802.3 LLC frames rather than EtherType. Keyed "oui:pid" hex. */
const SNAP_PROTO = {
  '00000c:2000':{name:'CDP',fam:'infra',dec:'cdp',note:'Cisco Discovery Protocol — device announces model, version, port, mgmt IP, neighbours.'},
  '00000c:2003':{name:'VTP',fam:'infra',note:'VLAN Trunking Protocol.'},
  '00000c:2004':{name:'DTP',fam:'infra',note:'Dynamic Trunking Protocol.'},
  '00000c:0102':{name:'CGMP',fam:'infra',note:'Cisco Group Management Protocol.'},
  '00000c:010b':{name:'PVSTP+',fam:'infra',note:'Per-VLAN Spanning Tree.'},
  '00000c:0104':{name:'UDLD',fam:'infra',note:'Unidirectional Link Detection.'},
  '00e02b:00bb':{name:'EDP',fam:'infra',note:'Extreme Discovery Protocol.'},
  '0000f8:0001':{name:'FDP',fam:'infra',note:'Foundry Discovery Protocol.'},
};

/* STP is carried in LLC with DSAP/SSAP 0x42. Bridge PDUs. */
const STP_NOTE={name:'STP/RSTP',fam:'infra',note:'Spanning Tree — loop prevention / topology on switches.'};

/* ---- Modbus function codes with plain-English intent ---- */
const MODBUS_FC = {
  1:['Read Coils','reads on/off outputs (e.g. relay/valve states)'],
  2:['Read Discrete Inputs','reads on/off inputs (e.g. limit switches)'],
  3:['Read Holding Registers','reads 16-bit values (setpoints, process values)'],
  4:['Read Input Registers','reads 16-bit sensor values (read-only)'],
  5:['Write Single Coil','switches one output ON/OFF — a control action'],
  6:['Write Single Register','sets one value — a control/parameter change'],
  15:['Write Multiple Coils','switches several outputs — control action'],
  16:['Write Multiple Registers','sets several values — control/config change'],
  22:['Mask Write Register','modifies bits in a register'],
  23:['Read/Write Registers','reads and writes in one transaction'],
  43:['Read Device ID','identifies vendor/model/firmware'],
  8:['Diagnostics','diagnostic / loopback — can restart comms or clear counters'],
};

/* ---- S7comm function area meanings ---- */
const S7_FUNC = {
  0x04:['Read Var','reads PLC memory / data blocks'],
  0x05:['Write Var','writes PLC memory — a control or config change'],
  0x1a:['Request Download','starts downloading a program block to the PLC'],
  0x1b:['Download Block','transfers program block content'],
  0x1c:['Download Ended','finishes a program download'],
  0x1d:['Start Upload','begins reading a block out of the PLC'],
  0x1e:['Upload','reads block content from the PLC'],
  0x1f:['End Upload','finishes a block upload'],
  0x28:['PLC Control','runs a control command (e.g. program a block)'],
  0x29:['PLC Stop','STOPS the CPU — halts the process'],
  0xf0:['Setup Comm','negotiates the S7 session'],
};
const S7_SZL_HINT='CPU function / system state read';

/* ---- DNP3 function codes ---- */
const DNP3_FC = {
  0:['Confirm','acknowledges a message'],
  1:['Read','reads points from an outstation'],
  2:['Write','writes to an outstation — control/config'],
  3:['Select','arms an output for operate (step 1 of 2)'],
  4:['Operate','executes a previously selected output — a control action'],
  5:['Direct Operate','directly actuates an output — a control action'],
  13:['Cold Restart','RESTARTS the outstation device'],
  14:['Warm Restart','warm-restarts the outstation'],
  18:['Stop Application','stops the outstation application'],
  20:['Enable Unsolicited','enables spontaneous reporting'],
  21:['Disable Unsolicited','disables spontaneous reporting'],
  23:['Delay Measurement','measures comms delay'],
};

/* ---- IEC-104 type IDs (subset) ---- */
const IEC104_TYPE = {
  45:['Single command','switches a single output — control action'],
  46:['Double command','operates a device (open/close) — control action'],
  47:['Regulating step','step a regulator up/down'],
  48:['Set-point (normalised)','sets an analog setpoint — control'],
  49:['Set-point (scaled)','sets an analog setpoint — control'],
  50:['Set-point (float)','sets an analog setpoint — control'],
  100:['Interrogation','polls all current values'],
  101:['Counter interrogation','polls accumulated counters'],
  103:['Clock sync','synchronises device clock'],
  105:['Reset process','RESETS the remote process'],
  1:['Single-point info','reports an on/off status'],
  13:['Measured float','reports a measured value'],
  30:['Single-point w/ time','status change with timestamp'],
};

/* ---- EtherNet/IP (CIP) command & service hints ---- */
const ENIP_CMD = {
  0x65:['Register Session','opens an EtherNet/IP session'],
  0x66:['UnRegister Session','closes the session'],
  0x6f:['Send RR Data','unconnected CIP request (explicit messaging)'],
  0x70:['Send Unit Data','connected CIP data (implicit/cyclic)'],
  0x63:['List Identity','discovers device identity'],
  0x64:['List Services','lists available services'],
};
const CIP_SVC = {
  0x01:['Get Attributes All','reads all attributes of an object'],
  0x0e:['Get Attribute Single','reads one attribute (a value)'],
  0x10:['Set Attribute Single','writes one attribute — a control/config change'],
  0x4c:['Read Tag','reads a controller tag value'],
  0x4d:['Write Tag','writes a controller tag — a control action'],
  0x52:['Unconnected Send','routes a request to another device'],
  0x06:['Reset','RESETS the device'],
  0x05:['Start','starts the device'],
  0x07:['Stop','stops the device'],
};

/* ============================================================
   EXTENDED OT PROTOCOL TABLE  — every protocol gets a decoder
   hook so "we don't know what we'll get" is covered. Each entry
   notes whether a secure/authenticated variant exists and how to
   tell from the wire.
   ============================================================ */
const PORTS_EXT = {
  // PROFINET family
  34962:{name:'PROFINET RT-UDP',fam:'ot',dec:'profinet',why:'PROFINET real-time over UDP.'},
  34963:{name:'PROFINET Alarm', fam:'ot',dec:'profinet',why:'PROFINET alarm channel.'},
  // IEC-61850 MMS already on 102 (S7 shares); handle via decoder content
  3480: {name:'OPC-UA (alt)',   fam:'ot',dec:'opcua',  why:'OPC-UA on alternate port.'},
  // Foundation Fieldbus / HART-IP
  5094: {name:'HART-IP',        fam:'ot',dec:null,     why:'HART over IP — field device data.'},
  1089: {name:'FF Annunciation',fam:'ot',dec:null,     why:'Foundation Fieldbus.'},
  1090: {name:'FF Config',      fam:'ot',dec:null,     why:'Foundation Fieldbus config.'},
  1091: {name:'FF Device',      fam:'ot',dec:null,     why:'Foundation Fieldbus device.'},
  // CODESYS
  1217: {name:'CODESYS',        fam:'ot',dec:null,     why:'CODESYS runtime — soft-PLC programming.'},
  11740:{name:'CODESYS V3',     fam:'ot',dec:null,     why:'CODESYS V3 runtime/programming.'},
  // ProConOS / KW
  20547:{name:'ProConOS',       fam:'ot',dec:null,     why:'ProConOS PLC runtime.'},
  // Beckhoff ADS
  48898:{name:'Beckhoff ADS',   fam:'ot',dec:null,     why:'TwinCAT ADS — Beckhoff PLC access.'},
  // GE-SRTP
  18245:{name:'GE SRTP',        fam:'ot',dec:null,     why:'GE PLC service request protocol.'},
  18246:{name:'GE SRTP',        fam:'ot',dec:null,     why:'GE PLC service request protocol.'},
  // Yokogawa Vnet/IP
  1324: {name:'Vnet/IP',        fam:'ot',dec:null,     why:'Yokogawa DCS control network.'},
  // Emerson ROC
  4000: {name:'Emerson ROC',    fam:'ot',dec:null,     why:'Emerson ROC/FloBoss RTU protocol.'},
};
Object.assign(PORTS, PORTS_EXT);

/* ---- broader IT / enterprise protocol coverage ---- */
const PORTS_IT = {
  88:    {name:'Kerberos',     fam:'mgmt',    why:'Windows/AD authentication.'},
  464:   {name:'Kerberos-pw',  fam:'mgmt',    why:'Kerberos password change.'},
  389:   {name:'LDAP',         fam:'mgmt',    why:'Directory access (Active Directory).'},
  636:   {name:'LDAPS',        fam:'mgmt',    why:'Encrypted directory access.'},
  3268:  {name:'LDAP-GC',      fam:'mgmt',    why:'AD Global Catalog.'},
  3269:  {name:'LDAP-GC/TLS',  fam:'mgmt',    why:'AD Global Catalog (TLS).'},
  1812:  {name:'RADIUS-auth',  fam:'mgmt',    why:'Network access authentication.'},
  1813:  {name:'RADIUS-acct',  fam:'mgmt',    why:'Network access accounting.'},
  49:    {name:'TACACS+',      fam:'mgmt',    why:'Device admin authentication (Cisco).'},
  5985:  {name:'WinRM-HTTP',   fam:'mgmt',    why:'Windows remote management (plaintext).'},
  5986:  {name:'WinRM-HTTPS',  fam:'mgmt',    why:'Windows remote management (TLS).'},
  135:   {name:'MS-RPC',       fam:'mgmt',    why:'Windows RPC endpoint mapper.'},
  593:   {name:'RPC-HTTP',     fam:'mgmt',    why:'RPC over HTTP.'},
  25:    {name:'SMTP',         fam:'web', dec:null, why:'Email relay (plaintext).'},
  587:   {name:'SMTP-sub',     fam:'web',     why:'Email submission.'},
  465:   {name:'SMTPS',        fam:'web',     why:'Encrypted email submission.'},
  110:   {name:'POP3',         fam:'web',     why:'Mailbox retrieval (plaintext).'},
  995:   {name:'POP3S',        fam:'web',     why:'Encrypted mailbox retrieval.'},
  143:   {name:'IMAP',         fam:'web',     why:'Mailbox access (plaintext).'},
  993:   {name:'IMAPS',        fam:'web',     why:'Encrypted mailbox access.'},
  3389:  {name:'RDP',          fam:'mgmt',    why:'Windows remote desktop.'},
  5222:  {name:'XMPP-client',  fam:'web',     why:'Chat/messaging.'},
  5060:  {name:'SIP',          fam:'web',     why:'VoIP call signalling (plaintext).'},
  5061:  {name:'SIP-TLS',      fam:'web',     why:'Encrypted VoIP signalling.'},
  1719:  {name:'H.323-RAS',    fam:'web',     why:'VoIP registration.'},
  1720:  {name:'H.323',        fam:'web',     why:'VoIP call setup.'},
  5190:  {name:'AIM/ICQ',      fam:'web',     why:'Legacy messaging.'},
  443:   {name:'HTTPS/TLS',    fam:'web', dec:'tls', why:'Encrypted web / API.'},
  80:    {name:'HTTP',         fam:'web', dec:'http',why:'PLAINTEXT web / HMI / REST.'},
  8000:  {name:'HTTP-alt',     fam:'web', dec:'http',why:'Alt web / app server.'},
  5672:  {name:'AMQP',         fam:'ot_info', why:'Message queue (RabbitMQ/IIoT brokers).'},
  5671:  {name:'AMQPS',        fam:'ot_info', why:'Encrypted message queue.'},
  9092:  {name:'Kafka',        fam:'ot_info', why:'Event streaming / historian ingest.'},
  6379:  {name:'Redis',        fam:'web',     why:'In-memory datastore / cache.'},
  27017: {name:'MongoDB',      fam:'web',     why:'Document database.'},
  1521:  {name:'Oracle DB',    fam:'web',     why:'Oracle historian/database.'},
  1434:  {name:'MSSQL-mon',    fam:'web',     why:'SQL Server browser.'},
  11211: {name:'Memcached',    fam:'web',     why:'Memory cache.'},
  2375:  {name:'Docker',       fam:'mgmt',    why:'Docker API (plaintext — dangerous if exposed).'},
  2376:  {name:'Docker-TLS',   fam:'mgmt',    why:'Docker API (TLS).'},
  6443:  {name:'Kubernetes',   fam:'mgmt',    why:'Kubernetes API server.'},
  179:   {name:'BGP',          fam:'infra',   why:'Inter-router routing.'},
  646:   {name:'LDP',          fam:'infra',   why:'MPLS label distribution.'},
  3784:  {name:'BFD',          fam:'infra',   why:'Fast link failure detection.'},
  520:   {name:'RIP',          fam:'infra',   why:'Legacy routing.'},
  1985:  {name:'HSRP',         fam:'infra',   why:'Cisco gateway redundancy.'},
  3222:  {name:'GLBP',         fam:'infra',   why:'Cisco gateway load balancing.'},
  5353:  {name:'mDNS',         fam:'name',dec:'dns', why:'Zero-config local name discovery.'},
  3702:  {name:'WS-Discovery', fam:'name',    why:'Web Services discovery (printers/cameras/NVRs).'},
  5357:  {name:'WSD',          fam:'name',    why:'Web Services for Devices.'},
  1900:  {name:'SSDP',         fam:'name',    why:'UPnP discovery.'},
  5355:  {name:'LLMNR',        fam:'name',    why:'Link-local name resolution.'},
  548:   {name:'AFP',          fam:'transfer',why:'Apple file sharing.'},
  873:   {name:'rsync',        fam:'transfer',why:'File sync.'},
  111:   {name:'RPC-portmap',  fam:'infra',   why:'ONC RPC portmapper (NFS etc).'},
  199:   {name:'SMUX',         fam:'ot_info', why:'SNMP multiplexing.'},
  9100:  {name:'JetDirect',    fam:'transfer',why:'Raw printing (HP JetDirect).'},
  631:   {name:'IPP',          fam:'transfer',why:'Internet printing.'},
  853:   {name:'DoT',          fam:'name',    why:'DNS over TLS.'},
  784:   {name:'DoQ',          fam:'name',    why:'DNS over QUIC.'},
};
// don't overwrite existing richer entries; only fill gaps
for(const p in PORTS_IT){ if(!PORTS[p]) PORTS[p]=PORTS_IT[p]; }

/* Security / version notes keyed by protocol display name. Shown in the
   detail panel so the user sees "secure vs plaintext / which version". */
const PROTO_SECURITY = {
  'Modbus/TCP':{secure:false,note:'Modbus/TCP has no authentication or encryption. A separate Modbus/TLS exists (port 802) and the 2018 security spec is rare; if you see plain 502 it is unprotected.'},
  'EtherNet/IP':{secure:false,note:'Classic EtherNet/IP is unauthenticated. CIP Security (TLS/DTLS) exists but is uncommon; plain 44818 is unprotected.'},
  'S7comm / COTP':{secure:false,note:'Classic S7comm (S7-300/400) is unauthenticated. S7comm-Plus (S7-1200/1500) adds integrity/anti-replay but not confidentiality — detected from the protocol id byte.'},
  'DNP3':{secure:false,note:'Base DNP3 is unauthenticated. DNP3 Secure Authentication (SAv5) adds challenge-response; detectable from aggressive-mode / auth objects.'},
  'IEC 60870-5-104':{secure:false,note:'IEC-104 is plaintext. IEC-62351 can wrap it in TLS; plain 2404 is unprotected.'},
  'OPC-UA':{secure:null,note:'OPC-UA security depends on the session: None, Sign, or SignAndEncrypt — read from the ClientHello / OpenSecureChannel. Detected per session.'},
  'BACnet/IP':{secure:false,note:'BACnet/IP is unauthenticated by default. BACnet/SC (secure connect, WebSocket+TLS) is the secure variant.'},
  'PROFINET RT':{secure:false,note:'PROFINET RT is Layer-2 and unauthenticated. PROFINET Security is emerging but rarely deployed.'},
  'Telnet':{secure:false,note:'Plaintext — credentials visible on the wire. Use SSH instead.'},
  'FTP':{secure:false,note:'Plaintext — credentials and files visible. Use SFTP/FTPS.'},
  'HTTP':{secure:false,note:'Plaintext. Use HTTPS.'},
  'SNMP':{secure:null,note:'v1/v2c use a cleartext community string; v3 adds auth+privacy. Version detected from the message header.'},
};

/* PROFINET frame-id ranges (L2 RT) -> meaning */
function profinetFrameMeaning(fid){
  if(fid>=0x0100&&fid<=0x6FF) return ['PTCP / sync','clock sync for isochronous I/O'];
  if(fid>=0x8000&&fid<=0xBFFF) return ['Cyclic RT I/O','real-time process data exchange'];
  if(fid>=0xC000&&fid<=0xFBFF) return ['Cyclic RT (high prio)','high-priority real-time I/O'];
  if(fid===0xFC01) return ['Alarm high','a high-priority device alarm'];
  if(fid===0xFE01) return ['Alarm low','a low-priority device alarm'];
  if(fid===0xFEFC||fid===0xFEFD) return ['DCP identify','device discovery/identification'];
  if(fid===0xFEFE||fid===0xFEFF) return ['DCP hello/get/set','device configuration (name/IP assignment)'];
  if(fid>=0xFF00&&fid<=0xFF43) return ['PTCP delay','cable delay measurement'];
  return ['PROFINET RT','real-time I/O frame'];
}
