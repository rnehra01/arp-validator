var pcap = require('pcap');
var raw = require("raw-socket");
var ip = require('ip');
const util = require('util');

function macToArr (macAddr) {
  var macArr = macAddr.split(':');
  var x;
  for (x in macArr){
    macArr[x] = '0x' + macArr[x];
  }
  return macArr;
}

function pktToBuffer(pkt){
  var x;
  var pktArr = [];
  for (x in pkt){
    pktArr = pktArr.concat(pkt[x]);
  }
  var pktBuffer = new Buffer(pktArr);
  return pktBuffer;
}

function sendSYN(iface, src_mac, dst_mac, src_ip, src_port, dst_ip, dst_port){
  SYNSession = pcap.createSession(iface, 'tcp');
  var etherHeader = {
      'dst' : macToArr(dst_mac),
      'src' : macToArr(src_mac),
      'ether_type' : [0x08, 0x00]
  };

  var etherBuffer = pktToBuffer(etherHeader);

  var ipBuffer = new Buffer([
      0x45,                   // IP: Version (0x45 is IPv4)
      0x00,                   // IP: Differentiated Services Field
      0x00,0x3c,              // IP: Total Length
      0x00,0x00,              // IP: Identification
      0x40,                   // IP: Flags (0x20 Don't Fragment)
      0x00,                   // IP: Fragment Offset
      0x40,                   // IP: TTL (0x40 is 64)
      0x06,                   // IP: protocol (ICMP=1, IGMP=2, TCP=6, UDP=17, static value)
      0x00,0x00,              // IP: checksum for IP part of this packet
      0x00,0x00,0x00,0x00,    // IP: ip src
      0x00,0x00,0x00,0x00,    // IP: ip dst
  ]);

  ipBuffer.writeUInt16BE(parseInt(Math.random()*0xffff), 4); // IP: set identification
  ip.toBuffer(src_ip, ipBuffer, 12);
  ip.toBuffer(dst_ip, ipBuffer, 16);

  raw.writeChecksum(ipBuffer, 10, raw.createChecksum(ipBuffer));

  var tcpBuffer = new Buffer([
      0x00,0x00,              // TCP: src port
      0x00,0x00,              // TCP: dst port
      0x00,0x00,0x00,0x00,    // TCP: sequence number
      0x00,0x00,0x00,0x00,    // TCP: acquitment number
      0x00,0x02,              // TCP: header length, flags
      0x72,0x10,              // TCP: window
      0x00,0x00,              // TCP: checksum for TCP part of this packet
      0x00,0x00,              // TCP: ptr urgent
      0x02,0x04,              // TCP: options
      0x05,0xb4,              // TCP: padding
      0x04,0x02,              // TCP: SACK Permitted (4) Option
      0x08,0x0a,              // TCP: TSval, Length
      0x01,0x75,0xdd,0xe8,    // value
      0x00,0x00,0x00,0x00,    // TSecr
      0x01,                   // TCP: NOP
      0x03,0x03,0x07          // TCP: Window scale
  ]);

  tcpBuffer.writeUInt32BE(parseInt(Math.random()*0xffffffff), 4);
  tcpBuffer.writeUInt8(tcpBuffer.length << 2, 12);
  tcpBuffer.writeUInt16BE(src_port, 0);
  tcpBuffer.writeUInt16BE(dst_port, 2);

  var pseudoBuffer = new Buffer([
      0x00,0x00,0x00,0x00,    // IP: ip src
      0x00,0x00,0x00,0x00,    // IP: ip dst
      0x00,
      0x06, // IP: protocol
      (tcpBuffer.length >> 8) & 0xff, tcpBuffer.length & 0xff
  ]);
  ip.toBuffer(src_ip, pseudoBuffer, 0); // IP: src_ip
  ip.toBuffer(dst_ip, pseudoBuffer, 4); // IP: dst_ip
  pseudoBuffer = Buffer.concat([pseudoBuffer, tcpBuffer]);
  raw.writeChecksum(tcpBuffer, 16, raw.createChecksum(pseudoBuffer));
  var buffer = Buffer.concat([etherBuffer, ipBuffer, tcpBuffer]);
  //console.log(util.inspect(session, {showHidden: false, depth: null}));
  try{
    SYNSession.inject(buffer);
    SYNSession.close();
    return 0;
  }catch(e){
    console.log("Error sending packet:", e);
    SYNSession.close();
    return -1;
  }
}

exports.sendSYN = sendSYN;
