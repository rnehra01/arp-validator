var pcap = require('pcap');
session = pcap.createSession('wlp6s0', 'arp');

function ipToArr (ipAddr) {
  var ipArr = ipAddr.split('.');
  var x;
  for (xm in ipArr) {
    ipArr[x] = ipArr[x];
  }
  return ipArr;
}

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

//Type = 1 for ARP request
//Type = 2 for ARP Reply
function sendARP(src_ip, src_mac, dst_ip, dst_mac, type){
  var etherHeader = {
      'dst' : macToArr(dst_mac),
      'src' : macToArr(src_mac),
      'ether_type' : [0x08, 0x06]
  };
  var etherBuffer = pktToBuffer(etherHeader);

  var op;
  if(type == 1) op = 0x01; //Request
  else op = 0x02; //Reply

  var arpRequest = {
    'hw_type'  : [0x00, 0x01],
    'proto_type' : [0x08, 0x00],
    'hw_len' : 0x06,
    'proto_len' : 0x04,
    'op' : [0x00, op],
    'src_mac' : macToArr(src_mac),
    'src_ip' : ipToArr(src_ip),
    'dst_mac' : macToArr(dst_mac),
    'dst_ip' : ipToArr(dst_ip)
  }
  var arpBuffer = pktToBuffer(arpRequest);
  var buffer = Buffer.concat([etherBuffer, arpBuffer]);

  try{
    session.inject(buffer, buffer.length);
    session.close();
  }catch(e){
    console.log("Error sending packet:", e);
    session.close();
  }
}

sendARP('192.168.43.219', 'e4:f8:9c:c5:a2:60', '192.168.43.159', 'f4:06:69:97:97:99', 2);
