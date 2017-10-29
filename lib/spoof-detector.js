var args = require('./args.js');
var pcap = require('pcap');
var ip = require('ip');
var tcp = require('./tcp.js');
var logger = require('./logger.js');
var macaddress = require('macaddress');
const util = require('util');
const fs = require('fs');
var my_mac = '';
macaddress.one(args.params.iface, function (err, mac) {
  my_mac = mac;
});

var pendingSYNs = {};

if (!fs.existsSync(args.params.hostdb)){
    fs.writeFileSync(args.params.hostdb, JSON.stringify({}));
}
var validatedHostsRaw = fs.readFileSync(args.params.hostdb);
var validatedHosts = JSON.parse(validatedHostsRaw);

//send a TCP SYN to the host and wait for 2 sec to receive a RST or ACK
function validateHost(host_ip, host_mac){
  logger.log('[?] Validating: '+host_ip+' is at '+host_mac, 'debug');
  if(validatedHosts[host_ip] != undefined){ //host is already validated
    if(validatedHosts[host_ip] != host_mac){
      logger.log('[-] Validation Failed : '+host_ip+' at '+pendingSYNs[address][0]);
    }else{
      logger.log('[+] Already Validated: '+host_ip+' is at '+validatedHosts[host_ip], 'debug');
    }
    return;
  }
  var host_port = parseInt(Math.random()*(65535-1024) + 1024);
  var src_ip = ip.address();
  var src_mac = my_mac;
  if(!tcp.sendSYN(args.params.iface, src_mac, host_mac, src_ip, 31337, host_ip, host_port)){
    logger.log('[?] Sent TCP SYN to '+host_ip+':'+host_port+' at '+host_mac, 'debug');
    pendingSYNs[host_ip +':'+ host_port] = [host_mac, Date.now()];
    setTimeout(handleTimedOutTCPSYNs, 2000, host_ip, host_port);
  }
}

//No RST or ACK received for 2 sec
function handleTimedOutTCPSYNs(host_ip, host_port){
  if(pendingSYNs[host_ip + ':' + host_port] != undefined){//No RST or ACK received for this, most probably spoofing underway
    logger.log('[-] Validation Failed : '+host_ip+' at '+pendingSYNs[host_ip + ':' + host_port][0]);
    delete pendingSYNs[host_ip + ':' + host_port];
  }
}

//some RST or ACK arrive at port 31337
function handleTCPPacket(ipPacket){
  var host_ip = ipPacket.saddr.addr.join('.');
  var host_port = ipPacket.payload.sport;
  if(pendingSYNs[host_ip +':'+ host_port] != undefined){
    if(ipPacket.payload.flags.rst){
      logger.log('[?] Received RST from '+host_ip+':'+host_port, 'debug');
    }else{
      logger.log('[?] Received ACK from '+host_ip+':'+host_port, 'debug');
    }
    logger.log('[+] Validated: '+host_ip+' is at '+pendingSYNs[host_ip +':'+ host_port][0], 'debug');
    validatedHosts[host_ip] = pendingSYNs[host_ip +':'+ host_port][0];
    //Write to database on new validation
    fs.writeFileSync(args.params.hostdb, JSON.stringify(validatedHosts));
    delete pendingSYNs[host_ip +':'+ host_port];
    //TODO: clear timeout on validation
  }
}

//convert mac address(array in packet) to string
function arrToMac(m){
  var mac = m[0].toString(16) + ':' + m[1].toString(16) + ':' + m[2].toString(16) + ':' + m[3].toString(16) + ':' + m[4].toString(16) + ':' + m[5].toString(16);
  return mac;
}

//match source and dst mac address in mac header and arp header
function checkHeaders(ethrPacket){
  var arpPacket = ethrPacket.payload;
  //checking source mac address
  if(arrToMac(ethrPacket.shost.addr) !==  arrToMac(arpPacket.sender_ha.addr)) return false;
  //checking dst mac address
  if(arrToMac(ethrPacket.dhost.addr) !== 'ff:ff:ff:ff:ff:ff'){//not a gratuitous reply
    if(arrToMac(ethrPacket.dhost.addr) !== arrToMac(arpPacket.target_ha.addr)) return false;
  }
  return true;
}

//we're interested only in ARP replies
function filterARPPackets(arp){
  var my_ip = ip.address();
  var sender_ip = arp.sender_pa.addr.join('.');
  if(arp.operation == 1) return false;
  if(arp.operation == 2 && sender_ip == my_ip) return false;
  return true;
}

function handleARPPacket(etherPacket){
  arpPacket = etherPacket.payload;
  if(!filterARPPackets(arpPacket)) return;
  if(!checkHeaders(etherPacket)){
    logger.log('Mac and ARP header mismatch');
    return;
  }
  validateHost(arpPacket.sender_pa.addr.join('.'), arrToMac(arpPacket.sender_ha.addr));
}

//Capture ARP(replies) and TCP(ACK or RST) packets
function startCapture(){
  var arpSession = pcap.createSession(args.params.iface, 'arp or (tcp dst port 31337)');
  arpSession.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    if(packet.payload.ethertype == 0x0800){//TCP
      handleTCPPacket(packet.payload.payload);
    }else if(packet.payload.ethertype == 0x0806){//ARP
      handleARPPacket(packet.payload);
    }
  });
}

process.on('uncaughtException', function(err) {
	fs.appendFile(args.params.log, err + '\n');
});

exports.startCapture = startCapture;
