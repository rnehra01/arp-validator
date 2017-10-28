var pcap = require('pcap');
var ip = require('ip');
var tcp = require('./tcp.js');
var logger = require('./logger.js');
var macaddress = require('macaddress');
const util = require('util');
const fs = require('fs');
var my_mac = '';
macaddress.one(process.argv[2], function (err, mac) {
  my_mac = mac;
});

var pendingSYNs = {};

if (!fs.existsSync(process.argv[3])){
    fs.writeFileSync(process.argv[3], JSON.stringify({}));
}
var validatedHostsRaw = fs.readFileSync(process.argv[3]);
var validatedHosts = JSON.parse(validatedHostsRaw);

function validateHost(host_ip, host_mac){
  logger.log('[?] Validating: '+host_ip+' is at '+host_mac, 'debug');
  if(validatedHosts[host_ip] != undefined){ //host is already validated
    if(validatedHosts[host_ip] != host_mac){
      logger.log('[-] Validation Failed : '+address+' at '+pendingSYNs[address]);
    }else{
      logger.log('[+] Already Validated: '+host_ip+' is at '+validatedHosts[host_ip], 'debug');
    }
    return;
  }
  var host_port = parseInt(Math.random()*(65535-1024) + 1024);
  var src_ip = ip.address();
  var src_mac = my_mac;
  if(!tcp.sendSYN(process.argv[2], src_mac, host_mac, src_ip, 31337, host_ip, host_port)){
    logger.log('[?] Sent TCP SYN to '+host_ip+':'+host_port+' at '+host_mac, 'debug');
    pendingSYNs[host_ip +':'+ host_port] = [host_mac, Date.now()];
    setTimeout(handleTimedOutTCPSYNs, 2000, host_ip +':'+ host_port);
  }
}

function handleTimedOutTCPSYNs(address){
  if(pendingSYNs[address] != undefined){//No RST or ACK received for this, most probably spoofing underway
    logger.log('[-] Validation Failed : '+address+' at '+pendingSYNs[address]);
    delete pendingSYNs[address];
  }
}

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
    fs.writeFileSync(process.argv[3], JSON.stringify(validatedHosts));
    delete pendingSYNs[host_ip +':'+ host_port];
    //TODO: clear timeout on validation
  }
}

function handleARPPacket(arp){
  var m = arp.sender_ha.addr;
  var mac = m[0].toString(16) + ':' + m[1].toString(16) + ':' + m[2].toString(16) + ':' + m[3].toString(16) + ':' + m[4].toString(16) + ':' + m[5].toString(16);
  validateHost(arp.sender_pa.addr.join('.'), mac);
}

function filterARPPackets(arp){
  var my_ip = ip.address();
  var sender_ip = arp.sender_pa.addr.join('.');
  if(arp.operation == 1) return false;
  if(arp.operation == 2 && sender_ip == my_ip) return false;
  return true;
}

function startCapture(){
  var arpSession = pcap.createSession(process.argv[2], 'arp or (tcp dst port 31337)');
  arpSession.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    if(packet.payload.ethertype == 0x0800){//TCP
      handleTCPPacket(packet.payload.payload);
    }else if(packet.payload.ethertype == 0x0806){//ARP
      if(filterARPPackets(packet.payload.payload)){
        handleARPPacket(packet.payload.payload);
      }
    }
  });
}

exports.startCapture = startCapture;
