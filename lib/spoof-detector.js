var pcap = require('pcap');
var ip = require('ip');
var tcp = require('./tcp.js');
const util = require('util');
var pendingSYNs = {};

function validateHost(host_ip, host_mac){
  console.log('[?] Validating: %s is at %s', host_ip, host_mac);
  var host_port = parseInt(Math.random()*(65535-1024) + 1024);
  var src_ip = ip.address();
  var src_mac = process.argv[2];
  if(!tcp.sendSYN(src_mac, host_mac, src_ip, 31337, host_ip, host_port)){
    console.log('[?] Sent TCP SYN to %s:%s at %s', host_ip, host_port, host_mac);
    pendingSYNs[host_ip +':'+ host_port] = host_mac;
  }
}

function handleTCPPacket(ipPacket){
  var host_ip = ipPacket.saddr.addr.join('.');
  var host_port = ipPacket.payload.sport;
  if(pendingSYNs[host_ip +':'+ host_port] != undefined){
    if(ipPacket.payload.flags.rst){
      console.log('[?] Received RST from %s:%s', host_ip, host_port);
    }else{
      console.log('[?] Received ACK from %s:%s', host_ip, host_port);
    }
    console.log('[+] Validated: %s is at %s\n', host_ip, pendingSYNs[host_ip +':'+ host_port]);
    delete pendingSYNs[host_ip +':'+ host_port];
    console.log(pendingSYNs);
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
  var arpSession = pcap.createSession('enp7s0', 'arp or (tcp dst port 31337)');
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
