var args = require('./args.js');
var pcap = require('pcap');
var ip = require('ip');
var tcp = require('./tcp.js');
var arp = require('./arp.js');
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
	if(validatedHosts[host_ip] === host_mac){//lets check current situation matches with validated one
	    logger.log('[+] Already Validated: '+host_ip+' is at '+validatedHosts[host_ip], 'debug');
	}else{
	    logger.log('[-] Validation Failed : '+host_ip+' at '+host_mac);
	}
	return;
    }
    //Host has not validated yet, let's do it
    var host_port = parseInt(Math.random()*(65535-1024) + 1024);
    var src_ip = ip.address();
    logger.log("SRC IP:"+src_ip);
    var src_mac = my_mac;
    if(!tcp.sendSYN(args.params.iface, src_mac, host_mac, src_ip, 31337, host_ip, host_port)){
	logger.log('[?] Sent TCP SYN to '+host_ip+':'+host_port+' at '+host_mac, 'debug');
	if(!pendingSYNs[host_ip].hasOwnProperty('data')){
	    //This is first ARP Reply, Store port to which TCP SYN is sent and wait for 2 sec
	    var timeout = setTimeout(handleTimedOut, 2000,  host_ip);
	    pendingSYNs[host_ip]['data'] = {}
	    pendingSYNs[host_ip]['data'][host_port] = {'mac': host_mac, 'rst_ack': false};
	    pendingSYNs[host_ip]['timeout'] = timeout;
	}
	else{
	    //Another ARP Reply, another TCP SYN sent, wait for 2 sec and clear previour timeout 
	    clearTimeout(pendingSYNs[host_ip]['timeout']);
	    pendingSYNs[host_ip]['data'][host_port] = {'mac': host_mac, 'rst_ack': false};
	    var timeout = setTimeout(handleTimedOut, 2000, host_ip);
	    pendingSYNs[host_ip]['timeout'] = timeout; 
	}
    }
}

//Max time for reply of TCP/SYN has reached
function handleTimedOut(host_ip){
    var count_rst_acks = 0;
    var last_mac = '';
    for(var key in pendingSYNs[host_ip]['data']){
	if(pendingSYNs[host_ip]['data'][key]['rst_ack']){
	    count_rst_acks++;
	    last_mac = pendingSYNs[host_ip]['data'][key]['mac'];
	}
    }
    
    if(count_rst_acks > 1){
	//Attacker as well as Real host is replying to TCP SYNs, that means attacker has customized its stack
	logger.log('[-] Validation Failed (customized network stack) : '+host_ip);
    }else if(count_rst_acks === 1){
	//Got only 1 ACK/RST, so rest are attackers  
	logger.log('[+] Validated : '+host_ip, 'debug');
	validatedHosts[host_ip] = last_mac;
	//Debug other ARP replies except the correct one
	for(var key in pendingSYNs[host_ip]['data']){
	    if(pendingSYNs[host_ip]['data'][key]['mac'] !== last_mac)
		logger.log('[-] Validation Failed: '+host_ip+ ' at '+ pendingSYNs[host_ip]['data'][key]['mac'], 'debug');
	}

        //Write to database on new validation
	fs.writeFileSync(args.params.hostdb, JSON.stringify(validatedHosts));
    }
    //Done with this host
    delete pendingSYNs[host_ip];
}

//some RST or ACK arrive at port 31337
function handleTCPPacket(etherPacket){
  var host_ip = etherPacket.payload.saddr.addr.join('.');
  var host_port = etherPacket.payload.payload.sport;
  var host_mac = arrToMacString(etherPacket.shost.addr);
  if(pendingSYNs[host_ip] != undefined){
      if(pendingSYNs[host_ip]['data'][host_port] !== undefined){
	  if(etherPacket.payload.payload.flags.rst){
	      logger.log('[?] Received RST from '+host_ip+':'+host_port, 'debug');
	      if(pendingSYNs[host_ip]['data'][host_port]['mac'] === host_mac) pendingSYNs[host_ip]['data'][host_port]['rst_ack'] = true;
	  }else if(etherPacket.payload.payload.flags.ack){
	      logger.log('[?] Received ACK from '+host_ip+':'+host_port, 'debug');
	      if(pendingSYNs[host_ip]['data'][host_port]['mac'] === host_mac) pendingSYNs[host_ip]['data'][host_port]['rst_ack'] = true;
	  }
      }
  }
}

//convert mac address(array in packet) to string
//[255,12,58,6,86,45] -> 'ff:0c:3a:06:56:2d'
function arrToMacString(mac){
  for(var i=0; i<mac.length; i++){
    var hexm = mac[i].toString(16);
    if(hexm.length < 2) mac[i] = '0'+ hexm;
    else mac[i] = hexm;
  }
  return mac.join(':');
}

//match source and dst mac address in mac header and arp header
function checkHeaders(ethrPacket){
  var arpPacket = ethrPacket.payload;
  //checking source mac address
  if(arrToMacString(ethrPacket.shost.addr) !==  arrToMacString(arpPacket.sender_ha.addr)) return false;
  //checking dst mac address
  var isGratuitous = arrToMacString(ethrPacket.dhost.addr) === 'ff:ff:ff:ff:ff:ff';
  isGratuitous = isGratuitous || (arrToMacString(ethrPacket.dhost.addr) == '00:00:00:00:00:00');
  isGratuitous = isGratuitous || (arrToMacString(arpPacket.target_ha.addr) === 'ff:ff:ff:ff:ff:ff');
  isGratuitous = isGratuitous || (arrToMacString(arpPacket.target_ha.addr) === '00:00:00:00:00:00');
  if(!isGratuitous){//not a gratuitous reply
    if(arrToMacString(ethrPacket.dhost.addr) !== arrToMacString(arpPacket.target_ha.addr)) return false;
  }
  return true;
}

function handleARPReply(etherPacket){
    //No need to validate arp replies sent by itself
    var arpPacket = etherPacket.payload;
    if(arrToMacString(etherPacket.shost.addr) === arrToMacString(arpPacket.sender_ha.addr) && arrToMacString(arpPacket.sender_ha.addr) === my_mac)
	return;

    var host_ip = arpPacket.sender_pa.addr.join('.');
    if(pendingSYNs[host_ip] === undefined){
	logger.log('[-] ARP Reply without Request from '+host_ip+', Send an ARP Request', 'debug');
	var src_ip = ip.address();
	var src_mac = my_mac;
	arp.sendARP(args.params.iface, src_ip, src_mac, host_ip, 'ff:ff:ff:ff:ff:ff', 1);
	pendingSYNs[host_ip] = {arpRequestSent: true};
    }else{
	//Got an ARP reply for a Request sent by us, let's validate it
	if(!checkHeaders(etherPacket)){
	    logger.log('Mac-ARP Header Mismatch : '+arrToMacString(arpPacket.sender_ha.addr)+' spoofing '+arpPacket.sender_pa.addr.join('.'));
	    return;
	}
	validateHost(arpPacket.sender_pa.addr.join('.'), arrToMacString(arpPacket.sender_ha.addr));
    }
}

function handleARPRequest(etherPacket){
    var arpPacket = etherPacket.payload;
    //We're concerned for ARPRequests sent by us
    if(arrToMacString(etherPacket.shost.addr) === arrToMacString(arpPacket.sender_ha.addr) && arrToMacString(arpPacket.sender_ha.addr) === my_mac){
	var host_ip = arpPacket.target_pa.addr.join('.');
	var sender_ip = arpPacket.sender_pa.addr.join('.');
	if(pendingSYNs[host_ip] === undefined){
	    pendingSYNs[host_ip] = {arpRequestSent: true};
	    logger.log(util.inspect(pendingSYNs));
	}
    }
}

function handleARPPacket(etherPacket){
    arpPacket = etherPacket.payload;
    if(arpPacket.operation === 1){
	handleARPRequest(etherPacket);
    }else{
	handleARPReply(etherPacket);
    }
}

//Capture ARP(requests and replies) and TCP(ACK or RST) packets
function startCapture(){
  var arpSession = pcap.createSession(args.params.iface, 'arp or (tcp dst port 31337)');
  arpSession.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    if(packet.payload.ethertype == 0x0800){//TCP
      handleTCPPacket(packet.payload);
    }else if(packet.payload.ethertype == 0x0806){//ARP
      handleARPPacket(packet.payload);
    }
  });
}

process.on('uncaughtException', function(err) {
	fs.appendFile(args.params.log, err + '\n');
});

exports.startCapture = startCapture;
