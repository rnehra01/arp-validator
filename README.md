# arp-validator
> Security Tool to detect arp poisoning attacks

## Features
  - Uses a faster approach in detection of arp poisoning attacks compared to passive approaches
  - Detects not only presence of ARP Poisoning but also valid IP-MAC mapping (when LAN hosts are using non-customized network stack)
  - Stores validated host for speed improvements
  - Works as a daemon process without interfering with normal traffic
  - Log's to any external file

## Architecture
```
  +-------------+                +---------------+                  +------------+    
  |  ARP packet |    ARP Reply   | Mac-ARP Header|    Consistent    |   Spoof    |
  |   Sniffer   |  ------------> |  consistency  |  --------------> |  Detector  |
  |             |     Packets    |    Checker    |    ARP Packets   |            |
  +-------------+                +---------------+                  +------------+
                                        |                                 /
                                   Inconsistent                         /
                                   ARP Packets                     Spoofed
                                        |                        ARP Packets
                                        V                         /
                                +--------------+                /
                                |              |              /
                                |   Notifier   |  <----------
                                |              |
                                +--------------+

```

1. **ARP Packets Sniffer**

   It sniffs all the ARP packets and discards
   - ARP Request Packets
   - ARP Reply packets sent by the machine itself which is using the tool (assuming host running the tool isn't ARP poisoning :stuck_out_tongue_winking_eye:)
2. **Mac-ARP Header Consistency Checker**

   It matches
   - source MAC addresses in MAC header with ARP header
   - destination MAC addresses in MAC header with ARP header

   If any of above doesn't match, then it will notified.
3. **Spoof Detector**

   It works on the basic property of TCP/IP stack.
   ```
   The network interface card of a host will accept packets sent to its MAC address, Broadcast  address
   and subscribed multicast addresses. It will pass on these packets to the IP layer. The IP layer will
   only  accept  IP packets  addressed to its IP address(s) and will  silently  discard the rest of the
   packets.
   If  the  accepted  packet  is a TCP packet it is passed on to the TCP  layer. If a TCP SYN packet is
   received then the host will either respond back with a TCP SYN/ACK packet if the destination port is
   open or with a TCP RST packet if the port is closed.
   ```
   So there can be two type of packets:
   - RIGHT MAC - RIGHT IP
   - RIGHT MAC - WRONG IP (**Spoofed packet**)

   For each consistent ARP packet, we will construct a TCP SYN packet with destination MAC and IP address as advertised by the ARP
   packet with some random TCP destination port and source MAC and IP address is that of the host running the tool.

   **_If_**  a RST(port is closed) or ACK(port is listening) within TIME LIMIT is received for the SYN then host(who sent the ARP packet) is legitimate.

   **_Else_**  No response is received within TIME LIMIT so host is not legitimate and it will be notified.
4. **Notifier**

   It provides desktop notifications in case of ARP spoofing detection.

   ![Screenshot](docs/arp-results.jpg?raw=true)

## Installation
  > npm
  ```
  [sudo] npm install arp-validator -g
  ```
  > source
  ```
  git clone https://github.com/rnehra01/arp-validator.git
  cd arp-validator
  npm install
  Use the binary in bin/ to run
  ```

## Usage
```
[sudo] arp-validator [action] [options]

actions:

	start		start arp-validator as a daemon

		options:
			--interface, -i
				Network interface on which tool works
				arp-validator start -i eth0 or --interface=eth0

			--hostdb, -d
				stores valid hosts in external file (absolute path)
				arp-validator start -d host_file or --hostdb=host_file

			--log, -l
				generte logs in external files(absolute path)
				arp-validator start -l log_file or --log=log_file


	stop		stop arp-validator daemon


	status		get status of arp-validator daemon


global options:

	--help, -h
		Displays help information about this script
		'arp-validator -h' or 'arp-validator --help'

	--version
		Displays version info
		arp-validator --version

```

## Dependencies

- libpcap-dev: library for network traffic capture
- [node-pcap/node_pcap](https://github.com/node-pcap/node_pcap)
- [stephenwvickers/node-raw-socket](https://github.com/stephenwvickers/node-raw-socket)
- [indutny/node-ip](https://github.com/indutny/node-ip)
- [scravy/node-macaddress](https://github.com/scravy/node-macaddress)
- [codenothing/argv](https://github.com/codenothing/argv)
- [niegowski/node-daemonize2](https://github.com/niegowski/node-daemonize2)
- [mikaelbr/node-notifier](https://github.com/mikaelbr/node-notifier)

## Issues
- [ ]  Currently, it is assumed that hosts are using non-customized network stack hence the malicious host won't respond the TCP SYN packet. But in case the malicious host is using a customized network stack, it can directly capture the TCP SYN packet from layer 2 and can respond with a self-constructed TCP RST or ACK hencour tool will validate the malicious host.
- [ ] If a host is using a firewall which allows TCP packets for only some specific ports, in that case a legitimate host 	also won't respond to the TCP SYN packet and tool will give a False Positive of ARP Poisoning Detection.

## References

   Vivek Ramachandran and Sukumar Nandi, [“Detecting ARP Spoofing: An Active Technique”](https://link.springer.com/content/pdf/10.1007%2F11593980_18.pdf)
