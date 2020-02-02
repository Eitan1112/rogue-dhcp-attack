# Rogue DHCP Server Attacker

This tool will detect rogue DHCP servers across your network and launch a DHCP starvation attack to neutralize the server.

## Quick Start

```
git clone https://github.com/Eitan1112/rogue-dhcp-attack
py script.py --allowed server1 server2
```

## Tool Details
The tool will sniff DHCP packets, originated from a rogue server, using scapy. When a rogue server is found, a new thread is started to attack the server. The main thread will continue to listen to rogue servers. 
The new thread will follow this chart:
Send DHCP Discover > Listen to DHCP OFFER > Send DHCP Request > Listen to DHCP ACK / DHCP NAK

On DHCP ACK - Continue the attack
On DHCP NAK - Stops the attack, the server is neutralized.

All the events are logged to 'script.log'.