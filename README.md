# Rogue DHCP Server Attacker

This tool will detect rogue DHCP servers across your network and launch a DHCP starvation attack to neutralize the server.

## Quick Start

```
git clone https://github.com/Eitan1112/rogue-dhcp-attack
py script.py --allowed server1 server2
```

## Details
The tool will listen for DHCP packets, originated from a rogue server, using scapy. When a rogue server is found, a new thread is started to attack the server. The main thread will continue to listen to rogue servers. 
The new thread will starve addresses until 5 consecutive failures to starve an address, or when a NAK packet is recieved.

All the events are logged to 'script.log'.

## Important Note
This tool will not work when connected to Wifi. The reason is that access points drop packets with spoofed MAC addresses.