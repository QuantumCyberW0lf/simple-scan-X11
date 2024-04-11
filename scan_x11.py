#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, sys
try:
    from scapy.all import *
except ImportError as imp_err:
    print("[-] Scapy is not installed!")
    sys.exit(1)

def check_x11_access(rhost:str)->None:
    # Check if the remote host supports X11
    try:
        response = sr1(IP(dst=rhost)/TCP(dport=6000,flags="S"),timeout=1,verbose=1)
        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 18: # Syn-Ack packet
                print("[*] X11 is accessible on {}".format(rhost))
            else:
                print("[-] X11 is not accessible on {}".format(rhost))
        else:
            print("[-] No response from remote host {}".format(rhost))
    except PermissionError as perm_err:
        print("[-] Error: {}. Please run as root.".format(str(perm_err)))
        sys.exit(1)

def validate_ip(rhost:str)->bool:
    try:
        ip_parts = rhost.split('.')
        if len(ip_parts) != 4:
            return False
        for part in ip_parts:
            if not 0 <= int(part) <= 255:
                return False
    except ValueError as err:
        return False
    return True

def main():
    description="Python Module to scan a single remote host of X11 Auth."
    epilog="Built by Thi Altenschmidt."
    parser=argparse.ArgumentParser(description=description,epilog=epilog)
    parser.add_argument("-r","--rhost",type=str,dest="rhost",action="store",required=True,
            help="Specify IP address of the remote host to scan for X11 accessibility.")
    args = parser.parse_args()
    rhost = args.rhost
    if not validate_ip(rhost):
        print("[-] Wrong ip address format")
        sys.exit(1)

    check_x11_access(rhost)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[*] Scanning terminated by user.")
        sys.exit(1)
