#!/usr/bin/env python
import sys, os, signal
from multiprocessing import Process

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

interface='' # monitor interface
unique = []

# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

def sniffMAC(p):
        if p.haslayer(Dot11):
             mac = p.sprintf("DEST:%Dot11.addr1%,SOURCE:%Dot11.addr2%,BSSID:%Dot11.addr3%")
             if unique.count(mac) == 0:
                  unique.append(mac)
                  print mac


# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):
    p.terminate()
    p.join()

    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        sys.exit(1)

    interface = sys.argv[1]

    # Start the channel hopper
    p = Process(target = channel_hopper)
    p.start()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    sniff(iface=interface,prn=sniffMAC)
