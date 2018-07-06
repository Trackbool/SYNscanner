#!/usr/bin/python3
# -*- coding: utf-8 -*-
#coded by: @adrianfa5

from random import randint
from pprint import pprint
import logging,time,sys,os,socket
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP,IP,TCP,UDP,ICMP,DNS,DNSQR,send,sr1

class Colors:
	HEADER = "\033[95m"
	OKBLUE = "\033[94m"
	RED = "\033[91m"
	OKYELLOW = "\033[93m"
	GREEN = "\033[92m"
	LIGHTBLUE = "\033[96m"
	WARNING = "\033[93m"
	FAIL = "\033[91m"
	ENDC = "\033[0m"
	BOLD = "\033[1m"
	UNDERLINE = "\033[4m"

def menu():
	print(Colors.GREEN+"  _______   ___   _")                              
	print(" /  ___\ \ / / \ | |")                         
	print(" \ `--. \ V /|  \| |___  ___ __ _ _ __  _ __   ___ _ __")
	print("  `--. \ \ / | . ` / __|/ __/ _` | '_ \| '_ \ / _ \ '__|")
	print(" /\__/ / | | | |\  \__ \ (_| (_| | | | | | | |  __/ |")   
	print(" \____/  \_/ \_| \_/___/\___\__,_|_| |_|_| |_|\___|_|\n")
	print(Colors.WARNING+"        Coded by Adrián Fernández Arnal-(@adrianfa5)\n"+Colors.ENDC)

def help_menu():
	print ("   --------------------------------------")
	print ("    [!] Options to use:")
	print ("    	  <ip>  - Scan the ports of victim's IP address")
	print ("    	  -p    - Specify the port or ports range | -p 1-100")
	print ("    	  -c    - Show the closed ports")
	print ("    	  -h    - This help menu")
	print ("   --------------------------------------")
	
def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False	

def arp_request(host):
	try:
		pkt = ARP(op=ARP.who_has, pdst=host)
		reply = sr1(pkt, timeout=1,verbose=0)
		print(Colors.LIGHTBLUE+" [-] Target MAC address: "+Colors.ENDC+reply[ARP].hwsrc)
		return True
	except:
		return False
	
def icmp_request(host):
	pkt = IP(dst=host)/ICMP(seq=1)
	reply = sr1(pkt, timeout=1,verbose=0)
	if(reply is not None):
		return True
	else:
         return False
	
def dns_request(domain_name):
	host = ""
	try:
		reply = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=domain_name,qtype="A")),verbose=0)
		i = 0
		exit = False
		while(i<reply.ancount and not exit):
			if(reply.an[i].type == 1):
				host = reply.an[i].rdata
				exit = True
			i+=1
	except:
		print("Error resolving the domain name")
		sys.exit(1)
	return host
	
def check_host_up(host):
	print(Colors.LIGHTBLUE+" [-] Checking if host ("+host+") is up..."+Colors.ENDC)
	arp = arp_request(host)
	icmp = icmp_request(host)
	if (arp or icmp):
         return True
	else:
         return False
	
#####
open_ports = 0
closed_ports = 0
filtered_ports = 0
#####

def portsLoop(host,start_port,end_port,showClosed):
	print(Colors.LIGHTBLUE+" [-] Scanning tcp ports of "+host+'...'+Colors.ENDC)
	for i in range(start_port,end_port):
		resend_cont = 0
		
		rand_tcp_seq = randint(1000, 99999)
		pkt = IP(dst=host) / TCP(seq=rand_tcp_seq,dport=i,flags=2)
		reply = sr1(pkt, timeout=0.1,verbose=0)
		
		while(reply is None and resend_cont < 2):
			reply = sr1(pkt, timeout=0.025,verbose=0)
			resend_cont+=1
			
		managePkt(reply,rand_tcp_seq,i,showClosed)
	
def managePkt(pkt,rand_tcp_seq,port,showClosed):
	global open_ports,closed_ports,filtered_ports
	if(pkt is not None and pkt[TCP].ack == rand_tcp_seq+1):
		if(pkt[TCP].flags == 'SA' or pkt[TCP].flags == 'S'):
			print('  [i] Port '+str(pkt[TCP].sport)+'/tcp is '+Colors.GREEN+'open'+Colors.ENDC)
			open_ports+=1
		elif(pkt[TCP].flags == 'RA'):
			if(showClosed):
				print('  [i] Port '+str(pkt[TCP].sport)+'/tcp is '+Colors.FAIL+'closed'+Colors.ENDC)
			closed_ports+=1
		else:
			print('  [i] Port '+str(pkt[TCP].sport)+'/tcp is '+Colors.WARNING+'unfiltered'+Colors.ENDC)
	elif(pkt is None or pkt.haslayer('ICMP') and (pkt[ICMP].type == 3 and pkt[ICMP].code == 1 or 
	   pkt[ICMP].code == 2 or pkt[ICMP].code == 3 or pkt[ICMP].code == 9 or pkt[ICMP].code == 10 
	   or pkt[ICMP].code == 13)):
		print('  [i] Port '+str(port)+'/tcp is '+Colors.OKBLUE+'filtered'+Colors.ENDC)
		filtered_ports+=1

	
def main():
	try:
		if(len(sys.argv) >=4 and len(sys.argv) <= 5 and '-p' in sys.argv):
			if(valid_ip(sys.argv[1])):
				target_ip = sys.argv[1]
			else:
				target_ip = dns_request(sys.argv[1])

			if(valid_ip(target_ip)):
				range_ports = sys.argv[sys.argv.index('-p')+1]

				if('-c' in sys.argv):
					showClosed = True
				else:
					showClosed = False

				try:
					split_range = range_ports.split('-')
					start_port = int(split_range[0])
					end_port = int(split_range[1])+1
				except:
					start_port = int(range_ports)
					end_port = int(range_ports)+1

				if(start_port+1>end_port):
					print("The start port can't be higher than end port")
					sys.exit(1)

				menu()
				t1_start = time.perf_counter()
				if(check_host_up(target_ip)):
					portsLoop(target_ip,start_port,end_port,showClosed)
				else:
					response = input(" Host seems down. Is not replying the ping requests.\n Do you want to analyze the host anyway? (y/N): ").upper()
					if(response=="Y" or response=="YES"):
						portsLoop(target_ip,start_port,end_port,showClosed)

				t1_stop = time.perf_counter()
				print(Colors.WARNING+"\n [!] "+str(open_ports)+" open port/s, "+str(filtered_ports)+" filtered port/s, "+str(closed_ports)+" closed port/s"+Colors.ENDC)
				print(" [#] Finished. Time elapsed: "+str(round(t1_stop-t1_start,2))+" seconds")

			else:
				print("Invalid IP address or domain name")
		elif('-h' in sys.argv or '--h' in sys.argv or '--help' in sys.argv):
			menu()
			help_menu()
		else:
			print(" Usage: python3 SYNscanner.py <targetIP/domain> -p <range>")
	except KeyboardInterrupt:
		print("Exiting...")
	
if __name__ == "__main__":
	main()
