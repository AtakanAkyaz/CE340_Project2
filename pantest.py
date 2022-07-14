#! /usr/bin/env python

import nmap
import sys
from scapy.all import *
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
import argparse

def ICMPping():
	file1 = open("icmp.dat","a")
	for x in range(0,256):
		
		ans, unans = sr(IP(dst="192.168.1." +str(x))/ICMP(),timeout=3)
		ans.summary( lambda s,r: r.sprintf("%ICMP.dst% is alive") )
		
		#file1.writelines(L)
	file1.close		

def PortIdentification():
	nm = nmap.PortScanner()
	file1 = open('icmp.dat', 'r')
	file2 = open('ports.dat', 'w')
	Lines = file1.readlines()
	for line in Lines:
	    L=line.strip()
	    ans, unans = sr(IP(dst=L)/ICMP(),timeout=3)
	    ans.summary(lambda s,r: r.sprintf("%ICMP.dst% alive"))
	    for port in range(0 , 65536):
	    	    try:
	    	        result = nm.scan(L, str(port))
	    	        port_status = (result['scan'][L]['tcp'][port]['state'])
	    	        file2.writelines(f"{L} {port} {port_status}\n")
	    	        print(f"Port {port} is {port_status}")
	    	    except:
	    	        print(f"Cannot scan port {port}.")
	        
	file1.close
	file2.close

def OpenPortIdentification():
	liveHosts=[]
	file1 = open('ports.dat', 'r')
	file2 = open('openPorts.dat' , 'w')
	Lines = file1.readlines()
	for line in Lines:
		parsedLine = line.split(' ')
		host = parsedLine[0]
		if host not in liveHosts:
			ans, unans = sr(IP(dst=host)/ICMP(),timeout=3)
			ans.summary( lambda s,r: r.sprintf("%ICMP.dst% is alive") )
			liveHosts.append(host)
			
		print(liveHosts)
	a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	for host in liveHosts:
		for x in range(0 , 65536):
			print(host)
			print(x)
			location = (host, x)
			result_of_check = a_socket.connect_ex(location)
			if result_of_check == 0:
				print("Port is open")
				file2.writelines(host + " " + x)
			else:
				print("Port is not open")
			a_socket.close()

def Sniff(iface=None):
	if iface:
		sniff(filter="port 80", prn=Packet, iface=iface, store=False)
	else:
		sniff(filter="port 80" , prn=Packet , store=False)
def Packet(packet):
	if packet.haslayer(HTTPRequest):
		url=packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
		ip=packet[IP].src
		method=packet[HTTPRequest].Method.decode()
		print(f"\n [+] {ip} Requested {url} with {method}")

def Sniffer():
	if __name__ == "__main__":
	    import argparse
	    parser = argparse.ArgumentParser()
	    parser.add_argument("-i", "--iface")
	    parser.add_argument("--show-raw", dest="show_raw", action="store_true")
	    # parse arguments
	    args = parser.parse_args()
	    iface = args.iface
	    show_raw = args.show_raw
	    Sniff(iface)




while True:
	print('1. ICMP ping \n2. Scan \n3. Parse \n10. Sniff \n0. Terminate')
	x = int(input('Choose :'))
	
	
	if x==1:
		ICMPping()
	elif x==2:
		PortIdentification()
	elif x==3:
		OpenPortIdentification()
	elif x==10:
		Sniffer()
	elif x==0:
		break
	else:
		print('invalid input')

