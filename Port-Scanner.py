#!/bin/python 
from termcolor import colored
import socket
import os
import sys
import subprocess
from datetime import datetime
import argparse
import re
import string
import ipaddress
from ipaddress import IPv4Network
import nmap
if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")
from art import *

input_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,epilog=''' 
	./file.py --help -----> Display the Full Help Menu 
	
	./file.py --target 'Target' -----> TCP Port Scan and NMAP Service Scan 
	
	./file.py --target 'Target' --udp -----> UDP Port Scan and NMAP Service Scan 
	
	./file.py --target 'Target' --udp --tcp -----> TCP and UDP Port Scan and NMAP Service Scan 
	
	''')
### Get User Input as Arguments
def get_user_input():
    input_parser.add_argument('--target', help='Use Target Ip, Range, Subnet or Hostname', action='store', type=str)
    input_parser.add_argument('--tcp', help='TCP Scan',action='store_true')
    input_parser.add_argument('--udp', help='UDP Scan',action='store_true')
    input_parser.add_argument('--TopPorts', help='Scan Top Ports',action='store_true')
    input_parser.add_argument('--AllPorts', help='Full Port Scan',action='store_true')
    input_parser.add_argument('--verbose', help='Verobse',action='store_true')
    global user_input
    user_input = input_parser.parse_args()

def get_live_ips_of_nw():
	global live_hosts
	ping1 = "ping -b -c 2 "
	print ("[+] Identifying Live Hosts")
	if subnet == 1:
		ips_list = input_IPS
	elif subnet ==0:
	    ips_list = input_IPS
	ttl_ind = "ttl="
	live_hosts = []
	for ip in input_IPS:
		ping_cmd = ping1 + str(ip)
		response = os.popen(ping_cmd)
		out_put = (response.readlines())[1]
		if ttl_ind in str(out_put):
			print(colored("[+] {} is Live".format(ip),'green'))
			live_hosts.append(str(ip))
	print(colored("[+] {} Hosts are Live".format(len(live_hosts)),'blue'))

### Validate user input IP or URL
def input_validate():
	global is_ip	
	tmp_ip = '%s' % user_input.target
	for i in tmp_ip.split('.')[0:-1]:
		if unicode(i,'UTF-8').isnumeric():
			is_ip = 0
		else:
			is_ip = 1    
	if is_ip == 0:
		get_ip_specs()
		target_regex = re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
	else:
		target_regex = re.compile(r"(^https://|^http://|^www\.|^\w[a-zA-Z0-9]*\.)(\w[a-zA-Z]*\.)*?(\w[a-zA-Z0-9]*)") 
	if is_ip == 0:
		if isinstance(input_IPS, str):
			result = re.findall(target_regex,input_IPS)
			try:
				x = result[0][2]
			except:
				print(colored("[-] Invalid IP",'red'))
				print("Exiting .....")
				exit(1) 
		else:
			result = re.findall(target_regex,str(input_IPS[-1]))
			try:
				x = result[0][2]
			except:
				print(colored("[-] Invalid IP",'red'))
				print("Exiting .....")
				exit(1) 
	else:
		result = re.findall(target_regex,user_input.target)
		try:
			x = result[0][2]
		except:
			print(colored("[-] Invalid URL",'red'))
			print("Exiting .....")
			exit(1) 



### Check if Subnet or Range or Single IP
def get_ip_specs():
	global input_IPS
	global subnet
	global ip_range 
	subnet=0
	ip_range =0
	dash = '-'
	slash = '/'
	if dash in user_input.target:
		ip_range =1
		print("[*] Got IP Range")
		input_IPS = get_ip_range()
	elif slash in (user_input.target):
		subnet = 1
		print("[*] Got Network subnet")
		input_IPS = get_ips_of_nw()
		input_IPS = list(input_IPS.hosts())
	else:
		input_IPS =user_input.target
		print("[*] Got Single IP")
### Check if the Subnet is valid or not
def get_ips_of_nw():
	try:
		ips_list = IPv4Network(unicode(str(user_input.target),'UTF-8'))
		return ips_list
	except:
		print(colored("[-] Invalid Input Subnet",'red'))

### Generate the IPs from the given Range
def get_ip_range():
	ips_list = []
	ips = user_input.target.split('-')
	#print(ips)
	temp_ip = ips[0].split('.')
	fst_ip = ips[0].split('.')[-1]
	lst_ip = ips[-1]
	#print(fst_ip)
	for i in range(int(fst_ip),int(lst_ip)+1):
		ip_add = str(temp_ip[0])+'.'+str(temp_ip[1])+'.'+str(temp_ip[2])+'.'+str(i)
		ips_list.append(ip_add)
		#print(ip_add)
	return ips_list

def tcp_scan(ip):
    global tcp_scan_result
    global pass_tcp_nmap 
    pass_tcp_nmap = "1"
    tcp_scan_result = []
    print("[+] Starting TCP Port Scanning on {}".format(ip))
    socket.setdefaulttimeout(0.5) 
    try:
        for port in ports:
            tcp_scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_tcp_scan_result = tcp_scanner.connect_ex((ip,port))
            if temp_tcp_scan_result == 0:
                tcp_scan_result.append(port)
                pass_tcp_nmap += ','+str(port)
            if user_input.verbose and (temp_tcp_scan_result == 0):
                print(colored('[+] Found Port {} Open'.format(port),'green'))
            tcp_scanner.close()
    except KeyboardInterrupt:
        print("Exiting .....")
        exit(1)
    except socket.error:
        print(colored("[-] Connection Error or Destionation Host Unreachable",'red'))
        print("Exiting .....")
        exit(1)
### Udp SCanner
def udp_scan(ip):
	global udp_scan_result
	global pass_udp_nmap 
	pass_udp_nmap = "1"
	udp_scan_result = []
	print("[+] Starting UDP Port Scanning")
	try:
		for port in ports:
			retrans = 3
			local_info = (ip,port)
			while (retrans > 0):
				udp_scanner = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				udp_scanner.settimeout(1)
				temp_udp_scan_sender = udp_scanner.sendto('a'.encode(),(local_info))
				try:
					temp_udp_scan_rcvr = udp_scanner.recvfrom(1024)
					if user_input.verbose:
						print(colored('[+] Found Port {} Open'.format(port),'green'))
					udp_scan_result.append(port)
					pass_udp_nmap += ','+str(port)
					break
				except KeyboardInterrupt:
					print("Exiting .....")
					exit(1)
				except:
					udp_scanner.close()
					pass				
				retrans -= 1
	except KeyboardInterrupt:
		print("Exiting .....")
		exit(1)
### NMAP Service Scanner for TCP
def tcp_pass_to_nmap(ip):
    #nmap_tcp_cmd ='nmap -sC -sV  -p ' + pass_tcp_nmap + ' ' + user_input.target  
    print('[+] Starting TCP Service Scan')
    nmap_tcp_scanner = nmap.PortScanner()
    nmap_tcp_scanner.scan(ip,pass_tcp_nmap,arguments='-sC -sV')
    print(colored('[+] '+str(nmap_tcp_scanner.command_line()),'yellow'))
    #nmap_tcp = os.popen(nmap_tcp_cmd)
    #nmap_tcp_result = nmap_tcp.read() 
    nmap_tcp_result = nmap_tcp_scanner.csv()
    nmap_tcp_result = nmap_tcp_result.replace(';',' ')
    nmap_tcp_result = nmap_tcp_result.replace(str(ip),'[+]')
    nmap_tcp_output = open('nmap_tcp_scripts_'+ip+'.txt',"w+")
    nmap_tcp_output.write(nmap_tcp_result)
    nmap_tcp_output.close
    xml_nmap_tcp_output = open('xml_nmap_tcp_scripts_'+ip+'.txt',"w+")
    xml_nmap_tcp_output.write(nmap_tcp_scanner.get_nmap_last_output())
    xml_nmap_tcp_output.close
    print(colored(nmap_tcp_result,'green'))

### NMAP Service Scanner for UDP
def udp_pass_to_nmap(ip):
    #nmap_udp_cmd ='nmap -sC -sV -sU -p ' + pass_udp_nmap + ' ' + user_input.target  
    print('[+] Starting UDP Service Scan')
    nmap_udp_scanner = nmap.PortScanner()
    nmap_udp_scanner.scan(ip,pass_udp_nmap,arguments='-sC -sV -sU')
    print(colored('[+] '+str(nmap_udp_scanner.command_line()),'yellow'))
    #nmap_tcp = os.popen(nmap_tcp_cmd)
    #nmap_tcp_result = nmap_tcp.read() 
    nmap_udp_result = nmap_udp_scanner.csv()
    nmap_udp_result = nmap_udp_result.replace(';',' ')
    nmap_udp_result = nmap_udp_result.replace(str(ip),'[+]')
    nmap_udp_output = open('nmap_udp_scripts_'+ip+'.txt',"w+")
    nmap_udp_output.write(nmap_udp_result)
    nmap_udp_output.close
    xml_nmap_udp_output = open('xml_nmap_udp_scripts_'+ip+'.txt',"w+")
    xml_nmap_udp_output.write(nmap_udp_scanner.get_nmap_last_output())
    xml_nmap_udp_output.close
    print(colored(nmap_udp_result,'green'))

### Resolve the Name of the IP or The IP of the Given URL
def name_resolution(ip):
	global host
	try:
		if is_ip==1:
			host = socket.gethostbyname(ip) #---------> DNS Resolution 
			print("[+] IP Address of {} is {}".format(ip,host))
	except socket.gaierror:
		print(colored("[-] Couldn't Resolve Hostname",'red'))
		print("Exiting .....")
		exit(1)


### Main Function of the Program
def main_fucntion():
	print("[+] Started at "+ str(datetime.now()))
	global ports
	global flag
	get_user_input()
	try:
		input_validate()
	except:
		print(colored("[*] Received no Input Target",'red'))
	if user_input.target:
		if user_input.AllPorts:
			ports = list(range(1,65536))
		else :
			ports = [20, 22, 25, 53, 67, 68, 80, 123, 137, 154, 161, 162, 443, 631, 727, 8080, 8888, 8898]
		if (user_input.tcp == True) and (user_input.udp == True):
			flag = 1
			if is_ip ==0:
				if subnet == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						tcp_scan(i)
						tcp_pass_to_nmap(i)
						udp_scan(i)
						udp_pass_to_nmap(i)
				elif ip_range == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						tcp_scan(i)
						tcp_pass_to_nmap(i)
						udp_scan(i)
						udp_pass_to_nmap(i)
				else:
					name_resolution(input_IPS)
					tcp_scan(input_IPS)
					tcp_pass_to_nmap(input_IPS)
					udp_scan(input_IPS)
					udp_pass_to_nmap(input_IPS)
			else:
				name_resolution(user_input.target)
				tcp_scan(user_input.target)
				tcp_pass_to_nmap(user_input.target)
				udp_scan(user_input.target)
				udp_pass_to_nmap(user_input.target)				
		if (user_input.tcp == False) and (user_input.udp == True):
			flag = 2
			if is_ip ==0:
				if subnet == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						udp_scan(i)
						udp_pass_to_nmap(i)
				elif ip_range == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						udp_scan(i)
						udp_pass_to_nmap(i)
				else:
					name_resolution(input_IPS)
					udp_scan(input_IPS)
					udp_pass_to_nmap(input_IPS)
			else:
				name_resolution(user_input.target)
				udp_scan(user_input.target)
				udp_pass_to_nmap(user_input.target)
		if (user_input.tcp == False) and (user_input.udp == False) :
			flag =3
			if is_ip ==0:
				if subnet == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						tcp_scan(i)
						tcp_pass_to_nmap(i)
				elif ip_range == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						tcp_scan(i)
						tcp_pass_to_nmap(i)        
				else:
					name_resolution(input_IPS)
					tcp_scan(input_IPS)
					tcp_pass_to_nmap(input_IPS)
			else:
				name_resolution(str(user_input.target))
				tcp_scan(user_input.target)
				tcp_pass_to_nmap(user_input.target)
		if (user_input.tcp == True)	and (user_input.udp == False):
			if is_ip ==0:
				if subnet == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						tcp_scan(i)
						tcp_pass_to_nmap(i)
				elif ip_range == 1:
					get_live_ips_of_nw()
					for i in live_hosts:
						name_resolution(i)
						tcp_scan(i)
						tcp_pass_to_nmap(i)        
				else:
					name_resolution(input_IPS)
					tcp_scan(input_IPS)
					tcp_pass_to_nmap(input_IPS)
			else:
				name_resolution(str(user_input.target))
				tcp_scan(user_input.target)
				tcp_pass_to_nmap(user_input.target)			

banner = text2art("Simple Port Scanner")
print(banner)
try:
	main_fucntion()
except KeyboardInterrupt:
	print("Exiting .....")
	exit(1)