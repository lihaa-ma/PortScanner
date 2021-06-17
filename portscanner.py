import logging   
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
import sys
from netaddr import *
from scapy.all import * 


if len(sys.argv) !=4: 
    print ("To use this port scanner you need to enter the following inputs: %s <Target IP range> <Starting Port> <Ending Port>" % (sys.argv[0]))
    sys.exit(0)

#Define the inputs
target = str(sys.argv[1])
startport = int(sys.argv[2])
endport = int(sys.argv[3])

#creating a .txt file to import the values to
file = open("portscan.txt","w")

#Starting the scan
print("Scanning " +target+ " for open TCP ports\n")

#Iterating through the IPs and printing the IP
for ip in IPNetwork(target).iter_hosts():
  print(ip,file=file)
  for p in range(startport,endport+1): 
    packet = IP(dst=target)/TCP(dport=p,flags='S')  
    response = sr1(packet,timeout=0.5,verbose=0) 
    try:

        if response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
            print("Port "+str(p)+" is open",file=file)
        sr(IP(dst=target)/TCP(dport=response.sport,flags='R'),timeout=0.5,verbose=0)

    except:
           print("Port "+str(p)+" is closed",file=file)
#letting the user know the scan is complete
print("Scan is complete, open file portscan.txt to see the results")

