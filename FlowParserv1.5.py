#!/usr/bin/python/
'''

Flow Parser: A script that extracts TCP, UDP & ICMP flows from a pcap file
and stores them into an import file for opentsdb

v1.1 Removing Duplication of Flows ? Add ICMP support
It aggregates the elephant flows i.e., all packets for each
flow within a 5 second period have 1 entry in db
v1.2 Print entry every second instead of every 5 second
v1.3 Adding support for ICMP packets, this version of parser
extracts TCP,UDP & ICMP packets from a trace file. Additionally
adding protocol names intead of numbers
? Expire the flow_table entries after 5 seconds
v1.4 Reduce flow_table size by removing completed flows i.e., flows
that have no packet for 5 seconds
v1.5 Speed Up Lookup in dictionary
'''

import dpkt
import sys
import socket
import binascii
import socket
import hashlib
import subprocess
import re, string, sys, subprocess, time, socket, struct, os, glob, time

rf= open(sys.argv[1],'r')
wf= open(sys.argv[1]+'out', 'w')
flow_table = {}
completed_flows = {}
aa = [0,0,0,0]

# Convert IP string to Long
def ip_to_long(ip):
    packedIP = socket.inet_aton(ip)
    IP = struct.unpack("!L", packedIP)[0]
    return IP

## values = {timestamp of most recent packet, bytesum of flow, Timestamp of first packet of Flow}
## source port = pheaders [2], destination port = pheaders [3], protocol = pheaders[4]
def print_to_file(values,lis4):
    if (lis4[4]=='6'):
        proto = 'TCP'
    elif (lis4[4] == '17'):
        proto = 'UDP'
    elif (lis4[4]== '1'):
        proto = 'ICMP'
    else:
        proto = lis4[4]
    wf.write(("bytes.uploaded {0} {1} sip={2} dip={3} sport={4} dport={5} proto={6} Firstseen={7} bytesum={8}\n").\
           format(values[0],values[1],lis4[0],lis4[1],lis4[2],lis4[3],proto,values[2],values[1]))
    
def lookup_dic(ip,port,proto,timestam,byts, aa):
    lis = [timestam,byts,timestam]
    # print (ip[0]+ip[1]+port[0]+port[1]+proto)
    # Convert IPs to Long & Extract Key
    key = str (ip_to_long(ip[0]))
    key = key + "-" + str (ip_to_long(ip[1])) + "-" + str (port[0]) + "-" + str (port[1]) + "-" + str (proto)
    # Lookup
    if key in flow_table:
        # Check if timestamp differs by miliseconds
        lis3 = flow_table[key]
        if (int (timestam)-int (lis3[0]) < 1):
            flow_table[key] = [timestam,int (byts) + int (lis3[1]),lis3[2]]
            aa[0] += 1
        elif (int (timestam)-int (lis3[0]) >= 5):
            completed_flows[key+"-"+str(lis3[0])] = flow_table[key]  # copy completed flow
            del flow_table [key] # delete completed flow from flow_Table
            flow_table[key] = lis
            aa[1] +=1
                # if true update dictionary
                # lis2 = [timestam,int (byts) + int (lis3[1]),lis3[2]]
                # return lis2
        else:
            flow_table[key+"-"+str(lis3[0])] = flow_table.pop(key) # if timestamp between 1 & 5            
            flow_table[key] = [lis[0],lis[1],lis3[2]]
            aa[2] += 1
            # return lis            
    else:
        flow_table[key] = lis
        aa[3] += 1
        # return lis

## Reverse Key Function
def reverse_key(key):
    pheaders = key.split("-")
    pheaders[0] = socket.inet_ntoa(struct.pack('!L', long (pheaders[0]))) # source IP
    pheaders[1] = socket.inet_ntoa(struct.pack('!L', long (pheaders[1]))) # destination IP
    ## source port = pheaders [2], destination port = pheaders [3], protocol = pheaders[4]
    return pheaders

pcap = dpkt.pcap.Reader(rf)
for ts,buf,size in pcap:
    timestam= int(round(ts))
    byts=size
    eth = dpkt.ethernet.Ethernet(buf)
    if (eth.type == 2048): # Check if it is an IP packet 
        packet = eth.data
        protocol=packet.p
        srcIP = socket.inet_ntoa(packet.src) # source IP
        dstIP = socket.inet_ntoa(packet.dst) # destination IP
        ip = [srcIP,dstIP]
        if (protocol == 6): # If TCP
            tcp = packet.data
            sport = tcp.sport # source Port
            dport = tcp.dport # destination Port
            port = [sport,dport]
            proto = 'TCP'
            lookup = lookup_dic(ip,port,6,timestam,byts,aa)
        elif (protocol == 17): #If UDP
            udp = packet.data
            sport = udp.sport
            dport = udp.dport
            proto = 'UDP'
            port = [sport,dport]
            lookup = lookup_dic(ip,port,17,timestam,byts,aa)
        elif (protocol == 1): #if ICMP
            icmp = packet.data
            sport = '7' # just a random number
            dport = '7' # just a random number
            proto = 'ICMP'
            lookup = lookup_dic(ip,port,1,timestam,byts,aa)
        else: # Ignore if not TCP,UDP or ICMP
            pass
    else: # Ignore if not an IP packet
        pass
# Merge two dictionaries
flow_table.update(completed_flows)
## Print The dictionary
for key,values in sorted(flow_table.items(), key=lambda e: e[1][0]):
    lis4 = reverse_key(key)
    # values = {timestamp of most recent packet, bytesum of flow, Timestamp of first packet of Flow}
    print_to_file(values,lis4)
rf.close()
wf.close()
'''
print ("Number of Times new flow {0}".format(aa[3]))
print ("Number of Times less than 1 {0}".format(aa[0]))
print ("Number of Times greater than 5 {0}".format(aa[1]))
print ("Number of Times between 1 & 5 {0}".format(aa[2]))
'''

