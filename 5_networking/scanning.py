#!/usr/bin/env python3
"""
Scan the network or hosts.
"""
import logging
import socket
import requests
import re
from os.path import exists
from requests.models import ProtocolError

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

if exists("nmap-services"):
    servicesfile = open("nmap-services", 'r').read()
else:
    servicesfile_url="https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
    servicesfile = requests.get(servicesfile_url).text
    with open("nmap-services", 'w') as f:
        f.write(servicesfile)
servicere = re.compile(r"(.+)\t(\d+)\/(tcp|udp)\t\b(0\.\d+)")

class service:
    def __init__(self, name, port, protocol, frequency):
        self.name = name
        self.port = int(port)
        self.protocol = protocol
        self.frequency = float(frequency)
    def __repr__(self):
        return "%s\t%d/%s\t%f" % (self.name, self.port, self.protocol, self.frequency)
    def __eq__(self, other):
        return ((self.name, self.port, self.protocol, self.frequency) == (other.name, other.port, other.protocol, other.frequency))
    def __ne__(self, other):
        return not (self == other)

def servicefrequency(item):
    return item.frequency

def top(servicelist, protocol=None, limit=100):
    if len(servicelist)>limit:
        final_item = limit
    else:
        final_item = len(servicelist)
    logger.debug("Limit set to %d" % (final_item))
    if not protocol:
        return sorted(servicelist, key=servicefrequency, reverse=True)[:final_item]
    else:
        return [s for s in sorted(servicelist, key=servicefrequency, reverse=True) if s.protocol==protocol][:final_item]

def get_port_range(port_range):
    range_rx = re.compile(r'^\s*(\d+)-(\d+)\s*$|^(.*)$')
    ports = []
    service_list = None
    for range_item in port_range.split(','):
        range_string = range_rx.match(range_item).groups()
        if range_string[0] and range_string[1]:
            range_start = int(range_string[0])
            range_end = int(range_string[1])+1
            if range_end < range_start:
                logger.error("Invalid port_range value received")
                return
            for port in range(range_start, range_end):
                ports.append(port)
        if range_string[2]:
            try:
                ports.append(int(range_string[2]))
            except ValueError:
                if not service_list:
                    with open("nmap-services", 'r') as f:
                        service_list = servicere.findall(f.read())
                [ports.append(service(*sname).port) for sname in service_list if sname[0] == range_string[2]]
            except:
                logger.error("Invalid port_range value received")
                pass
    logger.debug("Identified ports: %s" % ','.join([str(p) for p in ports]))
    unique_ports  = {}
    for port in ports:
        unique_ports[port] = 1
    unique_ports.keys()
    return unique_ports.keys()

def portscan(host, services_to_scan=None, port_range=None, timeout=0.5):
    try:
        socket.setdefaulttimeout(float(timeout))
    except:
        socket.setdefaulttimeout(1)
    port_list = None
    if not services_to_scan and not port_range:
        services_to_scan = top([service(*s) for s in servicere.findall(servicesfile)], protocol="tcp")
    if services_to_scan and port_range:
        logger.error("Use only either services_to_scan or port_range.")
        return
    if port_range and not services_to_scan:
        port_list = get_port_range(port_range)
        services_to_scan = [service('', port, 'tcp', 0.0) for port in port_list]
    for item in services_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sock.connect_ex((host,int(item.port))) == 0:
            logger.info("Host %s - Port %s/%d is open" % (host, item.protocol, item.port))
        else:
            logger.info("Host %s - Port %s/%d is closed" % (host, item.protocol, item.port))

host="127.0.0.1"
portscan(host)
