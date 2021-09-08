#!/usr/bin/env python3
"""
IP address and subnet manipulation.
"""
import ipaddress


def subnet(network, max_hosts=256, min_hosts=128):
    """
    Subnet an ip address network given a provided number of minimum and
    maximum hosts. Defaults to maximum of 256 hosts and a minimum of 128 hosts.
    '10.0.0.0/23' -> ['10.0.0.0/24', '10.0.1.0/24']
    """
    if min_hosts >= max_hosts:
        return "Minimum hosts should be greater than maximum hosts"
    ip_network = ipaddress.ip_network(network, strict=False)
    current_prefix = ip_network.prefixlen
    current_hosts = ip_network.num_addresses
    if current_hosts < min_hosts:
        return "Network {} has {} available addresses" % (
            ip_network, current_hosts
            )
    elif current_hosts == min_hosts:
        return ip_network
    for pfx_len in range(current_prefix, 32):
        num_hosts = 2 ** (32 - pfx_len)
        if min_hosts <= num_hosts <= max_hosts:
            new_prefix = pfx_len
            return [str(i) for i in ip_network.subnets(new_prefix=new_prefix)]
    return None


def num_hosts(network):
    """
    Number of hosts included in network.
    '10.0.0.0/24' -> 256
    """
    ip_network = ipaddress.ip_network(network, strict=False)
    return ip_network.num_addresses


def is_ipaddress(address):
    """
    Check if target is a valid ip address.
    '10.0.0.0' -> True
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_ipnetwork(network):
    """
    Check if target is a valid ip network.
    '10.0.0.0/24' -> True
    """
    try:
        if num_hosts(ipaddress.ip_network(network)) > 0:
            return True
        else:
            return False
    except ValueError:
        return False