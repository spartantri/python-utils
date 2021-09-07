#!/usr/bin/env python3
"""
IP address and subnet manipulation.
"""
import ipaddress


def subnet(network, max_hosts=256, min_hosts=128):
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

