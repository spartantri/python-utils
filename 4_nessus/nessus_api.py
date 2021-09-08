#!/usr/bin/env python3
"""
Nessus API operations with credentials stored in Hashicorp Vault.
"""
import hvac
import requests
import sys
from os import environ

try:
    sys.path.append('../3_subnetting')
    import subnet_calculator
except:
    pass

VAULT_URL = environ['VAULT_URL']
VAULT_TOKEN = environ['VAULT_TOKEN']
TENABLE_URL = "https://cloud.tenable.com/"

client = hvac.Client()
client = hvac.Client(
    url=environ['VAULT_URL'],
    token=environ['VAULT_TOKEN']
)


def read_secret(secret_path):
    """
    Read credentials from Hashicorp Vault.
    """
    return client.read(secret_path)['data']


def list_users():
    """
    List users in Tenable.io platform.
    """
    url = TENABLE_URL + "users"
    headers = { "Accept": "application/json" }
    auth = client.read('secret/tenable')['data']['data']
    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()

def get_users_details(user_id):
    """
    Get user details from the Tenable.io platform.
    """
    url = TENABLE_URL + "users/" + user_id
    headers = { "Accept": "application/json" }
    auth = client.read('secret/tenable')['data']['data']
    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()

def list_target_groups():
    """
    List target groups from the Tenable.io platform.
    """
    url = TENABLE_URL + "target-groups"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']
    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def split_targets(target_members, max_members):
    """
    Split a target list in items of a maximum number of hosts.
    """
    if type(target_members) == list:
        targets = target_members
    else:
        targets = target_members.split(',')
    target_list = list()
    target_count = 0
    for target in targets:
        if subnet_calculator.is_ipaddress(target):
            target_list.append([target)
            target_count += 1
        elif subnet_calculator.is_ipnetwork(target):
            target_list += subnet_calculator.subnet(
                target, max_hosts=max_members)
            target_count += subnet_calculator.num_hosts(target)
        else:
            target_list.append(target)
            target_count += 1
    return target_list, target_count

def create_target_groups(target_name, target_members):
    """
    Create target groups in the Tenable.io platform.
    """
    url = TENABLE_URL + "target-groups"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    payload = {"name": target_name, "members": target_members}
    response = requests.request("POST", url, headers={**headers, **auth},
                                json=payload)
    return response.json()