#!/usr/bin/env python3
"""
Nessus API operations with credentials stored in Hashicorp Vault.
"""
import hvac
import requests
import sys
from os import environ
from os import getcwd
from datetime import datetime, timezone, timedelta
from random import randint

try:
    cwd=getcwd()
    sys.path.append(cwd + '/3_subnetting')
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
            target_list.append([target])
            target_count += 1
        elif subnet_calculator.is_ipnetwork(target):
            target_list += subnet_calculator.subnet(
                target, max_hosts=max_members)
            target_count += subnet_calculator.num_hosts(target)
        else:
            target_list.append(target)
            target_count += 1
    return target_list, target_count


def list_target_groups():
    """
    List target groups in the Tenable.io platform.
    [(n['id'], n['name']) for n in list_target_groups()['target_groups']]
    """
    url = TENABLE_URL + "target-groups"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def create_target_groups(target_name, target_members):
    """
    Create target groups in the Tenable.io platform.
    response=[create_target_groups("public_"+target,target) for target in
        split_targets(bb.split('\n'),256)[0]]
    """
    url = TENABLE_URL + "target-groups"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    payload = {
        "acls": [
            {
                "type": "default",
                "permissions": 32
            }
        ],
        "type": "system",
        "name": target_name,
        "members": target_members
    }
    target_groups = list_target_groups()['target_groups']
    for target_group in target_groups:
        if target_group['name'] == payload['name']:
            if target_group['members'] == payload['members']:
                return target_group
            else:
                payload['acls'] = target_group['acls']
                payload['type'] = target_group['type']
                url = url + "/" + str(target_group['id'])
                response = requests.request("PUT", url,
                                            headers={**headers, **auth},
                                            json=payload)
                return response.json()
    response = requests.request("POST", url, headers={**headers, **auth},
                                json=payload)
    return response.json()


def list_scans():
    """
    List scans from the Tenable.io platform.
    """
    url = TENABLE_URL + "scans"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def locate_folder(folders, target):
    """
    Search for a target folder in the folders list and return the name and id.
    """
    if type(folders) == list:
        folder = [f for f in folders if f['name']==target]
    elif type(folders) == dict and folders.get('folders', False):
        folder = [f for f in folders['folders'] if f['name']==target]
    else:
        return False
    if len(folder)>0:
        return folder
    else:
        return False


def list_folders():
    """
    List folder sin the Tenable.io platform.
    """
    url = TENABLE_URL + "folders"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def create_folder(target):
    """
    Create folder in the Tenable.io platform.
    """
    url = TENABLE_URL + "folders"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    payload = {"name": target}
    requests.request("POST", url, headers={**headers, **auth},
                    json=payload)
    response = [f for f in list_folders()['folders'] if f['name']==target]
    return response[0]


def locate_or_create_folder(folders, target):
    """
    Search for a target folder in the folders list and return the name and id,
    if not found then create the folder in the Tenable.io platform.
    """
    folder = locate_folder(folders, target)
    if folder:
        return folder
    else:
        folder = create_folder(target)
        return folder


def list_scanners():
    """
    List scanners in the Tenable.io platform.
    """
    url = TENABLE_URL + "scanners"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def get_template_uuid(template_name='basic', template_type='scan'):
    """
    Get Tenable.io template uuid.
    """
    url = "https://cloud.tenable.com/editor/" + template_type + "/templates"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})
    template_uuid = [t['uuid'] for t in response.json()['templates']
            if t['name']==template_name][0]
    return template_uuid


def create_basic_external_scan_per_group(target_scanner='US Cloud Scanner',
                                         enable=True, launch='WEEKLY'):
    """
    Create basic network scan per target group in the Tenable.io platform.
    """
    url = TENABLE_URL + "scans"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']
    template_uuid = get_template_uuid()
    start_times = dict()

    folder = locate_or_create_folder(list_scans(), 'Internet')[0]['id']
    tz = "UTC"
    rrules = "FREQ=" + launch + ";INTERVAL=1"
    if launch not in ['ON_DEMAND', 'DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']:
        launch = 'WEEKLY'
    if enable not in [True, False]:
        enable = True

    target_groups = [(n['id'], n['name']) for n in
                     list_target_groups()['target_groups'] if
                     'public' in n['name']]
    scans = list_scans()['scans']
    scanner_id = [i['uuid'] for i in list_scanners()['scanners']
                if i['name'] == target_scanner][0]

    for group_id, group_name in target_groups:
        scan_prefix = "Basic External - "
        scan_name = scan_prefix + group_name
        if scan_name in [s['name'] for s in scans]:
            print("Skipping already existing scan %s" % (scan_name))
        else:
            start_times[group_name] = randint(1, len(target_groups))
            starttime = datetime.now().astimezone(timezone.utc) + timedelta(hours=start_times[group_name])
            payload = {
                "settings": {
                    "acls": [
                        {
                            "type": "default",
                            "permissions": 32
                        }
                    ],
                    "target_groups": [group_id],
                    "name": scan_name,
                    "description": "Basic External scan for " + group_name,
                    "timezone": tz,
                    "rrules": rrules,
                    "folder_id": folder,
                    "scanner_id": scanner_id,
                    "starttime": starttime.strftime("%Y%m%dT%H%M%S"),
                    "enabled": enable,
                    "launch": launch
                },
                "uuid": template_uuid
            }
            response = requests.request("POST", url,
                                        headers={**headers, **auth},
                                        json=payload)
            print(response.json())
    print(start_times)