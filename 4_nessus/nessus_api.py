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
    cwd = getcwd()
    sys.path.append(cwd + '/3_subnetting')
    import subnet_calculator
except ModuleNotFoundError:
    print("subnet_calculator module not found in path.")
else:
    print("Unexpected error:", sys.exc_info()[0])
    raise

VAULT_URL = environ['VAULT_URL']
VAULT_TOKEN = environ['VAULT_TOKEN']
TENABLE_URL = "https://cloud.tenable.com/"

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
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']
    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def get_users_details(user_id):
    """
    Get user details from the Tenable.io platform.
    """
    url = TENABLE_URL + "users/" + user_id
    headers = {"Accept": "application/json"}
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
        folder = [f for f in folders if f['name'] == target]
    elif type(folders) == dict and folders.get('folders', False):
        folder = [f for f in folders['folders'] if f['name'] == target]
    else:
        return False
    if len(folder) > 0:
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
    response = [f for f in list_folders()['folders'] if f['name'] == target]
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
                     if t['name'] == template_name][0]
    return template_uuid


def create_basic_external_scan_per_group(target_scanner='US Cloud Scanner',
                                         enable=True, launch='WEEKLY', scan_type='External'):
    """
    Create basic network scan per target group in the Tenable.io platform.
    """
    if launch not in ['ON_DEMAND', 'DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']:
        launch = 'WEEKLY'
    if enable not in [True, False]:
        enable = True
    if scan_type == 'External':
        scan_prefix = 'public'
    elif scan_type == 'Internal':
        scan_prefix = 'private'
    else:
        print("Invalid scan type : %s" % (scan_type))
        return None
    url = TENABLE_URL + "scans"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']
    template_uuid = get_template_uuid()
    start_times = dict()

    folder = locate_or_create_folder(list_scans(), 'Internet')[0]['id']
    tz = "UTC"
    rrules = "FREQ=" + launch + ";INTERVAL=1"

    target_groups = [(g['id'], g['name']) for g in
                     list_target_groups()['target_groups'] if
                     scan_prefix in g['name']]
    scans = list_scans()['scans']
    scanner_id = [s['uuid'] for s in list_scanners()['scanners']
                  if s['name'] == target_scanner][0]

    for group_id, group_name in target_groups:
        scan_prefix = "Basic " + scan_type + "External - "
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
                    "description": "Basic " + scan_type + " scan for " + group_name,
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


def export_scan(scan_id, export_format="db", password="", password_len=20):
    """
    Export scan from the Tenable.io platform.
    """
    url = TENABLE_URL + "scans/" + scan_id + "/export"
    headers = {"Accept": "application/json",
               "Content-Type": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    payload = {
        "format": export_format
    }

    if export_format not in ["nessus","csv","db","html","pdf"]:
        export_format = "CSV"
    if export_format not in ["html","pdf"]:
        chapters = "vuln_hosts_summary; vuln_by_host; compliance_exec; remediations; vuln_by_plugin; compliance"
        headers = {**headers, **{"chapters": chapters}}
    if password == "" and export_format == "db":
        try:
            password = client.read('secret/tenable/exports/' + scan_id)['data']['data']['password']
        except TypeError:
            password = client.write('sys/tools/random/' + str(password_len))['data']['random_bytes'][:password_len]
        except:
            import string, random
            password = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase +
                             string.digits, k = password_len))

    if len(password) > 0:
        client.write('secret/tenable/exports/' + scan_id, data={"password": password})
        payload = {**payload, **{"password": password}}
    print(url, payload)
    response = requests.request("POST", url, headers={**headers, **auth},
                                json=payload)
    return response.json()


def check_export_status(scan_id, file_id):
    """
    Check export scan status from the Tenable.io platform.
    """
    url = TENABLE_URL + "scans/" + scan_id + "/export/" + file_id + "/status"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})
    return response.json()


def download_exported_scan(scan_id, file_id):
    """
    Download exported from the Tenable.io platform.
    """
    url = TENABLE_URL + "scans/" + scan_id + "/export/" + file_id + "/download"
    headers = {"Accept": "application/json"}
    auth = client.read('secret/tenable')['data']['data']

    response = requests.request("GET", url, headers={**headers, **auth})

    with open(scan_id + file_id, 'wb') as f:
        f.write(response.text)
    return