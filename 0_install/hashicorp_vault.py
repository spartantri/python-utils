#!/usr/bin/env python3
"""
Hashicorp Vault operations.
"""
import hvac
from os import environ

VAULT_URL = environ['VAULT_URL']
VAULT_TOKEN = environ['VAULT_TOKEN']

client = hvac.Client()
client = hvac.Client(
    url=environ['VAULT_URL'],
    token=environ['VAULT_TOKEN']
)


def create_secret(secret_path, secret_name, secret_value):
    data = {secret_name: secret_value}
    client.write(secret_path, data=data)


def read_secret(secret_path):
    return client.read(secret_path)['data']


def delete_secret(secret_path):
    client.delete(secret_path)


def list_secrets(secret_path='secret'):
    client.list(secret_path)