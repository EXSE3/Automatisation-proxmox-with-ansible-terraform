#!/usr/bin/env python3
# installer python 
# prerequis: pip install requests
#export PVE_URL='https://192.168..:8006'
#export PVE_USERNAME='user@pam'
#export PVE_PASSWORD='votre_mot_de_passe'

import os 
import requests
import sys
import warnings

# Ignorer les avertissements de vérification SSL
warnings.filterwarnings("ignore", message="Unverified HTTPS request is being made")

# Remplacez ces valeurs par vos coordonnées

PVE_URL = os.environ.get('PVE_URL')
VE_USERNAME = os.environ.get('PVE_USERNAME')
VE_PASSWORD = os.environ.get('PVE_PASSWORD')


def authenticate():
    try:
        response = requests.post(f'{PVE_URL}/api2/json/access/ticket', data={
            'username': VE_USERNAME,
            'password': VE_PASSWORD
        }, verify=False)
        response.raise_for_status()
        ticket_info = response.json()['data']
        return ticket_info['ticket'], ticket_info['CSRFPreventionToken']
    except requests.exceptions.RequestException as e:
        print(f'Erreur lors de l\'authentification: {e}', file=sys.stderr)
        sys.exit(1)

def get_nodes(ticket):
    headers = {
        'Cookie': f'PVEAuthCookie={ticket}'
    }

    try:
        response = requests.get(f'{PVE_URL}/api2/json/nodes', headers=headers, verify=False)
        response.raise_for_status()
        nodes = response.json()['data']
        return nodes
    except requests.exceptions.RequestException as e:
        print(f'Erreur lors de la récupération des nœuds: {e}', file=sys.stderr)
        sys.exit(1)

def get_vms_and_lxc(node, ticket):
    headers = {
        'Cookie': f'PVEAuthCookie={ticket}'
    }

    vms = []
    try:
        response = requests.get(f'{PVE_URL}/api2/json/nodes/{node}/qemu', headers=headers, verify=False)
        response.raise_for_status()
        vms = response.json()['data']
        
        lxc_response = requests.get(f'{PVE_URL}/api2/json/nodes/{node}/lxc', headers=headers, verify=False)
        lxc_response.raise_for_status()
        lxc = lxc_response.json()['data']
        
        return vms, lxc
    except requests.exceptions.RequestException as e:
        print(f'Erreur lors de la récupération des VMs et LXC pour le nœud {node}: {e}', file=sys.stderr)
        return [], []

def get_ipaddresses(vm_id, node, ticket):
    headers = {
        'Cookie': f'PVEAuthCookie={ticket}'
    }

    try:
        response = requests.get(f'{PVE_URL}/api2/json/nodes/{node}/qemu/{vm_id}/config', headers=headers, verify=False)
        response.raise_for_status()
        return response.json()['data'].get('ip', [])  # Récupère la liste des adresses IP
    except requests.exceptions.RequestException as e:
        print(f'Erreur lors de la récupération des adresses IP pour la VM {vm_id} sur le nœud {node}: {e}', file=sys.stderr)
        return []

def write_inventory_to_ini(inventory):
    with open('inventory.ini', 'w') as f:
        for host in inventory:
            f.write(f'[{host["name"]}]\n')
            for vm in host['vms']:
                ip_addresses = ', '.join(vm['ip_addresses']) if vm['ip_addresses'] else 'N/A'
                f.write(f"{vm['name']} ansible_host={ip_addresses}\n")
            for lxc in host['lxcs']:
                ip_addresses = ', '.join(lxc['ip_addresses']) if lxc['ip_addresses'] else 'N/A'
                f.write(f"{lxc['name']} ansible_host={ip_addresses}\n")
            f.write('\n')  # Ligne vide entre les groupes

def build_inventory():
    ticket, csrf_token = authenticate()  # Authentification et récupération du ticket
    nodes = get_nodes(ticket)

    inventory = []

    for node in nodes:
        node_name = node['node']
        node_info = {
            'name': node_name,
            'vms': [],
            'lxcs': []
        }

        # Récupérer les VMs et conteneurs LXC
        vms, lxcs = get_vms_and_lxc(node_name, ticket)
        
        for vm in vms:
            ip_addresses = get_ipaddresses(vm['vmid'], node_name, ticket)  # Passer le ticket
            node_info['vms'].append({
                'id': vm['vmid'],
                'name': vm['name'],
                'ip_addresses': ip_addresses
            })
        
        for lxc in lxcs:
            ip_addresses = get_ipaddresses(lxc['vmid'], node_name, ticket)  # Passer le ticket
            node_info['lxcs'].append({
                'id': lxc['vmid'],
                'name': lxc['name'],
                'ip_addresses': ip_addresses
            })

        inventory.append(node_info)

    return inventory

def main():
    inventory = build_inventory()
    write_inventory_to_ini(inventory)

if __name__ == '__main__':
    main()

