#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import DiskCreateOption
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkSecurityGroup
from azure.mgmt.network.models import SecurityRule
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_exceptions import CloudError

# Ref:
# (1) https://docs.microsoft.com/zh-tw/azure/virtual-machines/windows/python
# (2) https://docs.microsoft.com/zh-tw/azure/active-directory/develop/howto-create-service-principal-portal
# (3) https://docs.microsoft.com/zh-tw/azure/virtual-machines/linux/create-cli-complete
# (4) https://docs.microsoft.com/zh-tw/azure/virtual-machines/linux/cli-ps-findimage
# (5) API document: https://docs.microsoft.com/en-us/python/api/azure-mgmt-compute
#                   https://docs.microsoft.com/en-us/python/api/azure-mgmt-network
#                   https://docs.microsoft.com/en-us/python/api/azure-mgmt-resource
# (6) https://gist.github.com/rchakra3/b6703a9d5c66e6fc9a7d

##############################################################################################################
DEFAULT_LOCATION = 'westus2'
DEFAULT_PASSWORD = '1qaz@WSX#EDC4rfv'
DEFAULT_VM_SIZE  = 'Standard_DS1_v2'

##############################################################################################################
def get_credentials(filepath='./credentials'):
    with open(filepath, 'r') as fp:
        d = eval(fp.read())
    credentials = ServicePrincipalCredentials(
        client_id=d['client_id'],
        secret=d['secret_string'], # authentication-key
        tenant=d['tenant_id']
    )
    return d['subscription_id'], credentials

##############################################################################################################
def azure_clients(subscription_id, credentials):
    resource_group_client = ResourceManagementClient(credentials, subscription_id)
    network_client = NetworkManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    return resource_group_client, network_client, compute_client

##############################################################################################################
def azure_init(credentials):
    print('Initialize Azure...', end='', flush=True)
    subscription, credentials = get_credentials(credentials)
    rcli, ncli, ccli = azure_clients(subscription, credentials)
    print()
    return rcli, ncli, ccli

##############################################################################################################
def azure_nic(cli, rg_name, nic_name, subnet_id, nsg_id=None, public_ip=None, location=DEFAULT_LOCATION):
    try:
        nic = cli.network_interfaces.get(
            resource_group_name=rg_name,
            network_interface_name=nic_name,
        )
        print(f'Use existed virtual network interface "{nic_name}"')

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            print(f'Create virtual network interface "{nic_name}"...', end='', flush=True)
            ipcfg = {
                'name': f'{nic_name}-ipconfig',
                'subnet': {'id': subnet_id},
            }

            if public_ip:
                ipcfg['public_ip_address'] = public_ip

            params = {
                'location': location,
                'ip_configurations': [ipcfg],
            }

            if nsg_id:
                params['network_security_group'] = {'id': nsg_id}

            nic = cli.network_interfaces.create_or_update(
                resource_group_name=rg_name,
                network_interface_name=nic_name,
                parameters=params,
            ).result()
            print()

        else:
            raise

    return nic

##############################################################################################################
def azure_nsg(cli, rg_name, nsg_name, rules=[], location=DEFAULT_LOCATION):
    try:
        nsg = cli.network_security_groups.get(rg_name, nsg_name)
        print(f'Use existed network security group "{nsg_name}"')

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            print(f'Create network security group "{nsg_name}"...', end='', flush=True)

            # We always open SSH port
            security_rules = [azure_security_rule('300:Allow:Inbound:Tcp:22:SSH')]

            # These are custom rules
            for rule in rules:
                security_rules.append(azure_security_rule(rule))

            params = NetworkSecurityGroup(
                location=location,
                security_rules=security_rules,
            )

            nsg = cli.network_security_groups.create_or_update(
                resource_group_name=rg_name,
                network_security_group_name=nsg_name,
                parameters=params,
            ).result()
            print()

        else:
            raise

    return nsg

##############################################################################################################
def azure_security_rule(rule):
    # PRIORITY:ACCESS:DIR:PROTOCOL:RANGE[:NAME]
    args = rule.split(':')
    if len(args)==5: args.append(None)

    security_rule = SecurityRule(
        priority=int(args[0]),
        access=args[1],
        direction=args[2],
        protocol=args[3],
        source_address_prefix='*',
        destination_address_prefix='*',
        source_port_range='*',
        destination_port_range=args[4],
        name=args[5],
    )

    return security_rule

##############################################################################################################
def azure_public_ip(cli, rg_name, public_ip_name, dns_label=None, location=DEFAULT_LOCATION):
    try:
        public_ip = cli.public_ip_addresses.get(
            resource_group_name=rg_name,
            public_ip_address_name=public_ip_name,
        )
        print(f'Use existed public IP "{public_ip_name}"')

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            print(f'Create public IP "{public_ip_name}"...', end='', flush=True)
            params = {
                'location': location,
                'public_ip_allocation_method': 'Dynamic',
            }
            if dns_label:
                params['dns_settings'] = {'domain_name_label': dns_label}
            public_ip = cli.public_ip_addresses.create_or_update(
                resource_group_name=rg_name,
                public_ip_address_name=public_ip_name,
                parameters=params
            ).result()
            print()

        else:
            raise

    return public_ip

##############################################################################################################
def azure_resource_group(cli, rg_name, location=DEFAULT_LOCATION, force=False):
    def create():
        print(f'Create resource group "{rg_name}"...', end='', flush=True)
        rg = cli.resource_groups.create_or_update(
            resource_group_name=rg_name,
            parameters={'location': location},
        )
        print()
        return rg

    try:
        rg = cli.resource_groups.get(rg_name)

    except CloudError as ex:
        if ex.error.error == 'ResourceGroupNotFound':
            rg = create()
        else:
            raise

    else:
        if force:
            print(f'Delete resource group "{rg_name}"...', end='', flush=True)
            cli.resource_groups.delete(rg_name).wait()
            print()
            rg = create()
        else:
            print(f'Use existed resource group "{rg_name}"')

    return rg

##############################################################################################################
def azure_storage(cli, rg_name, storage_name, location=DEFAULT_LOCATION, force=False):
    def create():
        print(f'Create storage "{storage_name}"...', end='', flush=True)
        storage = cli.disks.create_or_update(
            rg_name,
            storage_name,
            {
                'location': location,
                'disk_size_gb': 1024,
                'creation_data': {
                    'create_option': DiskCreateOption.empty,
                }
            }
        ).result()
        print()
        return storage

    try:
        storage = cli.disks.get(rg_name, storage_name)

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            storage = create()
        else:
            raise

    else:
        if force:
            print(f'Delete storage "{storage_name}"...', end='', flush=True)
            cli.disks.delete(rg_name, storage_name).wait()
            print()
            storage = create()

        else:
            print(f'Use existed storage "{storage_name}"')

    return storage

##############################################################################################################
def azure_subnet(cli, rg_name, vnet_name, subnet_name):
    try:
        subnet = cli.subnets.get(
            resource_group_name=rg_name,
            virtual_network_name=vnet_name,
            subnet_name=subnet_name
        )
        print(f'Use existed subnet "{subnet_name}"')

    except CloudError as ex:
        if ex.error.error == 'NotFound':
            print(f'Create subnet "{subnet_name}"...', end='', flush=True)
            params = {
                'address_prefix': '10.0.0.0/24'
            }
            subnet = cli.subnets.create_or_update(
                resource_group_name=rg_name,
                virtual_network_name=vnet_name,
                subnet_name=subnet_name,
                subnet_parameters=params
            ).result()
            print()

        else:
            raise

    return subnet

##############################################################################################################
def azure_vm(cli, rg_name, vm_name, nic_id, username, password=DEFAULT_PASSWORD, ssh_keys=[],
             storages=[], vm_size=DEFAULT_VM_SIZE, location=DEFAULT_LOCATION):
    def create_or_update(method):
        print(f'{method.capitalize()} virtual machine "{vm_name}"...', end='', flush=True)
        params = {
            'location': location,
            'os_profile': {
                'computer_name': vm_name,
                'admin_username': username,
                'admin_password': password,
            },
            'hardware_profile': {
                'vm_size': vm_size,
            },
            'storage_profile': {
                # https://docs.microsoft.com/zh-tw/azure/virtual-machines/linux/cli-ps-findimage
                # You may get the image list by issue "az vm image list --output table" in Azure CLI
                'image_reference': {
                    'publisher': 'Canonical',
                    'offer': 'UbuntuServer',
                    'sku': '18.04-LTS',
                    'version': 'latest'
                },
            },
            'network_profile': {
                'network_interfaces': [{
                    'id': nic_id
                }]
            },
        }

        if storages:
            LUN_BASE = 12
            data_disks = []
            for idx, storage in enumerate(storages):
                data_disks.append({
                    'lun': LUN_BASE + idx,
                    'name': storage.name,
                    'create_option': DiskCreateOption.attach,
                    'managed_disk': {'id': storage.id}
                })
            params['storage_profile']['data_disks'] = data_disks

        if ssh_keys:
            # https://github.com/Azure/azure-sdk-for-python/issues/745
            # We need to remove params['os_profile']['admin_password'] even though we set
            # params['os_profile']['linux_configuration']['disable_password_authentication'] as True
            del params['os_profile']['admin_password']
            linux_configuration = {
                'disable_password_authentication': True,
                'ssh': {
                    'public_keys': []
                }
            }
            for ssh_key in ssh_keys:
                linux_configuration['ssh']['public_keys'].append({
                    'path': f'/home/{username}/.ssh/authorized_keys',
                    'key_data': ssh_key
                })
            params['os_profile']['linux_configuration'] = linux_configuration
        #print(f'\n{params}'

        vm = cli.virtual_machines.create_or_update(
            resource_group_name=rg_name, 
            vm_name=vm_name, 
            parameters=params,
        ).result()
        print()

        return vm

    try:
        vm = cli.virtual_machines.get(
            resource_group_name=rg_name,
            vm_name=vm_name,
        )
        print(f'Use existed virtual machine "{vm_name}"')

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            vm = create_or_update('Create')
        else:
            raise

    else:
        vm = create_or_update('Update')

    return vm

##############################################################################################################
def azure_vnet(cli, rg_name, vnet_name, location=DEFAULT_LOCATION):
    try:
        vnet = cli.virtual_networks.get(
            resource_group_name=rg_name,
            virtual_network_name=vnet_name,
        )
        print(f'Use existed virtual network "{vnet_name}" ')
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            print(f'Create virtual network "{vnet_name}"...', end='', flush=True)
            params = {
                'location': location, 
                'address_space': {
                    'address_prefixes': ['10.0.0.0/16']
                }
            }
            vnet = cli.virtual_networks.create_or_update(
                resource_group_name=rg_name,
                virtual_network_name=vnet_name,
                parameters=params
            ).result()
            print()
        else:
            raise
    return vnet

##############################################################################################################
def standardrize_nsg(rules):
    def standardrize(rule):
        # PRIORITY:ACCESS:DIR:PROTOCOL:RANGE[:NAME]
        rule = rule.split(':')
        if len(rule) not in (5, 6):
            raise ValueError(f'Invalid --nsg ({rule})')

        msg = f'Invalid --nsg ({rule})'

        # PRIORITY
        try:
            priority = int(rule[0])
        except ValueError:
            raise ValueError(msg)
        else:
            if priority < 100 or priority > 4096:
                raise ValueError(msg)

        # ACCESS
        access = rule[1].lower()
        if access not in ('allow', 'deny'):
            raise ValueError(msg)
        access = access.capitalize()
        rule[1] = access

        # DIR
        direction = rule[2].lower()
        if direction not in ('inbound', 'outbound'):
            raise ValueError(msg)
        direction = direction.capitalize()
        rule[2] = direction

        # PROTOCOL
        protocol = rule[3].lower()
        if protocol not in ('tcp', 'udp', 'icmp', 'esp', '*', 'ah'):
            raise ValueError(msg)
        protocol = protocol.capitalize()
        rule[3] = protocol

        # RANGE
        # to-do

        # NAME
        if len(rule) == 6:
            rule[5] = rule[5].replace(' ', '')

        return ':'.join(rule)

    for idx, rule in enumerate(rules):
        rules[idx] = standardrize(rule)

    return rules

##############################################################################################################
def main(args):
    rcli, ncli, ccli = azure_init(args.credentials)

    rg_name = args.resource_group
    rg = azure_resource_group(rcli, rg_name, 
        location=args.location, 
        force=args.new_rg)

    vnet_name = f'{args.vm}-vnet'
    vnet = azure_vnet(ncli, rg_name, vnet_name, 
        location=args.location)

    subnet_name = f'{args.vm}-subnet'
    subnet = azure_subnet(ncli, rg.name, vnet.name, subnet_name)

    nsg_name = f'{args.vm}-nsg'
    nsg = azure_nsg(ncli, rg_name, nsg_name, 
        rules=args.nsg, 
        location=args.location)

    for n in range(args.quantity):
        vm_name = f'{args.vm}{n+1}'

        # dns_label must conform to the following regular expression: ^[a-z][a-z0-9-]{1,61}[a-z0-9]$.
        dns_label = None
        if args.dns_prefix:
            dns_label = f'{args.dns_prefix}{n+1}'
        public_ip_name = f'{vm_name}-public-ip'
        public_ip = azure_public_ip(ncli, rg_name, public_ip_name, 
            dns_label=dns_label,
            location=args.location)

        nic_name = f'{vm_name}-nic'
        nic = azure_nic(ncli, rg_name, nic_name, subnet.id, nsg.id, public_ip, 
            location=args.location)

        if args.storage:
            storage_name = f'{vm_name}-storage'
            storage = azure_storage(ccli, rg_name, storage_name, 
                location=args.location, 
                force=args.new_sto)

        vm = azure_vm(ccli, rg_name, vm_name, nic.id, args.username, 
            password=args.password, 
            ssh_keys=args.ssh, 
            storages=[storage], 
            vm_size=args.size, 
            location=args.location)

##############################################################################################################
if __name__ == '__main__':
    import argparse
    import os.path

    parser = argparse.ArgumentParser(
        description='Tool for create Azure Virtual Machine(s) in a specified Azure Resource Group.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--credentials',
        type=str, default='./credentials',
        help='Path to credential file.')
    parser.add_argument('-rg', '--resource-group',
        type=str, required=True,
        help='Resource group name.')
    parser.add_argument('-s', '--size',
        type=str, default=DEFAULT_VM_SIZE, 
        help='VM size.')
    parser.add_argument('-nsg', '--nsg',
        type=str, nargs='+',
        help='Network Security Group in PRIORITY:ACCESS:DIR:PROTOCOL:PORT_RANGE[:NAME] format.')
    parser.add_argument('-dns', '--dns-prefix',
        type=str,
        help='Domain name label prefix.')
    parser.add_argument('-v', '--vm',
        type=str, default='server',
        help='VM name prefix.')
    parser.add_argument('-q', '--quantity',
        type=int, default=1,
        help='Number of VM(s)')
    parser.add_argument('-u', '--username',
        type=str, required=True,
        help='VM login username.')
    parser.add_argument('-p', '--password',
        type=str, default=DEFAULT_PASSWORD,
        help='VM login password.')
    parser.add_argument('-ssh', '--ssh',
        type=str, nargs='+',
        help='Path to SSH public key(s). This disable password authentication.')
    parser.add_argument('-sto', '--storage',
        action='store_true',
        help='Attach an extra 1TB storage as data disk.')
    parser.add_argument('-l', '--location',
        type=str, default=DEFAULT_LOCATION, 
        help='Location.')
    parser.add_argument('-nrg', '--new-rg',
        action='store_true',
        help='Remove resource group if it exists.')
    parser.add_argument('-nsto', '--new-sto',
        action='store_true',
        help='Remove storage if it exists.')

    args = parser.parse_args()
    #print(args); import sys; sys.exit(0)

    if args.nsg:
        args.nsg = standardrize_nsg(args.nsg)

    pubkeys = []
    if args.ssh:
        for filepath in args.ssh:
            filepath = os.path.expanduser(filepath)
            with open(filepath, 'r') as fp:
                pubkey = fp.read()
                if not pubkey.startswith('ssh-rsa '):
                    raise ValueError(f'{filepath} is not an RSA public key file.')
            pubkeys.append(pubkey.strip())
        args.ssh = pubkeys

    if args.new_rg:
        args.new_sto = True

    main(args)
