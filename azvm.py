#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import azutils as az
import os.path
import re

##############################################################################################################
def show_vm(vm, show_detail=False):
    status = vm.instance_view.statuses[1].display_status.split(' ')[-1]
    print(f'Name: {vm.name} ({status})')
    if show_detail:
        print(f'    Size: {vm.hardware_profile.vm_size}')
        print(f'    Location: {vm.location}')
        print(f'    OS: {vm.storage_profile.image_reference.offer} {vm.storage_profile.image_reference.sku}')
        print(f'        Username: {vm.os_profile.admin_username}')
        print(f'        Password Authentication: {vm.os_profile.linux_configuration.disable_password_authentication}')
        print( '    Data Disks:')
        for data_disk in vm.storage_profile.data_disks:
            disk = az.get_disk(args.rg, data_disk.name)
            print(f'        Name: {disk.name}')
            print(f'        Size: {disk.disk_size_gb}GB')
            print('       ', '-'*22)
        print( '    NICs:')
        for network_interface in vm.network_profile.network_interfaces:
            nic_name = network_interface.id.split('/')[-1]
            nic = az.get_nic(args.rg, nic_name)
            print(f'        Name: {nic.name}')
            print(f'        MAC: {nic.mac_address}')
            for ipcfg in nic.ip_configurations:
                print(f'        Private IP: {ipcfg.private_ip_address}')
                ip_name = ipcfg.public_ip_address.id.split('/')[-1]
                ip = az.get_public_ip(args.rg, ip_name)
                print(f'        Public IP: {ip.ip_address} ({ip.public_ip_allocation_method})')
                print(f'        FQDN: {ip.dns_settings.fqdn}')
            print(f'        Enable Accelerated Networking: {nic.enable_accelerated_networking}')
            nsg_name = nic.network_security_group.id.split('/')[-1]
            nsg = az.get_nsg(args.rg, nsg_name)
            print(f'        Network Security Group: {nsg.name}')
            for rule in nsg.security_rules:
                print(f'            {rule.priority}:{rule.access}:{rule.direction}:{rule.protocol}:{rule.destination_port_range}:{rule.name}')
            print('       ', '-'*22)
    else:
        nic_name = vm.network_profile.network_interfaces[0].id.split('/')[-1]
        nic = az.get_nic(args.rg, nic_name)
        ipcfg = nic.ip_configurations[0]
        ip_name = ipcfg.public_ip_address.id.split('/')[-1]
        ip = az.get_public_ip(args.rg, ip_name)
        print(f'    Private IP: {ipcfg.private_ip_address}')
        print(f'    Public IP: {ip.ip_address} ({ip.public_ip_allocation_method})')
        print(f'    FQDN: {ip.dns_settings.fqdn}')

##############################################################################################################
def standardize_rules(rules):
    def standardrize(rule):
        parts = 'ACCESS:DIR:PROTO:PORT_RANGE:NAME'.split(':')
        rule_parts = rule.split(':')
        if len(rule_parts) != len(parts):
            raise ValueError(f'Invalid --nsg ({rule})')

        msg = f'Invalid --nsg ({rule})'
        for idx, part in enumerate(parts):
            if part == 'PRIORITY':
                try:
                    x = int(rule_parts[idx])
                except ValueError:
                    raise ValueError(msg)
                else:
                    if priority < 100 or priority > 4096:
                        raise ValueError(msg)
                rule_parts[idx] = x

            elif part == 'ACCESS':
                x = rule_parts[idx].lower()
                if x not in ('allow', 'deny'):
                    raise ValueError(msg)
                rule_parts[idx] = x.capitalize()

            elif part == 'DIR':
                x = rule_parts[idx].lower()
                if x not in ('inbound', 'outbound'):
                    raise ValueError(msg)
                rule_parts[idx] = x.capitalize()

            elif part == 'PROTO':
                x = rule_parts[idx].lower()
                if x not in ('tcp', 'udp', 'icmp', 'esp', '*', 'ah'):
                    raise ValueError(msg)
                rule_parts[idx] = x.capitalize()

            elif part == 'PORT_RANGE':
                pass

            elif part == 'NAME':
                pass

        return ':'.join(rule_parts)

    for idx, rule in enumerate(rules):
        rules[idx] = standardrize(rule)

    return rules

##############################################################################################################
def create(args):
    # Resource group
    rg_name = args.rg
    rg = az.get_resource_group(rg_name)
    if args.update or rg is None:
        create_or_update = 'Creating' if rg is None else 'Updating'
        print(f'{create_or_update} resource group {rg_name}...', end='', flush=True)
        rg = az.create_or_update_resource_group(rg_name, args.location)
        print(' \033[92mdone\033[0m.')
    else:
        print(f'Using existed resource group {rg_name}')

    # Virtual network
    vnet_name = f'{args.vm_prefix}-vnet'
    vnet = az.get_vnet(rg_name, vnet_name)
    if args.update or vnet is None:
        create_or_update = 'Creating' if vnet is None else 'Updating'
        print(f'{create_or_update} virtual network {rg_name}/{vnet_name}...', end='', flush=True)
        vnet = az.create_or_update_vnet(rg_name, vnet_name, args.vnet_prefix, args.location)
        print(' \033[92mdone\033[0m.')
    else:
        print(f'Using existed virtual network {rg_name}/{vnet_name}')

    # Subnet
    subnet_name = f'{args.vm_prefix}-subnet'
    subnet = az.get_subnet(rg_name, vnet_name, subnet_name)
    if args.update or subnet is None:
        create_or_update = 'Creating' if subnet is None else 'Updating'
        print(f'{create_or_update} subnet {rg_name}/{vnet_name}/{subnet_name}...', end='', flush=True)
        subnet = az.create_or_update_subnet(rg_name, vnet_name, subnet_name, args.subnet_prefix)
        print(' \033[92mdone\033[0m.')
    else:
        print(f'Using existed subnet {rg_name}/{vnet_name}/{subnet_name}')

    # Network security group
    nsg_name = f'{args.vm_prefix}-nsg'
    nsg = az.get_nsg(rg_name, nsg_name)
    if args.update or nsg is None:
        create_or_update = 'Creating' if nsg is None else 'Updating'
        print(f'{create_or_update} network security group {rg_name}/{nsg_name}...', end='', flush=True)
        nsg = az.create_or_update_nsg(rg_name, nsg_name, args.nsg, args.location)
        print(' \033[92mdone\033[0m.')
    else:
        print(f'Using existed network security group {rg_name}/{nsg_name}')

    for n in range(args.quantity):
        vm_name = f'{args.vm_prefix}{n+1}'

        # Public IP address
        ip_name = f'{vm_name}-ip'
        public_ip = az.get_public_ip(rg_name, ip_name)
        if args.update or public_ip is None:
            create_or_update = 'Creating' if public_ip is None else 'Updating'
            print(f'{create_or_update} public IP address {rg_name}/{ip_name}...', end='', flush=True)
            # dns_label must conform to the following regular expression: ^[a-z][a-z0-9-]{1,61}[a-z0-9]$.
            dns_label = f'{args.dns_prefix}{n+1}'
            public_ip = az.create_or_update_public_ip(rg_name, ip_name, dns_label, args.location)
            print(' \033[92mdone\033[0m.')
        else:
            print(f'Using existed public IP address {rg_name}/{ip_name}')

        # Network interface
        nic_name = f'{vm_name}-nic'
        nic = az.get_nic(rg_name, nic_name)
        if args.update or nic is None:
            create_or_update = 'Creating' if nic is None else 'Updating'
            print(f'{create_or_update} network interface {rg_name}/{nic_name}...', end='', flush=True)
            nic = az.create_or_update_nic(rg_name, nic_name, subnet.id, nsg.id, public_ip, args.location)
            print(' \033[92mdone\033[0m.')
        else:
            print(f'Using existed network interface {rg_name}/{nic_name}')

        # Data disk
        disks = []
        for idx, size in enumerate(args.disk):
            disk_name = f'{vm_name}-DataDisk{idx+1}'
            if args.update:
                print(f'Deleting existed data disk {rg_name}/{disk_name}...', end='', flush=True)
                az.delete_disk(rg_name, disk_name)
                print(' \033[92mdone\033[0m.')

            disk = az.get_disk(rg_name, disk_name)

            if disk is None:
                print(f'Creating data disk {rg_name}/{disk_name}...', end='', flush=True)
                disk = az.create_or_update_disk(rg_name, disk_name, int(size), args.location)
                print(' \033[92mdone\033[0m.')
            else:
                print(f'Using existed data disk {rg_name}/{disk_name}')

            disks.append(disk)

        # Virtual machine
        vm = az.get_vm(rg_name, vm_name)
        if args.update or vm is None:
            create_or_update = 'Creating' if vm is None else 'Updating'
            print(f'{create_or_update} virtual machine {rg_name}/{vm_name}...', end='', flush=True)
            vm = az.create_or_update_vm(
                rg_name=rg_name, 
                vm_name=vm_name, 
                nic_id=nic.id, 
                username=args.username, 
                password=args.password, 
                ssh_keys=args.pubkey,
                disks=disks, 
                vm_size=args.size, 
                location=args.location
            )
            print(' \033[92mdone\033[0m.')
        else:
            print(f'Using existed virtual machine {rg_name}/{vm_name}')

        print(f'Starting virtual machine {rg_name}/{vm_name}...', end='', flush=True)
        az.start_vm(rg_name, vm_name)
        print(' \033[92mdone\033[0m.')

##############################################################################################################
def start(args):
    # Check if resource group exist
    az.get_resource_group(args.rg)

    vm_list = az.get_all_vms(args.rg) if args.vm is None else args.vm
    for vm in vm_list:
        vm_name = vm if isinstance(vm, str) else vm.name
        print(f'Starting virtual machine {args.rg}/{vm_name}...', end='', flush=True)
        az.start_vm(args.rg, vm_name)
        print(' \033[92mdone\033[0m.')

##############################################################################################################
def deallocate(args):
    # Check if resource group exist
    az.get_resource_group(args.rg)

    vm_list = az.get_all_vms(args.rg) if args.vm is None else args.vm
    for vm in vm_list:
        vm_name = vm if isinstance(vm, str) else vm.name
        print(f'Deallocating virtual machine {args.rg}/{vm_name}...', end='', flush=True)
        az.deallocate_vm(args.rg, vm_name)
        print(' \033[92mdone\033[0m.')

##############################################################################################################
def delete(args):
    # Check if resource group exist
    az.get_resource_group(args.rg)

    if args.vm is None:
        print(f'Deleting resource group {args.rg}...', end='', flush=True)
        az.delete_resource_group(args.rg)
        print(' \033[92mdone\033[0m.')

    else:
        vm_list = args.vm
        for vm_name in vm_list:
            if az.get_vm_status(args.rg, vm_name) != 'deallocated':
                print(f'Deallocating virtual machine {args.rg}/{vm_name}...', end='', flush=True)
                az.deallocate_vm(args.rg, vm_name)
                print(' \033[92mdone\033[0m.')

            # Let's get all associated resources if we don't want to keep them
            nic_names, hdd_names = [], []
            if not args.keep_nic:
                nic_names = az.get_vm_nics(args.rg, vm_name)
            if not args.keep_hdd:
                hdd_names = az.get_vm_disks(args.rg, vm_name)

            print(f'Deleting virtual machine {args.rg}/{vm_name}...', end='', flush=True)
            az.delete_vm(args.rg, vm_name)
            print(' \033[92mdone\033[0m.')

            # Since VM has been deleted, the associated resources can be delete without dissociate.
            for nic_name in nic_names:
                print(f'Deleting network interface {args.rg}/{vm_name}/{nic_name}...', end='', flush=True)
                az.delete_nic(args.rg, nic_name)
                print(' \033[92mdone\033[0m.')
            for hdd_name in hdd_names:
                print(f'Deleting data disk {args.rg}/{vm_name}/{hdd_name}...', end='', flush=True)
                az.delete_disk(args.rg, hdd_name)
                print(' \033[92mdone\033[0m.')

##############################################################################################################
def info(args):
    if args.rg is None and args.vm is None:
        rg_list = az.get_all_resource_groups()
        for rg in rg_list:
            rg_dict = rg.as_dict()
            print('='*30)
            print(f'Name: {rg.name}')
            print(f'Location: {rg.location}')

    elif args.vm is None:
        vm_list = az.get_all_vms(args.rg, instance_view=True)
        for vm in vm_list:
            print('='*30)
            show_vm(vm, show_detail=args.detail)

    else:
        for vm_name in args.vm:
            print('='*30)
            vm = az.get_vm(args.rg, vm_name, instance_view=True)
            if vm is None:
                print(f'Cannot find virtual machine "{vm_name}" or resource group "{args.rg}".')
            else:
                show_vm(vm, show_detail=args.detail)

##############################################################################################################
def main(args):
    # Validate arguments for create
    if args.nsg:
        args.nsg = standardize_rules(args.nsg)
    if args.pubkey:
        pubkeys = []
        for filepath in args.pubkey:
            filepath = os.path.expanduser(filepath)
            with open(filepath, 'r') as fp:
                pubkey = fp.read()
                if not pubkey.startswith('ssh-rsa '):
                    raise ValueError(f'{filepath} is not an RSA public key file.')
            pubkeys.append(pubkey.strip())
        args.pubkey = pubkeys
    if args.dns_label:
        if re.match('^[a-z][a-z0-9-]{1,61}[a-z0-9]$', args.dns_label) is None:
            raise ValueError('--dns-label must match regex "^[a-z][a-z0-9-]{1,61}[a-z0-9]$"')
    if args.disk is None:
        args.disk = []
    else:
        args.disk = [args.disk]

    print('Initial Azure...', end='', flush=True)
    az.init(args.credentials)
    print(' \033[92mdone\033[0m.')

    functions = {
        'create': create,
        'generate': create,
        'delete': delete,
        'del': delete,
        'remove': delete,
        'rm': delete,
        'start': start,
        'run': start,
        'deallocate': deallocate,
        'stop': deallocate,
        'info': info,
        'show': info,
        'disp': info,
        'display': info,
    }
    functions[args.command](args)

##############################################################################################################
if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Tool for Azure virtual machine management.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-c', '--credentials', 
                        type=str, default='./credentials', 
                        help='Path to credential file.')
    parser.add_argument('--version', action='version',
                        version='0.6.3')

    subparsers = parser.add_subparsers(
        title='Available commands',
        description='Operation be executed.',
        dest='command',
        help='Description',
    )
    cmd_create = subparsers.add_parser('create',
        aliases=['generate'],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help='Create VM(s) in a resource group.')
    cmd_delete = subparsers.add_parser('delete',
        aliases=['del', 'rm', 'remove'], 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help='Delete VM(s) or resource group if --vm is not set.')
    cmd_start = subparsers.add_parser('start', 
        aliases=['run'],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help='Start VM(s) if exist(s).')
    cmd_deallocate = subparsers.add_parser('deallocate', 
        aliases=['stop'], 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help='Deallocate VM(s). If --vm is not set, deallocate all VMs in the resource group.')
    cmd_info = subparsers.add_parser('info',
        aliases=['show', 'disp', 'display'], 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help='Display information. If there is not any option be set, list all resource groups.')

    #-----------------------------------------------------------------------------------------------
    cmd_create.add_argument('rg',
        type=str,
        help='Resource group.')
    cmd_create.add_argument('-v', '--vm-prefix',
        type=str, default='server', 
        help='VM name prefix.')
    cmd_create.add_argument('-q', '--quantity',
        type=int, default=1,
        help='VM quantity.')
    cmd_create.add_argument('-s', '--size',
        type=str, default=az.DEFAULT_VM_SIZE, 
        help='VM size (VM model name). For detail please check Azure portal.')
    cmd_create.add_argument('--vnet-prefix',
        type=str, default='10.0.0.0/16', 
        help='The address prefix of the virtual network interface.')
    cmd_create.add_argument('--subnet-prefix', 
        type=str, default='10.0.0.0/24', 
        help='The address prefix of the subnet in the virtual network interface.')
    cmd_create.add_argument('-g', '--nsg',
        type=str, nargs='+',
        help='Network Security Group in ACCESS:DIR:PROTO:PORT_RANGE:NAME format. '
             'ACCESS could be "Allow" or "Deny"; DIR could be "Inbond" or "Outbound"; '
             'PROTO could be "Tcp", "Udp", "Icmp", "Esp", "*", or "Ah"; '
             'PORT_RANGE could be 0-65535 or "*"; NAME must be unique. '
             'The highest priority must present first.')
    cmd_create.add_argument('-d', '--dns-prefix', 
        type=str, required=True, 
        help='Domain name label prefix.')
    cmd_create.add_argument('-u', '--username', 
        type=str, required=True, 
        help='VM login username.')
    cmd_create.add_argument('-p', '--password', 
        type=str, default=az.DEFAULT_PASSWORD, 
        help='VM login password.')
    cmd_create.add_argument('-k', '--pubkey', 
        type=str, nargs='+', 
        help='Path to SSH public key(s). This disable password authentication.')
    cmd_create.add_argument('--disk', 
        type=int,
        help='Size of created/attached storage(s) size in GB.')
    cmd_create.add_argument('-l', '--location', 
        type=str, default=az.DEFAULT_LOCATION, 
        help='Location.')
    cmd_create.add_argument('--update', action='store_true', 
        help='Update resources if they are exist.')

    #-----------------------------------------------------------------------------------------------
    cmd_start.add_argument(      'rg', 
        type=str, 
        help='Resource group.')
    cmd_start.add_argument('-v', '--vm', 
        type=str, nargs='+', 
        help='VM name. If not set, all VMs and their resources in this resource group '
             'will be deleted.')

    #-----------------------------------------------------------------------------------------------
    cmd_delete.add_argument('rg', 
        type=str, 
        help='Resource group.')
    cmd_delete.add_argument('-v', '--vm', 
        type=str, nargs='+', 
        help='VM name. If not set, all VMs and their resources in this resource group '
             'will be deleted.')
    cmd_delete.add_argument('--keep-nic', 
        action='store_true', 
        help='Keep associated virtual network interface(s).')
    cmd_delete.add_argument('--keep-hdd', 
        action='store_true', 
        help='Keep associated data disk(s).')

    #-----------------------------------------------------------------------------------------------
    cmd_deallocate.add_argument('rg',
        type=str, 
        help='Resource group.')
    cmd_deallocate.add_argument('-v', '--vm', 
        type=str, nargs='+', 
        help='VM name. If not set, all VMs in this resource group will be deallocated.')

    #-----------------------------------------------------------------------------------------------
    cmd_info.add_argument('rg', 
        type=str, nargs='?', 
        help='Resource group.')
    cmd_info.add_argument('-v', '--vm', 
        type=str, nargs='+', 
        help='VM name. If not set, all VMs in this resource group will be deallocated.')
    cmd_info.add_argument('-d', '--detail', 
        action='store_true', 
        help='Show detail info.')

    #-----------------------------------------------------------------------------------------------
    args = parser.parse_args()
    #print(args); sys.exit(0)

    main(args)
