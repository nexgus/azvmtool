#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import azutils as az

##############################################################################################################
def standardrize_nsg(rules):
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
    # Validate arguments
    if args.nsg:
        args.nsg = standardrize_nsg(args.nsg)
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
    if args.new_rg:
        args.new_sto = True

    rg_name = args.rg
    rg = az.get_resource_group(rg_name)
    if args.update or rg is None:
        rg = az.create_or_update_resource_group(rg_name, args.location)

    vnet_name = f'{args.vm}-vnet'
    vnet = az.get_vnet(rg_name, vnet_name)
    if args.update or vnet is None:
        vnet = az.create_or_update_vnet(rg_name, vnet_name, args.vnet, args.location)

    subnet_name = f'{args.vm}-subnet'
    subnet = az.get_subnet(rg_name, vnet_name, subnet_name)
    if args.update or subnet is None:
        subnet = az.create_or_update_subnet(rg_name, vnet_name, subnet_name, args.subnet)

    nsg_name = f'{args.vm}-nsg'
    nsg = az.get_nsg(rg_name, nsg_name)
    if args.update or nsg is None:
        nsg = az.create_or_update_nsg(rg_name, nsg_name, args.nsg, args.location)

    for n in range(args.quantity):
        vm_name = f'{args.vm}{n+1}'

        ip_name = f'{vm_name}-ip'
        public_ip = az.get_public_ip(rg_name, ip_name)
        if args.update or public_ip is None:
            dns_label = f'{args.dns_prefix}{n+1}' # dns_label must conform to the following regular expression: ^[a-z][a-z0-9-]{1,61}[a-z0-9]$.
            public_ip = az.create_or_update_public_ip(rg_name, ip_name, dns_label, args.location)

        nic_name = f'{vm_name}-nic'
        nic = az.get_nic(rg_name, nic_name)
        if args.update or nic is None:
            nic = az.create_or_update_nic(rg_name, nic_name, subnet.id, nsg.id, public_ip, args.location)

        disks = []
        for idx, size in enumerate(args.disk):
            disk_name = f'{vm_name}-DataDisk{idx+1}'
            disk = az.get_disk(rg_name, disk_name)
            if args.update or disk is None:
                disk = az.create_or_update_disk(rg_name, disk_name, int(size), args.location)
            disks.append(disk)

        vm = az.get_vm(rg_name, vm_name)
        if args.update or vm is None:
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

##############################################################################################################
def deallocate(args):
    pass

##############################################################################################################
def delete(args):
    pass

##############################################################################################################
def info(args):
    if args.rg is None and args.vm is None:
        rg_list = az.get_all_resource_groups()
        print(f'Count: {len(rg_list)}')
        for rg in rg_list:
            rg_dict = rg.as_dict()
            print(f'  {rg_dict["name"]}, {rg_dict["location"]}, {rg_dict["properties"]["provisioning_state"]}')

    elif args.vm is None:
        vm_list = az.get_all_vms(args.rg)
        for vm in vm_list:
            nics = [nic.id.split('/')[-1] for nic in vm.network_profile.network_interfaces]
            print('='*30)
            print(f'Name: {vm.name}')
            print(f'Status: {az.get_vm_status(args.rg, vm.name)}')}
            print(f'Location: {vm.location}')
            print(f'VM SizeL {vm.hardware_profile.vm_size}')

            nic_names = [nic.id.split('/')[-1] for nic in vm.network_profile.network_interfaces]
            print(f'NIC Count: {len(nic_names)}')
            nics = [az.get_nic(args.rg, nic_name) for nic_name in nic_names]
            for nic in nics:
                print(' '*3, '-'*26)
                print(f'    Name: {nic.name}')
                print(f'    Location: {nic.location}')
                for ipcfg in nic.ip_configurations:
                    print(f'Private IP: {ipcfg.private_ip_address}')
                    print(f'Public IP:  {ipcfg.public_ip_address.ip_address}') # Possible None since vm is deallocated.
                    
                    

##############################################################################################################
def main(args):
    az.init(args.credentials)
    functions = {
        'create': create,
        'delete': delete,
        'deallocate': deallocate,
        'info': info,
    }
    functions[args.command](args)

##############################################################################################################
if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Tool for Azure virtual machine management.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-c', '--credentials', 
                        type=str, default='./credentials', 
                        help='Path to credential file.')

    subparsers = parser.add_subparsers(
        title='Available commands',
        description='Operation be executed.',
        dest='command',
        help=f'Description',
    )
    cmd_create     = subparsers.add_parser('create',     aliases=['generate'],     help='Create VM(s) in a resource group.')
    cmd_delete     = subparsers.add_parser('delete',     aliases=['rm', 'remove'], help='Delete VM(s) or resource group if --vm is not set.')
    cmd_deallocate = subparsers.add_parser('deallocate', aliases=['stop'],         help='Deallocate VM(s). If --vm is not set, '
                                                                                        'deallocate all VMs in the resource group.')
    cmd_info       = subparsers.add_parser('info',       aliases=['show', 'disp', 'display'], help='Display information. If there is not any option be set, '
                                                                                                   'list all resource groups.')

    #-----------------------------------------------------------------------------------------------
    cmd_create.add_argument(      'rg',           type=str,                   help='Resource group.')
    cmd_create.add_argument('-v', '--vm-prefix',  type=str, default='server', help='VM name prefix.')
    cmd_create.add_argument('-q', '--quantity',   type=int, default=1,        help='VM quantity.')
    cmd_create.add_argument('-s', '--size',       type=str, default=az.DEFAULT_VM_SIZE, help='VM size (VM model name). For detail please check Azure portal.')
    cmd_create.add_argument(      '--vnet',       type=str, default='10.0.0.0/16', help = 'The address prefix of the virtual network interface.')
    cmd_create.add_argument(      '--subnet',     type=str, default='10.0.0.0/24', help = 'The address prefix of the subnet in the virtual network interface.')
    cmd_create.add_argument('-g', '--nsg',        type=str, nargs='+',        help='Network Security Group in ACCESS:DIR:PROTO:PORT_RANGE:NAME format. '
                                                                                   'ACCESS could be "Allow" or "Deny"; DIR could be "Inbond" or "Outbound"; '
                                                                                   'PROTO could be "Tcp", "Udp", "Icmp", "Esp", "*", or "Ah"; '
                                                                                   'PORT_RANGE could be 0-65535 or "*"; NAME must be unique. '
                                                                                   'The highest priority must present first.')
    cmd_create.add_argument('-d', '--dns-prefix', type=str, required=True,    help='Domain name label prefix.')
    cmd_create.add_argument('-u', '--username',   type=str, required=True,    help='VM login username.')
    cmd_create.add_argument('-p', '--password',   type=str, default=az.DEFAULT_PASSWORD, help='VM login password.')
    cmd_create.add_argument('-k', '--pubkey',     type=str, nargs='+',        help='Path to SSH public key(s). This disable password authentication.')
    cmd_create.add_argument(      '--disk',       type=int, nargs='+',        help='Size of created/attached storage(s) size in GB. '
                                                                                   'The first one in this list should be /dev/sdc.')
    cmd_create.add_argument('-l', '--location',   type=str, default=az.DEFAULT_LOCATION, help='Location.')
    cmd_create.add_argument(      '--update',     action='store_true',        help='Update resources if they are exist.')

    #-----------------------------------------------------------------------------------------------
    cmd_delete.add_argument(      'rg',   type=str,            help='Resource group.')
    cmd_delete.add_argument('-v', '--vm', type=str, nargs='+', help='VM name. If not set, all VMs and their resources in this resource group will be deleted.')

    #-----------------------------------------------------------------------------------------------
    cmd_deallocate.add_argument(      'rg',   type=str,            help='Resource group.')
    cmd_deallocate.add_argument('-v', '--vm', type=str, nargs='+', help='VM name. If not set, all VMs in this resource group will be deallocated.')

    #-----------------------------------------------------------------------------------------------
    cmd_info.add_argument(      '--rg', type=str,            help='Resource group.')
    cmd_info.add_argument('-v', '--vm', type=str, nargs='+', help='VM name. If not set, all VMs in this resource group will be deallocated.')

    #-----------------------------------------------------------------------------------------------
    args = parser.parse_args()
    #print(args); sys.exit(0)

    main(args)
