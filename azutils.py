#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os.path
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

rcli = None # ResourceGroupClient
ncli = None # NetworkClient
ccli = None # ComputeClient

##############################################################################################################
def initial(filepath='./credentials'):
    """Initial this module. This function must be called first.

    Args:
      filepath: Path to credientials file.

      A credential file in fact is a JSON file contans the following contents:
        {
            'subscription_id': '<Subscription ID>',
            'client_id': '<Client ID>',
            'tenant_id': '<Tenant ID>',
            'secret_string': '<Secret>',
        }
    """
    global rcli, ncli, ccli
    c, s = credentials(filepath)
    rcli = ResourceManagementClient(c, s)
    ncli = NetworkManagementClient(c, s)
    ccli = ComputeManagementClient(c, s)

##############################################################################################################
def init(filepath='./credentials'):
    """An alias of initial()"""
    initial(filepath)

##############################################################################################################
def credentials(filepath='./credentials'):
    """Returns a subcription ID and a ServicePrincipalCredentials instance.

    Args:
      filepath: Path to credentials file.

      A credential file in fact is a JSON file contans the following contents:
        {
            'subscription_id': '<Subscription ID>',
            'client_id': '<Client ID>',
            'tenant_id': '<Tenant ID>',
            'secret_string': '<Secret>',
        }
    """
    with open(filepath, 'r') as fp:
        d = eval(fp.read())
    c = ServicePrincipalCredentials(
        client_id=d['client_id'],
        secret=d['secret_string'], # authentication-key
        tenant=d['tenant_id']
    )
    return c, d['subscription_id']

##############################################################################################################
def create_or_update_disk(rg_name, disk_name, disk_size=1024, location=DEFAULT_LOCATION):
    """Create an Azure Disk (empty).

    Args:
      rg_name: The name of the resource group.
      disk_name: The name of the managed disk that is being created.
      disk_size: Disk size in GB (default 1024).
      location: Location (default 'westus2').

    Returns:
      A Disk instance.

    Raises:
      CloudError: If it cannot create a resource group.
    """
    return ccli.disks.create_or_update(
        rg_name,
        storage_name,
        {
            'location': location,
            'disk_size_gb': disk_size,
            'creation_data': {
                # attach: Disk will be attached to a VM.
                # copy: Create a new disk or snapshot by copying from a disk or snapshot specified by the given sourceResourceId.
                # empty: Create an empty data disk of a size given by diskSizeGB.
                # from_image: Create a new disk from a platform image specified by the given imageReference or galleryImageReference.
                # import_enum: Create a disk by importing from a blob specified by a sourceUri in a storage account specified by storageAccountId.
                # restore: Create a new disk by copying from a backup recovery point.
                # upload: Create a new disk by obtaining a write token and using it to directly upload the contents of the disk.
                'create_option': DiskCreateOption.empty,
            }
        }
    ).result()

##############################################################################################################
def create_or_update_nic(rg_name, nic_name, subnet_id, nsg_id, public_ip=None, location=DEFAULT_LOCATION):
    """Create an Azure network interface.

    Args:
      rg_name: Resource group name.
      nic_name: The name of network interface.
      subnet_id: Subnet ID.
      nsg_id: NSG ID (default None). If nsg_id is assigned, a correspond NSG is adapted.
      public_ip: A NetworkInterface instance (default None).
      location: Location (default `westus2`).
      force: If True, update the existed one, or delete it then create (default False).

    Returns:
      A NetworkInterface instance.

    Raises:
      CloudError: If the resource group doesn't exist.
    """
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

    return ncli.network_interfaces.create_or_update(
        resource_group_name=rg_name,
        network_interface_name=nic_name,
        parameters=params,
    ).result()

##############################################################################################################
def create_or_update_nsg(rg_name, nsg_name, rules=None, location=DEFAULT_LOCATION, force=False):
    """Create An Azure Network Security Group (NSG).

    Args:
      rg_name: Resource group name. If the resource group doesn't exist, a CloudError exception raised.
      nsg_name: Network security group name.
      rules: A list of NetworkRule instance.
      location: Location (default `westus2`).
      force: If True, update the existed one, or delete it then create (default False).

    Returns:
      A NetworkSecurityGroup instance.
    """
    def update_or_create():
        """A local function to create and return a NetworkSecurityGroup instance."""
        if rules is None: rules = []
        rules = ['Allow:Inbound:Tcp:22:SSH'] + rules # We always open SSH port
        priority = {
            'Inbound': 300,
            'Outbond': 300,
        }
        for rule in rules:
            direction = rule.split(':')[1]
            rule = f'{priority[direction]}:{rule}'
            security_rules.append(security_rule(rule))
            priority[direction] += 10

        params = NetworkSecurityGroup(
            location=location,
            security_rules=security_rules,
        )

        return ncli.network_security_groups.create_or_update(
            resource_group_name=rg_name,
            network_security_group_name=nsg_name,
            parameters=params,
        ).result()

    try:
        nsg = ncli.network_security_groups.get(rg_name, nsg_name)

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            nsg = update_or_create()
        else:
            raise

    else:
        if force:
            delete_nsg(rg_name, nsg_name)
        nsg = update_or_create()

    return nsg

##############################################################################################################
def create_or_update_public_ip(rg_name, public_ip_name, dns_label, location=DEFAULT_LOCATION):
    """Create an Azure Public IP Address.

    Args:
      rg_name: The name of the resource group.
      ip_name: The name of the public IP address.
      dns_label: The DNS lable for the returned PublicIPAddress instance.
      location: Location (default 'westus2').

    Returns:
      A PublicIPAddress instance.

    Raises:
      CloudError: If the resource group doesn't exist.
    """
    params = {
        'location': location,
        'public_ip_allocation_method': 'Dynamic',
        'dns_settings': {
            'domain_name_label': dns_label
        }
    }
    return ncli.public_ip_addresses.create_or_update(
        resource_group_name=rg_name,
        public_ip_address_name=public_ip_name,
        parameters=params,
    ).result()

##############################################################################################################
def create_or_update_resource_group(rg_name, location=DEFAULT_LOCATION):
    """Create an Azure Resource Group.

    Args:
        rg_name: Resource group name.
        location: Location (default 'westus2').

    Returns:
      A ResourceGroup instance.
    """
    return rcli.resource_groups.create_or_update(
        resource_group_name=rg_name,
        parameters={'location': location},
    ).result()

##############################################################################################################
def create_or_update_subnet(rg_name, vnet_name, subnet_name, prefix='10.0.0.0/24'):
    """Creates or updates a subnet in the specified virtual network.

    Args:
      rg_name: The name of the resource group.
      vnet_name: The name of the virtual network.
      subnet_name: The name of the subnet.
      prefix: Address prefix (default 10.0.0.0/24).

    Returns:
      A Subnet instance.
    """
    params = {
        'address_prefix': prefix,
    }
    return cli.subnets.create_or_update(
        resource_group_name=rg_name,
        virtual_network_name=vnet_name,
        subnet_name=subnet_name,
        subnet_parameters=params
    ).result()

##############################################################################################################
def create_or_update_vm(rg_name, vm_name, nic_id, username, password=DEFAULT_PASSWORD, ssh_keys=None,
        disks=None, vm_size=DEFAULT_VM_SIZE, location=DEFAULT_LOCATION):
    """The operation to create or update a virtual machine. Please note some properties can be set only 
    during virtual machine creation.

    Args:
        rg_name: The name of the resource group.
        vm_name: The name of the virtual machine.
        nic_id: The ID of virtual network interface.
        username: Virtual machine login username.
        password: Virtual machine login password (default '1qaz@WSX#EDC4rfv').If ssh_keys is set, virtual 
            machine password authentication will be disabled, which meant you cannot login by input password.
        ssh_keys: A list of SSH public key (default None). If ssh_keys is set, virtual machine password 
            authentication will be disabled, which meant you cannot login by input password.
        disks: A list of Disk instance (default None).
        vm_size: Size (model) of virtual machine (default 'Standard_DS1_v2').
        location: Location (default 'westus2').

    Return:
        A VirtualMachine instance.
    """
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

    if disks:
        LUN_BASE = 12
        data_disks = []
        for idx, disk in enumerate(disks):
            data_disks.append({
                'lun': LUN_BASE + idx,
                'name': disk.name,
                'create_option': DiskCreateOption.attach,
                'managed_disk': {'id': disk.id}
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

    return cli.virtual_machines.create_or_update(
        resource_group_name=rg_name, 
        vm_name=vm_name, 
        parameters=params,
    ).result()

##############################################################################################################
def create_or_update_vnet(rg_name, vnet_name, prefix='10.0.0.0/16', location=DEFAULT_LOCATION):
    """Creates or updates a virtual network in the specified resource group.

    Args:
        rg_name: The name of the resource group.
        vnet_name: The name of the virtual network.
        Prefix: Address prefix (default '10.0.0.0/16').
        location: Location (default 'westus2').

    Returns:
        A VirtualNetwork instance.
    """
    params = {
        'location': location, 
        'address_space': {
            'address_prefixes': ['10.0.0.0/16']
        }
    }

    return cli.virtual_networks.create_or_update(
        resource_group_name=rg_name,
        virtual_network_name=vnet_name,
        parameters=params
    ).result()

##############################################################################################################
def create_security_rule(rule):
    """Returns a SecurityRule instance.

    Args:
      rule: A ':' seperate str instance to represent priority, access, direction, protocol, port range, 
        and name. The format is PRIORITY:ACCESS:DIR:PROTO:PORT_RANGE:NAME, where
            PRIORITY: The priority of the rule. The value can be between 100 and 4096. The priority number 
                must be unique for each rule in the collection. The lower the priority number, the higher 
                the priority of the rule.
            ACCESS: The network traffic is allowed or denied. Possible values include: 'Allow', 'Deny'.
            DIR: The direction of the rule. The direction specifies if rule will be evaluated on incoming 
                or outgoing traffic. Possible values include: 'Inbound', 'Outbound'.
            PROTO: Network protocol this rule applies to. Possible values include: 'Tcp', 'Udp', 'Icmp', 
                'Esp', '*', 'Ah'.
            PORT_RANGE: The destination port or range. Integer or range between 0 and 65535. Asterisk '*' can 
                also be used to match all ports.
            NAME: The name of the resource that is unique within a resource group. This name can be used to 
                access the resource.
    """
    args = rule.split(':')
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
def delete_disk(rg_name, disk_name):
    """Behavior is as same as ccli.disks.delete() except 
        (1) This is a blocking function call.
        (2) It keeps silence even though specified virtual network interface does not exist.

    Args:
        rg_name: The name of resource group.
        disk_name: The name of disk.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        ccli.disks.delete(rg_name, disk_name)
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_nic(rg_name, nic_name):
    """Behavior is as same as ncli.network_interfaces.delete() except 
        (1) This is a blocking function call.
        (2) It keeps silence even though specified virtual network interface does not exist.

    Args:
        rg_name: The name of resource group.
        nic_name: The name of virtual network interface.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        ncli.network_interfaces.delete(rg_name, nic_name).wait()
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_nsg(rg_name, nsg_name):
    """Same behavior with ncli.network_security_groups.delete() except 
        (1) This is a blocking function call.
        (2) It keeps silence even though specified virtual network interface does not exist.

    Args:
        rg_name: The name of resource group.
        nsg_name: The name of network security group.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        ncli.network_security_groups.delete(rg_name, nic_name).wait()
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_public_ip(rg_name, ip_name):
    """Same behavior with ncli.public_ip_addresses.delete() except 
        (1) This is a blocking function call, 2) 
        (2) It keeps silence even though specified virtual network interface does not exist.

    Args:
        rg_name: The name of resource group.
        ip_name: The name of public ip.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        ncli.public_ip_addresses.delete(rg_name, ip_name).wait()
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_resource_group(rg_name):
    """Same behavior with rcli.resource_groups.delete() except it is blocking.

    When you delete a resource group, all of its resources are also
    deleted. Deleting a resource group deletes all of its template
    deployments and currently stored operations.

    Args:
        rg_name: Resource group name.

    Raises:
        CloudError: If any problem.
    """
    try:
        rcli.resource_groups.delete(rg_name).wait()
    except CloudError as ex:
        if ex.error.error == 'ResourceGroupNotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_subnet(rg_name, vnet_name, subnet_name):
    """Same behavior with ncli.subnets.delete() except
    (1) It is blocking.
    (2) It keeps silence even though specified subnet does not exist.

    Args:
        rg_name: The name of the resource group.
        vnet_name: The name of the virtual network interface.
        subnet_name: The name of the subnet.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        rcli.resource_groups.delete(rg_name).wait()
    except CloudError as ex:
        if ex.error.error == 'NotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_vm(rg_name, vm_name):
    """Same behavior with ccli.virtual_machines.delete() except
    (1) It is blocking.
    (2) It keeps silence even though specified virtual machine does not exist.

    Args:
        rg_name: The name of the resource group.
        vm_name: The name of the virtual machine.

    Args:
        CloudError: If the resource group doesn't exist.
    """
    try:
        ccli.virtual_machines.delete(rg_name, vm_name).wait()
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            pass
        else:
            raise

##############################################################################################################
def delete_vnet(rg_name, vnet_name):
    """Same behavior with ncli.virtual_networks.delete() except
    (1) It is blocking.
    (2) It keeps silence even though specified virtual network interface does not exist.

    Args:
        rg_name: The name of the resource group.
        vnet_name: The name of the virtual network interface.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        ncli.virtual_networks.delete(rg_name, vnet_name).wait()
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            pass
        else:
            raise

##############################################################################################################
def get_all_resource_groups():
    """Gets all resource groups.

    Returns:
        A list contains found ResourceGroup instances.
    """
    rg_list = [rg for rg in rcli.resource_groups.list()]
    return rg_list

##############################################################################################################
def get_all_vms(rg_name, instance_view=False):
    """Gets all virtual machines in a specified resource group.

    Args:
        rg_name: The name of the resource group.
        instance_view: Include instance view (default False)

    Returns:
        A list contains found ResourceGroup instances.
    """
    iter = ccli.virtual_machines.list(rg_name)
    vm_list = []
    for vm in iter:
        if instance_view:
            vm = get_vm(rg_name, vm.name, instance_view)
            vm_list.append(vm)
        else:
            vm_list.append(vm)
    return vm_list

##############################################################################################################
def get_disk(rg_name, disk_name):
    """Gets information about a disk.

    Args:
      rg_name: The name of the resource group.
      disk_name: The name of the managed disk that is being created. The name can't be changed after the 
        disk is created. Supported characters for the name are a-z, A-Z, 0-9 and _. The maximum name length 
        is 80 characters.

    Returns:
      A Disk instance if it exists else None.

    Raises:
      CloudError: If resource group doesn't exist.
    """
    try:
        disk = ccli.disks.get(rg_name, disk_name)
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            disk = None
        else:
            raise
    return disk

##############################################################################################################
def get_nic(rg_name, nic_name):
    """Get an Azure network interface.

    Args:
      rg_name: Resource group name.
      nic_name: The name of network interface.

    Returns:
      A NetworkInterface instance if it exists, else None.

    Raises:
      CloudError: If the resource group doesn't exist.
    """
    try:
        nic = ncli.network_interfaces.get(
            resource_group_name=rg_name,
            network_interface_name=nic_name,
        )

    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            nic = None
        else:
            raise

    return nic

##############################################################################################################
def get_nsg(rg_name, nsg_name):
    """Gets the specified network security group.

    Args:
        rg_name: The name of the resource group.
        nsg_name: The name of the network security group.

    Returns:
        A NetworkSecurityGroup instance if it exists else None.

    Raises:
        CloudError: If the resource group doesn't exist.
    """
    try:
        nsg = ncli.network_security_groups.get(rg_name, nsg_name)
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            nsg = None
        else:
            raise

    return nsg

##############################################################################################################
def get_public_ip(rg_name, ip_name):
    """Gets the specified public IP address in a specified resource group.

    Args:
      rg_name: The name of the resource group.
      ip_name: The name of the public IP address.

    Returns:
      A PublicIPAddress instance if it exists else None.

    Raises:
      CloudError: If the resource group doesn't exist.
    """
    try:
        ip = ncli.public_ip_addresses.get(rg_name, ip_name)
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            ip = None
        else:
            raise

    return ip

##############################################################################################################
def get_resource_group(rg_name):
    """Get an Azure Resource Group.

    Args:
        rg_name: The name of resource group.

    Returns:
        An ResourceGroupInstance if it exists, else None.
    """
    try:
        rg = rcli.resource_groups.get(rg_name)
    except CloudError as ex:
        rg = None

    return rg

##############################################################################################################
def get_subnet(rg_name, vnet_name, subnet_name):
    """Gets the specified subnet by virtual network and resource group.

    Args:
      rg_name: The name of the resource group.
      vnet_name: The name of the virtual network.
      subnet_name: The name of the subnet.
      prefix: Address prefix (default: 10.0.0.0/24).

    Returns:
      A Subnet instance if it exists else None.

    Raise:
      CloudError: If it cannot create a resource group.
    """
    try:
        subnet = cli.subnets.get(rg_name, vnet_name, subnet_name).wait()
    except CloudError as ex:
        if ex.error.error == 'NotFound':
            subnet = None
        else:
            raise

    return subnet

##############################################################################################################
def get_vm(rg_name, vm_name, instance_view=False):
    """Retrieves a virtual machine.

    Args:
      rg_name: The name of the resource group.
      vm_name: The name of the virtual machine.
      instance_view: Include instance view (default False)

    Returns:
      A VirtualMachine instance if it exists else None.

    Raises:
      CloudError: If it cannot create a resource group.
    """
    expand = 'instanceView' if instance_view else None
    try:
        vm = ccli.virtual_machines.get(rg_name, vm_name, expand=expand)
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            vm = None
        else:
            raise

    return vm

##############################################################################################################
def get_vm_status(rg_name, vm_name):
    return ccli.virtual_machines.get(
        rg_name, vm_name, 
        expand='instanceView'
    ).instance_view.statuses[1].display_status

##############################################################################################################
def get_vnet(rg_name, vnet_name):
    """Gets the specified virtual network by resource group.

    Args:
        rg_name: The name of the resource group.
        vnet_name: The name of the virtual network.

    Returns:
        A VirtualNetwork instance if it exists else None.

    Raises:
        CloudError: If it cannot create a resource group.
    """
    try:
        vnet = cli.virtual_networks.get(rg_name, vnet_name)
    except CloudError as ex:
        if ex.error.error == 'ResourceNotFound':
            vnet = None
        else:
            raise

    return vnet
