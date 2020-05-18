# Azure Virtual Machine Deployment Tool

## Getting Started
1.  Clone this repository
    ```bash
    $ git clone https://github.com/nexgus/azvmtool
    $ cd azvmtool
    ```
1.  Install required Microsoft Azure SDK for Python
    ```bash
    $ pip install -r requirements.txt
    ```
1.  [使用 Azure 入口網站來建立可存取資源的 Azure AD 應用程式和服務主體](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)  
    [Use the Azure portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/zh-tw/azure/active-directory/develop/howto-create-service-principal-portal)  
    Save your subscription ID, application (client) ID, and directory (tenant) ID in a file `./credentials` in json format. For example:
    ```
    {
        'subscription_id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        'client_id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        'tenant_id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        'secret_string': 'xxxxxxx.xxxxxxxxxxxxx.xxxxxxxxxxxx',
    }
    ```
1.  Create 3 VMs in a resource group `my_resource_group`. These two VMs will be naming in `kafka1`, `kafka2`, and `kafka3`. The VM size is `Standard_B2ms`.  
    Each VM share the same network security group: allow inbound TCP port 9092, and the name is `kafka`.  
    Each VM has the same DNS prefix `mykafka`, so the FQDN will be `mykafka1.westus2.cloudapp.azure.com`, `mykafka2.westus2.cloudapp.azure.com` and `mykafka3.westus2.cloudapp.azure.com`.  
    The login username is `deployer`. We don't want to use password authentication, so we assign an RSA public key to each VM by option `--pubkey`.  
    And each VM has an extra data disk with size 1024GB.
    ```bash
    $ python azvm.py create my_resource_group \
        --vm-prefix kafka \
        --quantity 3 \
        --size Standard_B2ms \
        --nsg allow:inbound:tcp:9092:kafka \
        --dns-prefix mykafka \
        --username deployer \
        --pubkey ~/.ssh/id_rsa.pub \
        --disk 1024
    ```  
    After VM is created, it will start automatically.
1.  Deallocate VM.  
    This will deallocate all VMs in the resource group `my_resource_group`.
    ```bash
    $ python azvm.py stop my_resource_group
    ```
1.  Delete one or more virtual machine(s). The associated resources will be deleted.  
    The following command delete two VMs: `kafka1` and `kafka3`
    ```bash
    $ python azvm.py del my_resource_group --vm kafka1 kafka3
    ```
1.  Delete resource group.
    This will delete the resource group `my_resource_group`.
    ```bash
    $ python azvm.py del my_resource_group
    ```

## Syntax
```
$ python azvm.py --help
usage: azvm.py [-h] [-c CREDENTIALS] [--version]
               {create,generate,delete,del,rm,remove,start,run,deallocate,stop,info,show,disp,display}
               ...

Tool for Azure virtual machine management.

optional arguments:
  -h, --help            show this help message and exit
  -c CREDENTIALS, --credentials CREDENTIALS
                        Path to credential file. (default: ./credentials)
  --version             show program's version number and exit

Available commands:
  Operation be executed.

  {create,generate,delete,del,rm,remove,start,run,deallocate,stop,info,show,disp,display}
                        Description
    create (generate)   Create VM(s) in a resource group.
    delete (del, rm, remove)
                        Delete VM(s) or resource group if --vm is not set.
    start (run)         Start VM(s) if exist(s).
    deallocate (stop)   Deallocate VM(s). If --vm is not set, deallocate all
                        VMs in the resource group.
    info (show, disp, display)
                        Display information. If there is not any option be
                        set, list all resource groups.
```

### `create`
```
$ python azvm.py create --help
usage: azvm.py create [-h] [-v VM_PREFIX] [-q QUANTITY] [-s SIZE]
                      [--vnet-prefix VNET_PREFIX]
                      [--subnet-prefix SUBNET_PREFIX] [-g NSG [NSG ...]] -d
                      DNS_PREFIX -u USERNAME [-p PASSWORD]
                      [-k PUBKEY [PUBKEY ...]] [--disk DISK [DISK ...]]
                      [-l LOCATION] [--update]
                      rg

positional arguments:
  rg                    Resource group.

optional arguments:
  -h, --help            show this help message and exit
  -v VM_PREFIX, --vm-prefix VM_PREFIX
                        VM name prefix.
  -q QUANTITY, --quantity QUANTITY
                        VM quantity.
  -s SIZE, --size SIZE  VM size (VM model name). For detail please check Azure
                        portal.
  --vnet-prefix VNET_PREFIX
                        The address prefix of the virtual network interface.
  --subnet-prefix SUBNET_PREFIX
                        The address prefix of the subnet in the virtual
                        network interface.
  -g NSG [NSG ...], --nsg NSG [NSG ...]
                        Network Security Group in
                        ACCESS:DIR:PROTO:PORT_RANGE:NAME format. ACCESS could
                        be "Allow" or "Deny"; DIR could be "Inbond" or
                        "Outbound"; PROTO could be "Tcp", "Udp", "Icmp",
                        "Esp", "*", or "Ah"; PORT_RANGE could be 0-65535 or
                        "*"; NAME must be unique. The highest priority must
                        present first.
  -d DNS_PREFIX, --dns-prefix DNS_PREFIX
                        Domain name label prefix.
  -u USERNAME, --username USERNAME
                        VM login username.
  -p PASSWORD, --password PASSWORD
                        VM login password.
  -k PUBKEY [PUBKEY ...], --pubkey PUBKEY [PUBKEY ...]
                        Path to SSH public key(s). This disable password
                        authentication.
  --disk DISK [DISK ...]
                        Size of created/attached storage(s) size in GB. The
                        first one in this list should be /dev/sdc.
  -l LOCATION, --location LOCATION
                        Location.
  --update              Update resources if they are exist.
```

### `delete`
```
$ python azvm.py delete --help
usage: azvm.py delete [-h] [-v VM [VM ...]] [--keep-nic] [--keep-hdd] rg

positional arguments:
  rg                    Resource group.

optional arguments:
  -h, --help            show this help message and exit
  -v VM [VM ...], --vm VM [VM ...]
                        VM name. If not set, all VMs and their resources in
                        this resource group will be deleted.
  --keep-nic            Keep associated virtual network interface(s).
  --keep-hdd            Keep associated data disk(s).
```

### `start`
```
$ python azvm.py start --help
usage: azvm.py start [-h] [-v VM [VM ...]] rg

positional arguments:
  rg                    Resource group.

optional arguments:
  -h, --help            show this help message and exit
  -v VM [VM ...], --vm VM [VM ...]
                        VM name. If not set, all VMs and their resources in
                        this resource group will be deleted.
```

### `deallocate`
```
$ python azvm.py deallocate --help
usage: azvm.py deallocate [-h] [-v VM [VM ...]] rg

positional arguments:
  rg                    Resource group.

optional arguments:
  -h, --help            show this help message and exit
  -v VM [VM ...], --vm VM [VM ...]
                        VM name. If not set, all VMs in this resource group
                        will be deallocated.
```

### `info`
```
$ python azvm.py info --help
usage: azvm.py info [-h] [--rg RG] [-v VM [VM ...]] [-d]

optional arguments:
  -h, --help            show this help message and exit
  --rg RG               Resource group.
  -v VM [VM ...], --vm VM [VM ...]
                        VM name. If not set, all VMs in this resource group
                        will be deallocated.
  -d, --detail          Show detail info.
```
