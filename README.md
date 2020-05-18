# Azure Virtual Machine Deployment Tool

## Getting Started
1.  Clone this repository
    ```bash
    git clone https://github.com/nexgus/azvmtool
    cd azvmtool
    ```
1.  Install required Microsoft Azure SDK for Python
    ```bash
    pip install -r requirements.txt
    ```
1.  [使用 Azure 入口網站來建立可存取資源的 Azure AD 應用程式和服務主體](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)  
    [Use the Azure portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/zh-tw/azure/active-directory/develop/howto-create-service-principal-portal)  
    Save your subscription ID, application (client) ID, and directory (tenant) ID in a file `./credentials` in json format. For example:
    ```json
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
    python azvm.py create my_resource_group \
        --vm-prefix kafka \
        --quantity 3 \
        --size Standard_B2ms \
        --nsg allow:inbound:tcp:9092:kafka \
        --ns-prefix mykafka \
        --username deployer \
        --pubkey ~/.ssh/id_rsa.pub \
        --disk 1024
    ```  
    After VM is created, it will start automatically.
1.  Deallocate VM.  
    This will deallocate all VMs in the resource group `my_resource_group`.
    ```bash
    python azvm.py stop my_resource_group
    ```
1.  Delete one or more virtual machine(s). The associated resources will be deleted.  
    The following command delete two VMs: `kafka1` and `kafka3`
    ```bash
    python azvm.py del my_resource_group --vm kafka1 kafka3
    ```
1.  Delete resource group.
    This will delete the resource group `my_resource_group`.
    ```bash
    python azvm.py del my_resource_group
    ```
