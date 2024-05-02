from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from Report import Report, Resource

def check_blob_storage(storage_client, report):
    accounts = storage_client.storage_accounts.list()
    for account in accounts:
        props = storage_client.storage_accounts.get_properties(account.resource_group_name, account.name)
        if props.allow_blob_public_access:
            issue = f"Storage account '{account.name}' allows public blob access."
            remediation = "Disable public blob access for this storage account."
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=[Resource(name=account.name, service='Azure Blob Storage')])
        if not props.encryption.services.blob.enabled:
            issue = f"Storage account '{account.name}' does not have default blob encryption enabled."
            remediation = "Enable default encryption on the blob service."
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=[Resource(name=account.name, service='Azure Blob Storage')])

def check_sql_databases(sql_client, report):
    servers = sql_client.servers.list()
    for server in servers:
        databases = sql_client.databases.list_by_server(server.resource_group_name, server.name)
        for database in databases:
            tde = sql_client.transparent_data_encryptions.get(server.resource_group_name, server.name, database.name)
            if not tde.status == 'Enabled':
                issue = f"SQL Database '{database.name}' on server '{server.name}' does not have Transparent Data Encryption enabled."
                remediation = "Enable Transparent Data Encryption (TDE) for this database."
                report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=[Resource(name=database.name, service='Azure SQL Database')])

            backup = sql_client.backup_short_term_retention_policies.get(server.resource_group_name, server.name, database.name)
            if backup.retention_days < 7:
                issue = f"SQL Database '{database.name}' on server '{server.name}' has short backup retention period."
                remediation = "Increase backup retention period to at least 7 days."
                report.add_issue(severity=2, issue=issue, remediation=remediation, affected_resources=[Resource(name=database.name, service='Azure SQL Database')])

def check_virtual_machines(compute_client, report):
    vms = compute_client.virtual_machines.list_all()
    for vm in vms:
        vm_id = vm.id
        disks = compute_client.disks.list_by_vm(vm.resource_group_name, vm.name)
        for disk in disks:
            if not disk.encryption_settings_collection.enabled:
                issue = f"Virtual Machine '{vm.name}' has an unencrypted disk '{disk.name}'."
                remediation = "Enable encryption on the virtual machine's disks."
                report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=[Resource(name=vm.name, service='Azure Virtual Machine', detail=f"Disk: {disk.name}")])

def check_virtual_machines(compute_client, report):
    vms = compute_client.virtual_machines.list_all()
    for vm in vms:
        vm_id = vm.id
        disks = compute_client.disks.list_by_vm(vm.resource_group_name, vm.name)
        for disk in disks:
            if not disk.encryption_settings_collection.enabled:
                issue = f"Virtual Machine '{vm.name}' has an unencrypted disk '{disk.name}'."
                remediation = "Enable encryption on the virtual machine's disks."
                report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=[Resource(name=vm.name, service='Azure Virtual Machine', detail=f"Disk: {disk.name}")])

def check_network_security_groups(network_client, report):
    nsgs = network_client.network_security_groups.list_all()
    for nsg in nsgs:
        rules = network_client.security_rules.list(nsg.resource_group_name, nsg.name)
        for rule in rules:
            if rule.access == 'Allow' and rule.destination_address_prefix == '*' and (rule.destination_port_range == '*' or rule.destination_port_range == '80' or rule.destination_port_range == '443'):
                issue = f"Network Security Group '{nsg.name}' has an overly permissive rule '{rule.name}'."
                remediation = "Restrict the rule to specific IP ranges and/or specific ports."
                report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=[Resource(name=nsg.name, service='Azure Network Security Group')])


def main(report):
    try:
        credential = DefaultAzureCredential()
        subscription_id = 'your-subscription-id'

        resource_client = ResourceManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)
        sql_client = SqlManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        check_blob_storage(storage_client, report)
        check_sql_databases(sql_client, report)
        check_virtual_machines(compute_client, report)
        check_network_security_groups(network_client, report)
    except:
        print("Cannot connect to Microsoft Azure.")
        pass
