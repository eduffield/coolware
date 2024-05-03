from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
import os
import json
from Report import Report, Resource

def check_blob_storage(storage_client, report, region='your-region'):
    accounts = storage_client.storage_accounts.list()
    for account in accounts:
        props = storage_client.storage_accounts.get_properties(account.resource_group_name, account.name)
        if props.allow_blob_public_access:
            issue = f"Storage account '{account.name}' allows public blob access."
            remediation = "Disable public blob access for this storage account."
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=[Resource(name=account.name, provider='Azure', region=region, service='Azure Blob Storage')])
        if not props.encryption.services.blob.enabled:
            issue = f"Storage account '{account.name}' does not have default blob encryption enabled."
            remediation = "Enable default encryption on the blob service."
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=[Resource(name=account.name, provider='Azure', region=region, service='Azure Blob Storage')])

def check_sql_databases(sql_client, report, region='your-region'):
    servers = sql_client.servers.list()
    for server in servers:
        databases = sql_client.databases.list_by_server(server.resource_group_name, server.name)
        for database in databases:
            tde = sql_client.transparent_data_encryptions.get(server.resource_group_name, server.name, database.name)
            if not tde.status == 'Enabled':
                issue = f"SQL Database '{database.name}' on server '{server.name}' does not have Transparent Data Encryption enabled."
                remediation = "Enable Transparent Data Encryption (TDE) for this database."
                report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=[Resource(name=database.name, provider='Azure', region=region, service='Azure SQL Database')])

            backup = sql_client.backup_short_term_retention_policies.get(server.resource_group_name, server.name, database.name)
            if backup.retention_days < 7:
                issue = f"SQL Database '{database.name}' on server '{server.name}' has short backup retention period."
                remediation = "Increase backup retention period to at least 7 days."
                report.add_issue(severity=2, issue=issue, remediation=remediation, affected_resources=[Resource(name=database.name, provider='Azure', region=region, service='Azure SQL Database')])

def check_virtual_machines(compute_client, report, region='your-region'):
    vms = compute_client.virtual_machines.list_all()
    for vm in vms:
        disks = compute_client.disks.list_by_vm(vm.resource_group_name, vm.name)
        for disk in disks:
            if not disk.encryption_settings_collection.enabled:
                issue = f"Virtual Machine '{vm.name}' has an unencrypted disk '{disk.name}'."
                remediation = "Enable encryption on the virtual machine's disks."
                report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=[Resource(name=vm.name, provider='Azure', region=region, service='Azure Virtual Machine', detail=f"Disk: {disk.name}")])

def check_network_security_groups(network_client, report, region='your-region'):
    nsgs = network_client.network_security_groups.list_all()
    for nsg in nsgs:
        rules = network_client.security_rules.list(nsg.resource_group_name, nsg.name)
        for rule in rules:
            if rule.access == 'Allow' and rule.destination_address_prefix == '*' and (rule.destination_port_range == '*' or rule.destination_port_range == '80' or rule.destination_port_range == '443'):
                issue = f"Network Security Group '{nsg.name}' has an overly permissive rule '{rule.name}'."
                remediation = "Restrict the rule to specific IP ranges and/or specific ports."
                report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=[Resource(name=nsg.name, provider='Azure', region=region, service='Azure Network Security Group')])

def read_subscription_id_from_azure_profile():
    azure_profile_path = os.path.expanduser('~/.azure/azureProfile.json')
    try:
        with open(azure_profile_path, 'r') as file:
            profile = json.load(file)
            subscription_id = profile['subscriptions'][0]['id']
            return subscription_id
    except FileNotFoundError:
        print(f"Azure profile file not found at {azure_profile_path}. Please ensure you are logged in via the Azure CLI.")
        return None
    except (KeyError, IndexError):
        print("Could not parse the subscription ID from the Azure profile. Please check the profile file format.")
        return None

def mitre_detect_unauthorized_access(report, region='your-region'):
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    monitor_client = MonitorManagementClient(credential, subscription_id)

    query = "AzureActivity | where OperationName == 'Sign-in activity' and ResultType != '0'"
    result = monitor_client.query(subscription_id, {"query": query, "timespan": "PT1H"})

    for event in result:
        issue = f"Unauthorized access attempt detected: {event.as_dict()}"
        remediation = "Investigate and address the unauthorized access attempts."
        affected_resources = [Resource(name='Azure Sign-in Activity', provider='Azure', region=region, service='Azure Monitor')]
        report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=affected_resources)

def mitre_check_excessive_permissions(report, region='your-region'):
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    roles = auth_client.role_definitions.list(scope=f"subscriptions/{subscription_id}")

    for role in roles:
        if 'Owner' in role.role_name or 'Contributor' in role.role_name:
            issue = f"Role with potentially excessive permissions found: {role.role_name}"
            remediation = "Review and possibly reduce the level of permissions."
            affected_resources = [Resource(name=role.role_name, provider='Azure', region=region, service='Azure RBAC')]
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=affected_resources)

def mitre_audit_management_console(report, region='your-region'):
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    monitor_client = MonitorManagementClient(credential, subscription_id)

    query = "AzureActivity | where OperationNameValue contains 'MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE'"
    result = monitor_client.query(subscription_id, {"query": query, "timespan": "P1D"})

    for event in result:
        issue = f"Management console activity detected: {event.as_dict()}"
        remediation = "Review management console activities for any unauthorized or suspicious actions."
        affected_resources = [Resource(name='Azure Management Console', provider='Azure', region=region, service='Azure Monitor')]
        report.add_issue(severity=2, issue=issue, remediation=remediation, affected_resources=affected_resources)

def mitre_validate_security_group_configs(report, region='your-region'):
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    network_client = NetworkManagementClient(credential, subscription_id)

    network_security_groups = network_client.network_security_groups.list_all()

    for nsg in network_security_groups:
        for rule in nsg.security_rules:
            if rule.access == 'Allow' and rule.destination_address_prefix == '*':
                issue = f"Overly permissive rule found in NSG {nsg.name}"
                remediation = "Restrict the rule to specific IP ranges and specific ports."
                affected_resources = [Resource(name=nsg.name, provider='Azure', region=region, service='Azure NSG')]
                report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=affected_resources)

def mitre_assess_storage_permissions(report, region='your-region'):
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    storage_client = StorageManagementClient(credential, subscription_id)

    storage_accounts = storage_client.storage_accounts.list()

    for account in storage_accounts:
        properties = storage_client.storage_accounts.get_properties(account.resource_group_name, account.name)
        if properties.allow_blob_public_access:
            issue = f"Public access allowed in storage account: {account.name}"
            remediation = "Disable public access on storage accounts to protect data."
            affected_resources = [Resource(name=account.name, provider='Azure', region=region, service='Azure Storage')]
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=affected_resources)

def main(report):
    try:
        credential = DefaultAzureCredential()
        subscription_id = 'your-subscription-id'
        region = 'US-East'

        resource_client = ResourceManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)
        sql_client = SqlManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        check_blob_storage(storage_client, report, region)
        check_sql_databases(sql_client, report, region)
        check_virtual_machines(compute_client, report, region)
        check_network_security_groups(network_client, report, region)
        mitre_detect_unauthorized_access(report, region)
        mitre_check_excessive_permissions(report, region)
        mitre_audit_management_console(report, region)
        mitre_validate_security_group_configs(report, region)
        mitre_assess_storage_permissions(report, region)

    except:
        print("Cannot connect to Microsoft Azure.")
        pass
