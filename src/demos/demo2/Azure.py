import os
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import AzureError
from datetime import datetime
from Report import Report

RED_ALERT_PORTS = [21, 22, 80]
RED_ALERT_PROTOCOLS = ['TCP']

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

def get_azure_credentials():
    try:
        credentials = DefaultAzureCredential()
        return credentials
    except AzureError as e:
        print(f"Error authenticating with Azure: {e}")
        return None

def list_nsgs(credentials, subscription_id):
    try:
        network_client = NetworkManagementClient(credentials, subscription_id)
        nsgs = network_client.network_security_groups.list_all()

        return list(nsgs)
    except AzureError as e:
        print(f"Error retrieving NSGs: {e}")
        return None

def evaluate_nsgs(nsgs, report_to_modify):
    for nsg in nsgs:
        print(f"Evaluating NSG: {nsg.name}")
        for security_rule in nsg.security_rules:
            protocol = security_rule.protocol
            port_range = security_rule.destination_port_range
            direction = security_rule.direction
            access = security_rule.access

            ports = port_range.split("-")
            ports = range(int(ports[0]), int(ports[-1]) + 1) if len(ports) > 1 else [int(ports[0])]

            if any(port in ports for port in RED_ALERT_PORTS) and protocol.upper() in RED_ALERT_PROTOCOLS and direction == 'Inbound' and access == 'Allow':
                print(f"Warning: Rule '{security_rule.name}' allows access on a sensitive port.")
                report_to_modify.add_issue(2, f"Open sensitive port in NSG rule {security_rule.name}", "Modify your rule to restrict access.")

def mitre_detect_unauthorized_access():
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    monitor_client = MonitorManagementClient(credential, subscription_id)

    # Query for failed logins
    query = "AzureActivity | where OperationName == 'Sign-in activity' and ResultType != '0'"
    result = monitor_client.query(subscription_id, {"query": query, "timespan": "PT1H"})

    for event in result:
        print(f"Unauthorized access attempt detected: {event.as_dict()}")

def mitre_check_excessive_permissions():
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    roles = auth_client.role_definitions.list(scope="subscriptions/{}".format(subscription_id))

    for role in roles:
        if 'Owner' in role.role_name or 'Contributor' in role.role_name:
            print(f"Role with potentially excessive permissions found: {role.role_name}")

def mitre_audit_management_console():
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    monitor_client = MonitorManagementClient(credential, subscription_id)

    # Query for management console activities
    query = "AzureActivity | where OperationNameValue contains 'MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE'"
    result = monitor_client.query(subscription_id, {"query": query, "timespan": "P1D"})

    for event in result:
        print(f"Management console activity detected: {event.as_dict()}")

def mitre_validate_security_group_configs():
    credential = DefaultAzureCredential()
    subscription_id = read_subscription_id_from_azure_profile()
    network_client = NetworkManagementClient(credential, subscription_id)

    network_security_groups = network_client.network_security_groups.list_all()

    for nsg in network_security_groups:
        for rule in nsg.security_rules:
            if rule.access == 'Allow' and rule.destination_address_prefix == '*':
                print(f"Overly permissive rule found in NSG {nsg.name}")

def mitre_assess_storage_permissions():
    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)

    storage_accounts = storage_client.storage_accounts.list()

    for account in storage_accounts:
        properties = storage_client.storage_accounts.get_properties(account.resource_group_name, account.name)
        # Check for public access on Blob containers
        if properties.allow_blob_public_access:
            print(f"Public access allowed in storage account: {account.name}")


def run_report_azure():
    dt = datetime.now()
    dtstring = dt.strftime("%Y-%m-%d_%H-%M-%S")
    my_report = Report(dtstring)

    subscription_id = read_subscription_id_from_azure_profile()
    if subscription_id:
        credentials = get_azure_credentials()
        if credentials:
            nsgs = list_nsgs(credentials, subscription_id)
            if nsgs:
                evaluate_nsgs(nsgs, my_report)

    my_report.write_to_json(dtstring + ".json")

run_report_azure()
