import os
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
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
            # Assuming the default subscription is to be used
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
        # Authenticate using default credentials
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

            # Azure uses '*' to denote all ports, split port ranges to cover all RED_ALERT_PORTS
            ports = port_range.split("-")
            ports = range(int(ports[0]), int(ports[-1]) + 1) if len(ports) > 1 else [int(ports[0])]

            if any(port in ports for port in RED_ALERT_PORTS) and protocol.upper() in RED_ALERT_PROTOCOLS and direction == 'Inbound' and access == 'Allow':
                print(f"Warning: Rule '{security_rule.name}' allows access on a sensitive port.")
                report_to_modify.add_issue(2, f"Open sensitive port in NSG rule {security_rule.name}", "Modify your rule to restrict access.")

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
