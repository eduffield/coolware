'''

AWS core security module

Written by: Evan Duffield

'''


import boto3
from botocore.exceptions import NoCredentialsError
from datetime import datetime
from Report import Report

RED_ALERT_PORTS = 21, 22, 80

def read_aws_credentials(profile_name='default'):
    try:
        session = boto3.Session(profile_name=profile_name)

        credentials = session.get_credentials()

        access_key = credentials.access_key
        secret_key = credentials.secret_key
        token = credentials.token

        return {
            'AccessKey': access_key,
            'SecretKey': secret_key,
            'SessionToken': token
        }

    except NoCredentialsError:
        print("AWS credentials not available.")
        return None

def print_credentials_object():
    credentials = read_aws_credentials()
    if credentials:
        print("AWS Access Key:", credentials['AccessKey'])
        print("AWS Secret Key:", credentials['SecretKey'])
        if credentials['SessionToken']:
            print("AWS Session Token:", credentials['SessionToken'])

class SecurityGroup:
    def __init__(self, group_id, group_name, description, vpc_id, ingress_rules, egress_rules):
        self.group_id = group_id
        self.group_name = group_name
        self.description = description
        self.vpc_id = vpc_id
        self.ingress_rules = ingress_rules
        self.egress_rules = egress_rules

class EC2:
    def __init__(self, instance_id, instance_type, key_name, state, security_groups):
        self.instance_id = instance_id
        self.instance_type = instance_type
        self.key_name = key_name
        self.state = state
        self.security_groups = security_groups

def get_security_groups():
    try:
        ec2_client = boto3.client('ec2')

        response = ec2_client.describe_security_groups()

        security_groups = []
        for group in response['SecurityGroups']:
            security_group = SecurityGroup(
                group_id=group['GroupId'],
                group_name=group['GroupName'],
                description=group['Description'],
                vpc_id=group['VpcId'],
                ingress_rules=group.get('IpPermissions', []),
                egress_rules=group.get('IpPermissionsEgress', [])
            )
            security_groups.append(security_group)

        return security_groups

    except Exception as e:
        print(f"Error: {e}")
        return None

def get_ec2_instances_by_security_group(security_group_id):
    try:
        ec2_resource = boto3.resource('ec2')

        instances = ec2_resource.instances.filter(Filters=[{'Name': 'instance.group-id', 'Values': [security_group_id]}])

        ec2_instances = []
        for instance in instances:
            ec2_instance = EC2(
                instance_id=instance.id,
                instance_type=instance.instance_type,
                key_name=instance.key_name,
                state=instance.state['Name'],
                security_groups=[group['GroupName'] for group in instance.security_groups]
            )
            ec2_instances.append(ec2_instance)

        return ec2_instances

    except Exception as e:
        print(f"Error: {e}")
        return None
    
def evaluate_route_tables(report_to_modify):
    ec2_client = boto3.client('ec2')

    vpcs = ec2_client.describe_vpcs()['Vpcs']

    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        print(f"Route Tables for VPC: {vpc_id}")

        route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']

        for route_table in route_tables:
            route_table_id = route_table['RouteTableId']

            print(f"  Route Table ID: {route_table_id}")

            for route in route_table['Routes']:
                destination = route.get('DestinationCidrBlock', 'N/A')
                target = route.get('GatewayId', 'N/A')

                print(f"    Destination: {destination}, Target: {target}")

                if destination == '0.0.0.0/0' and target.startswith('igw-'):
                    print("      Warning: Default route to 0.0.0.0/0 with Internet Gateway. Check if this is intentional for a public subnet.")
                    report_to_modify.add_issue(1, "Default route to 0.0.0.0/0 with Internet Gateway.", "Check if this is intentional for a public subnet.")
                
                if destination.startswith('10.') or destination.startswith('172.') or destination.startswith('192.'):
                    print("      Warning: Internal route detected. Ensure this is intended for private communication.")
                    report_to_modify.add_issue(1, "Internal route detected.", "Ensure this is intended for private communication.")
                
                if destination == '0.0.0.0/0' and not target.startswith('igw-'):
                    print("      Warning: Default route to 0.0.0.0/0 without an Internet Gateway (unused destination). Consider the security implications.")
                    report_to_modify.add_issue(2, "Default route to 0.0.0.0/0 without an Internet Gateway (unused destination).", "Consider the security implications.")
            print()

def run_report():

    dt = datetime.now()

    dtstring = dt.strftime("%Y-%m-%d_%H-%M-%S")

    my_report = Report(dtstring)

    evaluate_route_tables(my_report)

    security_group_id_to_query = 'sg-03e413d5e389d7a1c'

    security_groups_list = get_security_groups()

    if security_groups_list:

        invalid_sgs = []

        for sg in security_groups_list:
            print(f"Security Group ID: {sg.group_id}")
            print(f"Security Group Name: {sg.group_name}")
            print(f"Description: {sg.description}")
            print(f"VPC ID: {sg.vpc_id}")
            print("Ingress Rules:")
            for rule in sg.ingress_rules:
                print(f"  {rule}")
            print("Egress Rules:")
            for rule in sg.egress_rules:
                print(f"  {rule}")


            for rule in sg.ingress_rules:
                port = rule.get('FromPort')
                # print(port)
                ip_ranges = rule.get('IpRanges', [])
                for ip_range in ip_ranges:
                    cidr_ip = ip_range.get('CidrIp', 'N/A')
                    # print(f"  IpRange: {cidr_ip}")

                if port in RED_ALERT_PORTS and cidr_ip == '0.0.0.0/0':
                    print(f"INVALID RULE: PORT {port} IS OPEN TO {cidr_ip}")
                    if port == 21:
                        my_report.add_issue(2, "Open FTP port", "Modify your CIDR block to only accept IPs you trust.")
                    elif port == 22:
                        my_report.add_issue(3, "Open SSH port", "Modify your CIDR block to only accept IPs you trust.")
                    elif port == 80:
                        my_report.add_issue(2, "Open HTTP port", "Make sure your HTTP is routed to HTTPS.")
                    else:
                        my_report.add_issue(1, "Open Unkown port", "Modify your CIDR block to only accept IPs you trust.")
                    invalid_sgs.append(sg)
            print("-" * 40)

            
        ### Print any EC2 containers that use the invalid security groups
        for sg in invalid_sgs:
            security_group_id_to_query = sg.group_id
            ec2_instances_list = get_ec2_instances_by_security_group(security_group_id_to_query)

            if ec2_instances_list:
                for ec2_instance in ec2_instances_list:
                    print(f"Instance ID: {ec2_instance.instance_id}")
                    print(f"Instance Type: {ec2_instance.instance_type}")
                    print(f"Key Name: {ec2_instance.key_name}")
                    print(f"State: {ec2_instance.state}")
                    print(f"Security Groups: {ec2_instance.security_groups}")
                    print("-" * 40)


    my_report.write_to_json(dtstring + ".json")