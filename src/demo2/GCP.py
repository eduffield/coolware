from google.cloud import compute_v1
from google.cloud import resource_manager_v3
from google.auth.exceptions import DefaultCredentialsError
from datetime import datetime
from Report import Report

RED_ALERT_PORTS = ['21', '22', '80']
BROAD_CIDR_BLOCKS = ['0.0.0.0/0']
OVERLY_PERMISSIVE_ROLES = ['roles/owner', 'roles/editor']

class GCPFirewallRule:
    def __init__(self, id, name, description, direction, priority, target_tags, source_ranges, allowed):
        self.id = id
        self.name = name
        self.description = description
        self.direction = direction
        self.priority = priority
        self.target_tags = target_tags
        self.source_ranges = source_ranges
        self.allowed = allowed

def check_bucket_permissions(project_id):
    client = storage.Client(project=project_id)
    buckets = client.list_buckets()
    for bucket in buckets:
        iam_policy = bucket.get_iam_policy()
        for role, members in iam_policy.items():
            if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                print(f"Public access found on bucket {bucket.name}")

def get_firewall_rules():
    try:
        client = compute_v1.FirewallsClient()
        project = 'your-gcp-project-id'
        firewall_rules = client.list(project=project)

        gcp_firewall_rules = []
        for rule in firewall_rules:
            allowed = [{'IPProtocol': a.IPProtocol, 'ports': getattr(a, 'ports', [])} for a in rule.allowed]
            gcp_firewall_rule = GCPFirewallRule(
                id=rule.id,
                name=rule.name,
                description=rule.description,
                direction=rule.direction,
                priority=rule.priority,
                target_tags=rule.target_tags,
                source_ranges=rule.source_ranges,
                allowed=allowed
            )
            gcp_firewall_rules.append(gcp_firewall_rule)

        return gcp_firewall_rules

    except DefaultCredentialsError:
        print("GCP credentials not available.")
        return None

def evaluate_firewall_rules(firewall_rules, report_to_modify):
    for rule in firewall_rules:
        for allowed in rule.allowed:
            for port in allowed.get('ports', []):
                if port in RED_ALERT_PORTS and '0.0.0.0/0' in rule.source_ranges:
                    print(f"INVALID RULE: PORT {port} IS OPEN TO 0.0.0.0/0 in rule {rule.name}")
                    report_to_modify.add_issue(2, f"Open port {port}", "Modify your rule to restrict access.")
                    break

def run_report_gcp():
    dt = datetime.now()
    dtstring = dt.strftime("%Y-%m-%d_%H-%M-%S")
    my_report = Report(dtstring)

    firewall_rules = get_firewall_rules()
    if firewall_rules:
        evaluate_firewall_rules(firewall_rules, my_report)

    my_report.write_to_json(dtstring + ".json")

def get_project_id():
    try:
        _, project = google.auth.default()
        if project is None:
            raise Exception("Default project not set in gcloud SDK")
        return project
    except DefaultCredentialsError:
        print("GCP credentials not available.")
        return None

def list_vpcs_and_subnets(project_id):
    try:
        client = compute_v1.SubnetworksClient()
        subnets = client.aggregated_list(project=project_id)
        for _, subnets_scoped_list in subnets:
            if subnets_scoped_list.subnetworks:
                for subnet in subnets_scoped_list.subnetworks:
                    if subnet.ip_cidr_range in BROAD_CIDR_BLOCKS:
                        print(f"Subnet {subnet.name} in {subnet.region} has a broad CIDR: {subnet.ip_cidr_range}")
    except Exception as e:
        print(f"Error listing VPCs and Subnets: {e}")

def list_external_ip_instances(project_id):
    try:
        client = compute_v1.InstancesClient()
        instances = client.aggregated_list(project=project_id)
        for _, instances_scoped_list in instances:
            if instances_scoped_list.instances:
                for instance in instances_scoped_list.instances:
                    for network_interface in instance.network_interfaces:
                        for access_config in network_interface.access_configs:
                            if access_config.type_ == 'ONE_TO_ONE_NAT':
                                print(f"Instance {instance.name} has an external IP: {access_config.nat_ip}")
    except Exception as e:
        print(f"Error listing instances with external IPs: {e}")

def check_overly_permissive_iam_roles(project_id):
    try:
        client = resource_manager_v3.ProjectsClient()
        policy = client.get_iam_policy(resource=project_id)
        for binding in policy.bindings:
            if binding.role in OVERLY_PERMISSIVE_ROLES:
                print(f"Overly permissive role found: {binding.role} with members {binding.members}")
    except Exception as e:
        print(f"Error checking IAM roles: {e}")

def run_security_inspection():
    project_id = get_project_id()
    if not project_id:
        return
    
    my_report = Report(datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

    list_vpcs_and_subnets(project_id)
    list_external_ip_instances(project_id)
    check_overly_permissive_iam_roles(project_id)

if __name__ == '__main__':
    run_security_inspection()
    run_report_gcp()
