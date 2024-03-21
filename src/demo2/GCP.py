from google.cloud import compute_v1
from google.auth.exceptions import DefaultCredentialsError
from datetime import datetime
from Report import Report

RED_ALERT_PORTS = ['21', '22', '80']

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

def get_firewall_rules():
    try:
        client = compute_v1.FirewallsClient()
        project = 'your-gcp-project-id'  # Replace with your GCP project ID
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
                    break  # To avoid duplicate reports for the same rule

def run_report_gcp():
    dt = datetime.now()
    dtstring = dt.strftime("%Y-%m-%d_%H-%M-%S")
    my_report = Report(dtstring)

    firewall_rules = get_firewall_rules()
    if firewall_rules:
        evaluate_firewall_rules(firewall_rules, my_report)

    my_report.write_to_json(dtstring + ".json")

run_report_gcp()
