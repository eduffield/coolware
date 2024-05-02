import json
import os

class Resource:
    def __init__(self, **kwargs):
        self.data = kwargs

    def to_json(self):
        return self.data

class Report:
    def __init__(self, report_date):
        self.report_date = report_date
        self.report_contents = []

    def add_issue(self, severity, issue, remediation, affected_resources=None):
        new_issue = {
            "Status": "Active",
            "Severity": severity,
            "Issue": issue,
            "Remediation": remediation,
            "Affected Resources": [resource.to_json() for resource in affected_resources] if affected_resources else []
        }
        self.report_contents.append(new_issue)

    def list_issues(self):
        print("List of Issues:")
        for issue in self.report_contents:
            print(f"Severity {issue['Severity']}: {issue['Issue']} - {issue['Remediation']}")
            if issue['Affected Resources']:
                print("Affected Resources:")
                for resource in issue['Affected Resources']:
                    print(resource)

    def filter_issues(self, min_severity):
        filtered_issues = [issue for issue in self.report_contents if issue['Severity'] >= min_severity]
        print(f"Issues with Severity >= {min_severity}:")
        for issue in filtered_issues:
            print(f"Severity {issue['Severity']}: {issue['Issue']} - {issue['Remediation']}")
            if issue['Affected Resources']:
                print("Affected Resources:")
                for resource in issue['Affected Resources']:
                    print(resource)

    def clear_report(self):
        self.report_contents = []
        print("Report has been cleared.")

    def write_to_json(self, file_path):
        directory = 'Reports'
        if not os.path.exists(directory):
            os.makedirs(directory)
        file_path = os.path.join(directory, file_path)

        report_data = {
            "Report Date": self.report_date,
            "Report Contents": self.report_contents
        }

        with open(file_path, 'w') as json_file:
            json.dump(report_data, json_file, indent=2)

if __name__ == "__main__":
    my_report = Report("2024-01-14")

    resources = [
        Resource(name="SQLDatabase01", region="us-east-1", provider="aws", service="RDS"),
        Resource(name="WebServer02", region="europe-west1", provider="gcp", service="Compute Engine"),
        Resource(name="StorageAccount03", region="us-east-2", provider="azure", service="Blob Storage"),
        Resource(name="KubernetesCluster04", region="asia-east1", provider="gcp", service="GKE"),
        Resource(name="FunctionApp05", region="us-west-2", provider="azure", service="Azure Functions"),
        Resource(name="BigDataTable06", region="eu-west-1", provider="aws", service="DynamoDB"),
        Resource(name="CloudSQLDB07", region="us-central1", provider="gcp", service="Cloud SQL"),
        Resource(name="VirtualMachine08", region="uk-south", provider="azure", service="Virtual Machines"),
        Resource(name="DataWarehouse09", region="us-west-1", provider="aws", service="Redshift"),
        Resource(name="AutoScalingGroup10", region="asia-southeast1", provider="gcp", service="Compute Engine"),
        Resource(name="BlobContainer11", region="canada-central", provider="azure", service="Blob Storage"),
        Resource(name="LambdaFunction12", region="us-east-1", provider="aws", service="Lambda"),
        Resource(name="APIGateway13", region="europe-north1", provider="gcp", service="API Gateway"),
        Resource(name="CosmosDB14", region="australia-east", provider="azure", service="Cosmos DB"),
        Resource(name="ElasticLoadBalancer15", region="us-east-2", provider="aws", service="ELB"),
        Resource(name="AppEngine16", region="us-central", provider="gcp", service="App Engine"),
        Resource(name="QueueStorage17", region="japan-east", provider="azure", service="Queue Storage"),
        Resource(name="DocumentDB18", region="eu-west-3", provider="aws", service="DocumentDB"),
        Resource(name="PubSub19", region="us-west2", provider="gcp", service="Pub/Sub"),
        Resource(name="DiskStorage20", region="brazil-south", provider="azure", service="Disk Storage")
    ]

    issues = [
        ("High CPU Usage", "Upgrade or optimize the current instances to handle the load better."),
        ("Data Breach", "Investigate the breach source, inform affected users, and strengthen security measures."),
        ("SSL Certificate Expiry", "Renew SSL certificates before they expire to avoid service interruptions."),
        ("Over Provisioning", "Adjust resource allocation to actual usage to reduce costs."),
        ("Underutilized Database", "Consider downsizing or terminating underutilized databases to save costs."),
        ("Security Group Misconfiguration", "Review and correct inbound and outbound rules."),
        ("Unencrypted Sensitive Data", "Encrypt sensitive data in transit and at rest."),
        ("Root Account Usage", "Avoid using root accounts for daily operations."),
        ("Publicly Accessible Resources", "Restrict access to resources to trusted IP ranges only."),
        ("Out of Date Kernel", "Apply the latest kernel updates to secure the systems."),
        ("API Rate Limiting Not Configured", "Set up rate limiting to protect APIs from abuse."),
        ("Logging and Monitoring Issues", "Implement comprehensive logging and monitoring for all activities."),
        ("Network Latency Problems", "Optimize network configuration to improve latency."),
        ("Incorrect IAM Permissions", "Restrict IAM roles to least privilege access."),
        ("Container Vulnerabilities", "Update containers to use secure base images."),
        ("Hardcoded Secrets", "Remove hardcoded secrets and use secret management tools."),
        ("Orphaned Resources", "Identify and remove resources not in use."),
        ("Load Balancer Downtime", "Ensure high availability configurations for load balancers."),
        ("Deprecated API Usage", "Migrate to supported APIs to ensure functionality."),
        ("High Memory Usage", "Analyze and optimize application memory usage.")
    ]

    for i in range(20):
        selected_resources = resources[i:] + resources[:i]  # rotating resource list
        my_report.add_issue(i % 5 + 1, issues[i][0], issues[i][1], selected_resources[:3])

    my_report.write_to_json("extensive_report.json")

