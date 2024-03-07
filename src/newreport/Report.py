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

# Example Usage:
if __name__ == "__main__":
    my_report = Report("2024-01-14")

    resource1 = Resource(name="disk212122", region="us-east-1")
    resource2 = Resource(name="drive33", region="us-east-2", provider="aws")
    resource3 = Resource(name="db9", region="us-west-2")


    my_report.add_issue(1, "Low Disk Space", "Free up space by deleting unnecessary files or moving them to an external drive.", [resource1, resource2])
    my_report.add_issue(2, "Outdated Software", "Update the software to the latest version to patch security vulnerabilities and improve performance.")
    my_report.add_issue(3, "Weak Passwords", "Change passwords to strong and unique combinations to enhance account security.", [resource1])
    my_report.add_issue(2, "Outdated Software", "Update the software to the latest version to patch security vulnerabilities and improve performance.", [resource1, resource2, resource3])


    my_report.list_issues()
    my_report.write_to_json("report.json")
