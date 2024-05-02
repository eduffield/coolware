import json

class Report:
    def __init__(self, report_date):
        self.report_date = report_date
        self.report_contents = []

    def add_issue(self, severity, issue, remediation):
        new_issue = {
            "Severity": severity,
            "Issue": issue,
            "Remediation": remediation
        }
        self.report_contents.append(new_issue)

    def list_issues(self):
        print("List of Issues:")
        for issue in self.report_contents:
            print(f"Severity {issue['Severity']}: {issue['Issue']} - {issue['Remediation']}")

    def filter_issues(self, min_severity):
        filtered_issues = [issue for issue in self.report_contents if issue['Severity'] >= min_severity]
        print(f"Issues with Severity >= {min_severity}:")
        for issue in filtered_issues:
            print(f"Severity {issue['Severity']}: {issue['Issue']} - {issue['Remediation']}")

    def clear_report(self):
        self.report_contents = []
        print("Report has been cleared.")

    def write_to_json(self, file_path):
        report_data = {
            "Report Date": self.report_date,
            "Report Contents": self.report_contents
        }

        with open(file_path, 'w') as json_file:
            json.dump(report_data, json_file, indent=2)

if __name__ == "__main__":
    my_report = Report("2024-01-14")

    my_report.add_issue(1, "Low Disk Space", "Free up space by deleting unnecessary files or moving them to an external drive.")
    my_report.add_issue(2, "Outdated Software", "Update the software to the latest version to patch security vulnerabilities and improve performance.")
    my_report.add_issue(3, "Weak Passwords", "Change passwords to strong and unique combinations to enhance account security.")

    my_report.list_issues()

    my_report.filter_issues(2)

    my_report.clear_report()

    my_report.write_to_json("example_report.json")
