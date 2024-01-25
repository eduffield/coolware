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

    def write_to_json(self, file_path):
        report_data = {
            "Report Date": self.report_date,
            "Report Contents": self.report_contents
        }

        with open(file_path, 'w') as json_file:
            json.dump(report_data, json_file, indent=2)

my_report = Report("2024-01-14")

# Add issues to the report
my_report.add_issue(1, "Hello", "Free up space by deleting unnecessary files or moving them to an external drive.")
my_report.add_issue(2, "Outdated Software", "Update the software to the latest version to patch security vulnerabilities and improve performance.")
my_report.add_issue(3, "Weak Passwords", "Change passwords to strong and unique combinations to enhance account security.")

# Write the report to a JSON file
my_report.write_to_json("example_report.json")
