import json
from deepdiff import DeepDiff

def load_json(filename):
    
    with open(filename, 'r') as file:
        return json.load(file)

def compare_reports(test_file, expected_file):
    
    test_report = load_json(test_file)
    expected_report = load_json(expected_file)

    test_issues = test_report.get('Report Contents', [])
    expected_issues = expected_report.get('Report Contents', [])

    if len(test_issues) != len(expected_issues):
        print("Fail: The number of issues in the reports do not match.")
        print(f"Test report has {len(test_issues)} issues, expected report has {len(expected_issues)} issues.")
        return

    differences = DeepDiff(test_issues, expected_issues)

    if differences:
        print("Differences found in report issues:")
        print(json.dumps(differences, indent=4))
    else:
        print("Success: No differences found. Both reports have the same issues.")

if __name__ == "__main__":
    compare_reports('test_report.json', 'expected_report.json')
