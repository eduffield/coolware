# main.py
from datetime import datetime
from Report import Report
import AWS
import Azure
import GCP
import sys
from flask import Flask, render_template, redirect, url_for, flash, request
import os
import json

app = Flask(__name__)
app.secret_key = "secret key wowee"

@app.route('/')
def index():
    # Get a list of all JSON files in the 'Reports' folder
    json_files = [f for f in os.listdir('Reports') if f.endswith('.json')]

    # Create a dictionary to store data from each JSON file
    all_report_data = {}
    for file in json_files:
        with open(os.path.join('Reports', file)) as json_file:
            data = json.load(json_file)
            all_report_data[file] = data

    return render_template('index.html', json_files=json_files, all_report_data=all_report_data)

@app.route('/report/<filename>')
def report(filename):
    # Load the specific JSON file based on the filename provided in the URL
    json_file_path = os.path.join('Reports', filename)
    if os.path.isfile(json_file_path):
        with open(json_file_path) as file:
            report_data = json.load(file)
        return render_template('report.html', filename=filename, report_data=report_data)
    else:
        return "File not found"

@app.route('/delete_report/<filename>', methods=['POST'])
def delete_report(filename):
    try:
        os.remove(os.path.join('Reports', filename))
        #flash('Report deleted successfully!', 'success')
    except Exception as e:
        flash(f'Failed to delete report: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/resolve_report/<filename>', methods=['POST'])
def resolve_report(filename):
    try:
        json_file_path = os.path.join('Reports', filename)
        index = int(request.json['index'])  # Get the index of the issue from the request
        with open(json_file_path, 'r+') as file:
            report_data = json.load(file)
            # Update the status of the specified issue to "Resolved"
            report_data['Report Contents'][index]['Status'] = "Resolved"
            file.seek(0)
            json.dump(report_data, file, indent=4)
            file.truncate()
        flash('Report status updated to Resolved successfully!', 'success')
    except Exception as e:
        flash(f'Failed to update report status: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/ignore_report/<filename>', methods=['POST'])
def ignore_report(filename):
    try:
        json_file_path = os.path.join('Reports', filename)
        index = int(request.json['index'])  # Get the index of the issue from the request
        with open(json_file_path, 'r+') as file:
            report_data = json.load(file)
            # Update the status of the specified issue to "Ignored"
            report_data['Report Contents'][index]['Status'] = "Ignored"
            file.seek(0)
            json.dump(report_data, file, indent=4)
            file.truncate()
        flash('Report status updated to Ignored successfully!', 'success')
    except Exception as e:
        flash(f'Failed to update report status: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/activate_issue/<filename>', methods=['POST'])
def activate_issue(filename):
    try:
        json_file_path = os.path.join('Reports', filename)
        index = int(request.json['index'])  # Get the index of the issue from the request
        with open(json_file_path, 'r+') as file:
            report_data = json.load(file)
            # Update the status of the specified issue to "Active"
            report_data['Report Contents'][index]['Status'] = "Active"
            file.seek(0)
            json.dump(report_data, file, indent=4)
            file.truncate()
        flash('Issue status updated to Active successfully!', 'success')
    except Exception as e:
        flash(f'Failed to update issue status: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/report/<filename>/issue/<int:index>')
def issue_details(filename, index):
    json_file_path = os.path.join('Reports', filename)
    if os.path.isfile(json_file_path):
        with open(json_file_path) as file:
            report_data = json.load(file)
            issue_data = report_data["Report Contents"][index]
            return render_template('issue.html', filename=filename, issue_data=issue_data)
    else:
        return "File not found"

def main():
    dt_string = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = Report(report_date=dt_string)

    AWS.scan_aws_resources(report)
    Azure.main(report)
    GCP.main(report)
    report.list_issues()
    report.write_to_json(f"comprehensive_cloud_report_{dt_string}.json")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py [makereport | viewreport]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "makereport":
        main()
    elif command == "viewreport":
        app.run(debug=False)
    else:
        print("Invalid command. Usage: python main.py [makereport | viewreport]")
        sys.exit(1)