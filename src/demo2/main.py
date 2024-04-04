from flask import Flask, render_template, redirect, url_for, flash
import os
import json
from AWS import run_report

run_report()

app = Flask(__name__)
app.secret_key = "c2VjcmV0IGtleSB3b3dlZQ=="

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

    #TODO Make the index page look better
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

if __name__ == '__main__':
    app.run(debug=True)
