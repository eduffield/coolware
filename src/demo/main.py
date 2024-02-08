from flask import Flask, render_template
from AWS import runreport
import json

runreport()

app = Flask(__name__)

@app.route('/')
def index():
    with open('report.json') as json_file:
        data = json.load(json_file)

    return render_template('index.html', report_data=data)

if __name__ == '__main__':
    app.run(debug=True)
