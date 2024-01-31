from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route('/')
def index():
    with open('testdata.json') as json_file:
        data = json.load(json_file)

    return render_template('index.html', report_data=data)

if __name__ == '__main__':
    app.run(debug=True)
