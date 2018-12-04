from flask import Flask, request, redirect, render_template, url_for, session
import os
import subprocess as sp
import json
app = Flask(__name__)
app.secret_key = b'\xc0I\xdb\x8eq\x00"\',-W\xa2\xf1\xab\x06u'

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)

def process_response(text):
    data = json.loads(text)
    output=[]
    for layer in data['ancestry']['layers']:
        if layer.get('detected_features', False):
            for feature in layer['detected_features']:
                name=feature.get("name","")
                ns=feature.get("namespace_name","")
                vf=feature.get("version_format","")
                v=feature.get("version","")
                if feature.get("vulnerabilities",False):
                    for vul in feature['vulnerabilities']:
                        row=[]
                        row.append(vul.get('name',""))
                        row.append(vul.get('severity'))
                        if ns=='python':
                            row.append('PyPi')
                        else:
                            row.append(ns)    
                        row.append(name)
                        row.append(v)
                        row.append(vul.get('fixed_by',""))
                        row.append(vul.get('link',""))
                        output.append(row)
    return output
@app.route('/')
def homepage():
    return render_template("index.html")

@app.route('/table')
def table():
    cve_list = session['cve_list']
    return render_template('table.html',cve_list = cve_list)


@app.route('/', methods=['POST'])
def inputform():
    text = request.form['email']
    with cd("~/paclair"):
        response = sp.check_output(["paclair","--conf","conf/conf.yml", "Docker",text,"analyse", "--output-report", "term"])
    cve_list = process_response(response.decode('utf-8'))
    session['cve_list'] = cve_list
    return redirect(url_for('table'))

if __name__ == "__main__":
    app.run()
