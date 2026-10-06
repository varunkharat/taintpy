"""A Flask URL variable is user input even though no request.* call appears."""

from flask import Flask, send_file

app = Flask(__name__)


@app.route("/files/<name>")
def download(name):
    return send_file("/srv/files/" + name)
