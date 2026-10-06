"""String-built SQL is flagged. A parameterized query is not."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    db = sqlite3.connect("app.db")
    db.execute("SELECT * FROM users WHERE name = '" + name + "'")
    db.execute("SELECT * FROM users WHERE name = ?", (name,))
    return "ok"
