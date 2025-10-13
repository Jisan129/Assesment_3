from flask import Flask,render_template
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


@app.route('/')
def home():
    hashed_password = generate_password_hash('mypassword123')

    return render_template('index.html')