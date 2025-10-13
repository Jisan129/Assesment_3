# from flask import Flask,render_template
# from werkzeug.security import generate_password_hash, check_password_hash
#
# app = Flask(__name__)
#
#
# @app.route('/')
# def home():
#     hashed_password = generate_password_hash('mypassword123')
#
#     return render_template('index.html')
#
#
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     msg = ''
#     if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
#         username = request.form['username']
#         password = request.form['password']
#         email = request.form['email']
#
#         cursor = mysql.connection.cursor()
#         cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
#         account = cursor.fetchone()
#
#         if account:
#             msg = 'Account already exists!'
#         elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
#             msg = 'Invalid email address!'
#         elif not re.match(r'[A-Za-z0-9]+', username):
#             msg = 'Username must contain only characters and numbers!'
#         elif not username or not password or not email:
#             msg = 'Please fill out the form!'
#         else:
#             hashed_password = generate_password_hash(password)
#             cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
#                            (username, email, hashed_password))
#             mysql.connection.commit()
#             cursor.close()
#             msg = 'You have successfully registered!'
#             return redirect(url_for('login'))
#
#     return render_template('register.html', msg=msg)


from flask import Flask, request, redirect, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'change_this_secret_key'

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345678'
app.config['MYSQL_DB'] = 'flask_app'

mysql = MySQL(app)


@app.route('/')
def home():
    if 'user' in session:
        return f'<h1>Welcome {session["user"]}!</h1><a href="/logout">Logout</a>'
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):
            session['user'] = username
            return redirect('/')
        return '<p style="color:red">Invalid credentials!</p>' + login_form()

    return login_form()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed = generate_password_hash(password)

        cur = mysql.connection.cursor()
        cur.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                    (username, email, hashed))
        mysql.connection.commit()
        cur.close()

        return '<p style="color:green">Registered! <a href="/login">Login here</a></p>'

    return register_form()


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')


def login_form():
    return '''
        <h2>Login</h2>
        <form method="post">
            <input name="username" placeholder="Username" required><br><br>
            <input name="password" type="password" placeholder="Password" required><br><br>
            <button>Login</button>
        </form>
        <p><a href="/register">Register</a></p>
    '''


def register_form():
    return '''
        <h2>Register</h2>
        <form method="post">
            <input name="username" placeholder="Username" required><br><br>
            <input name="email" placeholder="Email" type="email" required><br><br>
            <input name="password" type="password" placeholder="Password" required><br><br>
            <button>Register</button>
        </form>
        <p><a href="/login">Login</a></p>
    '''


if __name__ == '__main__':
    app.run(debug=True)