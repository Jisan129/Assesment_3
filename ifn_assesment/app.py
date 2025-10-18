from flask import Flask, request, redirect, session, render_template, url_for, flash
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key = 'change_this_secret_key'  # Change this to a random secret key

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345678'
app.config['MYSQL_DB'] = 'flask_app'

mysql = MySQL(app)


# Home route
@app.route('/')
def home():
    # Check if user is logged in
    if 'loggedin' in session:
        username = session['username']
        return render_template('index.html', username=username)
    return render_template('index.html')


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''

    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Validation
        if not username or not password:
            msg = 'Please fill out the form completely!'
        else:
            # Check if account already exists
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists!'
            else:
                # Insert new user into database (plain text password)
                cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)',
                               (username, password, email))
                mysql.connection.commit()
                cursor.close()

                msg = 'You have successfully registered! Please login.'
                return redirect(url_for('login'))

    return render_template('register.html', msg=msg)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''

    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        print(username)
        print(password)
        cursor = mysql.connection.cursor()
        # Check if account exists
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        cursor.close()
        print(account)
        print(account[2])
        # Compare plain text passwords directly
        if account and account[3] == password:
            # Password is correct - create session
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]

            # Redirect to home page
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username or password!'

    return render_template('login.html', msg=msg)


# Logout route
@app.route('/logout')
def logout():
    # Remove session data
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)

    return redirect(url_for('login'))


# Protected route example
@app.route('/profile')
def profile():
    # Check if user is logged in
    if 'loggedin' in session:
        username = session['username']
        return render_template('profile.html', username=username)

    # User is not logged in, redirect to login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)