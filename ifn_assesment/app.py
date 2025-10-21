from flask import Flask, request, redirect, session, render_template, url_for, flash
from flask_mysqldb import MySQL
from functools import wraps

app = Flask(__name__)
app.secret_key = 'change_this_secret_key'  # Change this to a random secret key

# Admin secret key - change this to your desired secret key
ADMIN_SECRET_KEY = 'admin123secret'
# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345678'
app.config['MYSQL_DB'] = 'flask_app'

mysql = MySQL(app)


def admin_required(f):
    """Decorator to restrict access to admin only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
def home():
    # Check if user is logged in
    if 'loggedin' in session:
        username = session['username']
        user_type = session.get('user_type', 'user')
        return render_template('index.html', username=username, user_type=user_type)
    return render_template('index.html')


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''

    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        user_type = request.form.get('user_type')
        secret_key = request.form.get('secret_key')

        # Validation
        if not username or not password or not user_type:
            msg = 'Please fill out all required fields!'
        elif password != confirm_password:
            msg = 'Passwords do not match!'
        elif user_type == 'admin' and secret_key != ADMIN_SECRET_KEY:
            msg = 'Invalid admin secret key!'
        else:
            # Check if account already exists
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists!'
            else:
                # Insert new user into database with user_type
                cursor.execute('INSERT INTO users (username, password, email, user_type) VALUES (%s, %s, %s, %s)',
                               (username, password, email, user_type))
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

        # Check if account exists
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        cursor.close()
        print(account)
        # Compare plain text passwords directly
        if account and account[3] == password:
            # Password is correct - create session
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            session['user_type'] = account[4]
            if account[4] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif account[4] == 'photographer':
                return redirect(url_for('photographer_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
            # Store user type in session

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
    session.pop('user_type', None)

    return redirect(url_for('login'))


# Protected route example
@app.route('/profile')
def profile():
    # Check if user is logged in
    if 'loggedin' in session:
        username = session['username']
        user_type = session.get('user_type', 'user')
        return render_template('profile.html', username=username, user_type=user_type)

    # User is not logged in, redirect to login page
    return redirect(url_for('login'))


# Admin only route example
@app.route('/admin')
def admin():
    # Check if user is logged in and is admin
    if 'loggedin' in session and session.get('user_type') == 'admin':
        return render_template('admin.html', username=session['username'])

    # Not admin, redirect to home
    return redirect(url_for('home'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard - manage all users, content, and orders"""
    cursor = mysql.connection.cursor()

    # Get all users
    cursor.execute('SELECT id, username, email, role, created_at FROM users')
    users = cursor.fetchall()

    # Get all galleries
    cursor.execute('''
                   SELECT g.id, g.title, g.price, u.username, g.created_at
                   FROM galleries g
                            JOIN users u ON g.photographer_id = u.id
                   ''')
    galleries = cursor.fetchall()

    # Get all bookings
    cursor.execute('''
                   SELECT b.id,
                          c.username as customer,
                          p.username as photographer,
                          b.booking_date,
                          b.status,
                          b.total_price
                   FROM bookings b
                            JOIN users c ON b.customer_id = c.id
                            JOIN users p ON b.photographer_id = p.id
                   ''')
    bookings = cursor.fetchall()

# Photographer only route example
@app.route('/photographer_dashboard')
def photographer_dashboard():
    # Check if user is logged in and is photographer
    if 'loggedin' in session and session.get('user_type') == 'photographer':
        return render_template('photographer_dashboard.html', username=session['username'])

    # Not photographer, redirect to home
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)