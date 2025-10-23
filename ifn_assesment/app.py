from flask import Flask, request, redirect, session, render_template, url_for, flash, abort
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'change_this_to_random_secret_key_in_production'

# Admin secret key for registration
ADMIN_SECRET_KEY = '    '

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345678'
app.config['MYSQL_DB'] = 'flask_app'

mysql = MySQL(app)


# ==================== CUSTOM DECORATORS ====================

def login_required(f):
    """Decorator to require login for any route"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


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


def photographer_required(f):
    """Decorator to restrict access to photographers only"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'photographer':
            flash('Access denied. Photographer account required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


def customer_required(f):
    """Decorator to restrict access to customers only"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'customer':
            flash('Access denied. Customer account required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


# ==================== PUBLIC ROUTES ====================

@app.route('/')
def home():
    """Home page - accessible to everyone"""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page with role selection"""
    msg = ''

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        role = request.form.get('user_type')
        secret_key = request.form.get('secret_key')
        print(username, password, confirm_password, email, role, secret_key)
        # Validation
        if not username or not password or not role:
            msg = 'Please fill out all required fields!'
        elif len(password) < 6:
            msg = 'Password must be at least 6 characters long!'
        elif password != confirm_password:
            msg = 'Passwords do not match!'
        elif role == 'admin' and secret_key != ADMIN_SECRET_KEY:
            msg = 'Invalid admin secret key!'
        elif role not in ['admin', 'photographer', 'customer']:
            msg = 'Invalid role selected!'
        else:
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists!'
                cursor.close()
            else:
                # Hash the password for security
                hashed_password = generate_password_hash(password)

                # Insert new user with user_type
                cursor.execute(
                    'INSERT INTO users (username, password, email, user_type) VALUES (%s, %s, %s, %s)',
                    (username, hashed_password, email, role)
                )
                mysql.connection.commit()
                cursor.close()

                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))

    return render_template('register.html', msg=msg)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with session creation"""
    msg = ''

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        cursor.close()
        print(username, password)
        print(account)
        # Verify password using hash
        if account and check_password_hash(account[2], password):
            # Create session
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            session['role'] = account[4]  # user_type is at index 4

            flash(f'Welcome back, {username}!', 'success')

            # Redirect based on role
            if account[4] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif account[4] == 'photographer':
                return redirect(url_for('photographer_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            msg = 'Incorrect username or password!'

    return render_template('login.html', msg=msg)


@app.route('/logout')
@login_required
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


# ==================== ADMIN ROUTES ====================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard - manage all users, content, and orders"""
    cursor = mysql.connection.cursor()

    # Get all users
    cursor.execute('SELECT id, username, email, user_type, created_at FROM users')
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

    cursor.close()

    return render_template('admin_dashboard.html',
                           users=users,
                           galleries=galleries,
                           bookings=bookings)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin can delete any user"""
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection.commit()
    cursor.close()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/galleries/delete/<int:gallery_id>', methods=['POST'])
@admin_required
def admin_delete_gallery(gallery_id):
    """Admin can delete any gallery"""
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM galleries WHERE id = %s', (gallery_id,))
    mysql.connection.commit()
    cursor.close()

    flash('Gallery deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# ==================== PHOTOGRAPHER ROUTES ====================

@app.route('/photographer/dashboard')
@photographer_required
def photographer_dashboard():
    """Photographer dashboard - manage own gallery"""
    photographer_id = session['id']

    cursor = mysql.connection.cursor()
    cursor.execute('''
                   SELECT id, title, description, price, image_url, created_at
                   FROM galleries
                   WHERE photographer_id = %s
                   ''', (photographer_id,))
    galleries = cursor.fetchall()

    # Get bookings for this photographer
    cursor.execute('''
                   SELECT b.id, u.username, b.booking_date, b.status, b.total_price
                   FROM bookings b
                            JOIN users u ON b.customer_id = u.id
                   WHERE b.photographer_id = %s
                   ''', (photographer_id,))
    bookings = cursor.fetchall()

    cursor.close()

    return render_template('photographer_dashboard.html',
                           galleries=galleries,
                           bookings=bookings)


@app.route('/photographer/gallery/add', methods=['GET', 'POST'])
@photographer_required
def photographer_add_gallery():
    """Photographer can add to their gallery"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        image_url = request.form.get('image_url')

        cursor = mysql.connection.cursor()
        cursor.execute('''
                       INSERT INTO galleries (photographer_id, title, description, price, image_url)
                       VALUES (%s, %s, %s, %s, %s)
                       ''', (session['id'], title, description, price, image_url))
        mysql.connection.commit()
        cursor.close()

        flash('Gallery item added successfully!', 'success')
        return redirect(url_for('photographer_dashboard'))

    return render_template('photographer_add_gallery.html')


@app.route('/photographer/gallery/edit/<int:gallery_id>', methods=['GET', 'POST'])
@photographer_required
def photographer_edit_gallery(gallery_id):
    """Photographer can edit their own gallery items"""
    cursor = mysql.connection.cursor()

    # Verify ownership
    cursor.execute('SELECT * FROM galleries WHERE id = %s AND photographer_id = %s',
                   (gallery_id, session['id']))
    gallery = cursor.fetchone()

    if not gallery:
        flash('Gallery item not found or unauthorized!', 'danger')
        cursor.close()
        return redirect(url_for('photographer_dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        image_url = request.form.get('image_url')

        cursor.execute('''
                       UPDATE galleries
                       SET title       = %s,
                           description = %s,
                           price       = %s,
                           image_url   = %s
                       WHERE id = %s
                         AND photographer_id = %s
                       ''', (title, description, price, image_url, gallery_id, session['id']))
        mysql.connection.commit()
        cursor.close()

        flash('Gallery item updated successfully!', 'success')
        return redirect(url_for('photographer_dashboard'))

    cursor.close()
    return render_template('photographer_edit_gallery.html', gallery=gallery)


@app.route('/photographer/gallery/delete/<int:gallery_id>', methods=['POST'])
@photographer_required
def photographer_delete_gallery(gallery_id):
    """Photographer can only delete their own gallery items"""
    cursor = mysql.connection.cursor()

    # Verify ownership
    cursor.execute('SELECT photographer_id FROM galleries WHERE id = %s', (gallery_id,))
    gallery = cursor.fetchone()

    if gallery and gallery[0] == session['id']:
        cursor.execute('DELETE FROM galleries WHERE id = %s', (gallery_id,))
        mysql.connection.commit()
        flash('Gallery item deleted successfully!', 'success')
    else:
        flash('Unauthorized action!', 'danger')

    cursor.close()
    return redirect(url_for('photographer_dashboard'))


# ==================== CUSTOMER ROUTES (SHOPPING CART SYSTEM) ====================

@app.route('/customer/dashboard')
@customer_required
def customer_dashboard():
    """Customer dashboard - view bookings and browse"""
    customer_id = session['id']

    cursor = mysql.connection.cursor()

    # Get customer's bookings
    cursor.execute('''
                   SELECT b.id, p.username, b.booking_date, b.status, b.total_price
                   FROM bookings b
                            JOIN users p ON b.photographer_id = p.id
                   WHERE b.customer_id = %s
                   ORDER BY b.created_at DESC
                   ''', (customer_id,))
    bookings = cursor.fetchall()

    cursor.close()

    return render_template('customer_dashboard.html', bookings=bookings)


@app.route('/customer/browse')
@customer_required
def customer_browse():
    """Customer can browse all galleries"""
    cursor = mysql.connection.cursor()
    cursor.execute('''
                   SELECT g.id, g.title, g.description, g.price, g.image_url, u.username, g.photographer_id
                   FROM galleries g
                            JOIN users u ON g.photographer_id = u.id
                   ORDER BY g.created_at DESC
                   ''')
    galleries = cursor.fetchall()
    cursor.close()

    return render_template('customer_browse.html', galleries=galleries)


@app.route('/customer/book/<int:photographer_id>', methods=['GET'])
@customer_required
def customer_book(photographer_id):
    """Customer can view booking form for a photographer"""
    # Get photographer info
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, email FROM users WHERE id = %s AND user_type = %s',
                   (photographer_id, 'photographer'))
    photographer = cursor.fetchone()
    cursor.close()

    if not photographer:
        flash('Photographer not found!', 'danger')
        return redirect(url_for('customer_browse'))

    return render_template('customer_book.html',
                           photographer=photographer,
                           photographer_id=photographer_id)


@app.route('/customer/cart')
@customer_required
def view_cart():
    """View shopping cart"""
    cart = session.get('cart', [])

    # Get photographer details for cart items
    cart_items = []
    total = 0

    if cart:
        cursor = mysql.connection.cursor()
        for item in cart:
            cursor.execute('SELECT username, email FROM users WHERE id = %s', (item['photographer_id'],))
            photographer = cursor.fetchone()
            if photographer:
                cart_items.append({
                    'photographer_id': item['photographer_id'],
                    'photographer_name': photographer[0],
                    'photographer_email': photographer[1],
                    'booking_date': item['booking_date'],
                    'price': item['price'],
                    'service': item.get('service', 'Photography Session')
                })
                total += float(item['price'])
        cursor.close()

    return render_template('cart.html', cart_items=cart_items, total=total)


@app.route('/customer/cart/add', methods=['POST'])
@customer_required
def add_to_cart():
    """Add item to cart"""
    photographer_id = request.form.get('photographer_id')
    booking_date = request.form.get('booking_date')
    price = request.form.get('price')
    service = request.form.get('service', 'Photography Session')

    # Validate inputs
    if not photographer_id or not booking_date or not price:
        flash('Please fill all required fields!', 'danger')
        return redirect(url_for('customer_browse'))

    # Initialize cart if it doesn't exist
    if 'cart' not in session:
        session['cart'] = []

    # Add item to cart
    cart_item = {
        'photographer_id': int(photographer_id),
        'booking_date': booking_date,
        'price': float(price),
        'service': service
    }

    session['cart'].append(cart_item)
    session.modified = True

    flash('Item added to cart successfully!', 'success')
    return redirect(url_for('customer_browse'))


@app.route('/customer/cart/remove/<int:index>', methods=['POST'])
@customer_required
def remove_from_cart(index):
    """Remove item from cart"""
    cart = session.get('cart', [])

    if 0 <= index < len(cart):
        cart.pop(index)
        session['cart'] = cart
        session.modified = True
        flash('Item removed from cart!', 'info')

    return redirect(url_for('view_cart'))


@app.route('/customer/cart/clear', methods=['POST'])
@customer_required
def clear_cart():
    """Clear entire cart"""
    session['cart'] = []
    session.modified = True
    flash('Cart cleared!', 'info')
    return redirect(url_for('view_cart'))


@app.route('/customer/checkout', methods=['GET', 'POST'])
@customer_required
def checkout():
    """Checkout page for cart items or direct booking"""
    # Check if this is a direct checkout from customer_book form
    if request.method == 'POST':
        photographer_id = request.form.get('photographer_id')
        booking_date = request.form.get('booking_date')
        price = request.form.get('price')
        service = request.form.get('service', 'Photography Session')

        # Get photographer details
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT username, email FROM users WHERE id = %s', (photographer_id,))
        photographer = cursor.fetchone()
        cursor.close()

        if photographer:
            cart_items = [{
                'photographer_id': int(photographer_id),
                'photographer_name': photographer[0],
                'booking_date': booking_date,
                'price': float(price),
                'service': service
            }]
            total = float(price)

            # Store in temporary session for checkout
            session['temp_checkout'] = cart_items
            session.modified = True

            return render_template('checkout.html', cart_items=cart_items, total=total)

    # Otherwise, checkout from cart
    cart = session.get('cart', [])

    if not cart:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('customer_browse'))

    # Get photographer details for cart items
    cart_items = []
    total = 0

    cursor = mysql.connection.cursor()
    for item in cart:
        cursor.execute('SELECT username, email FROM users WHERE id = %s', (item['photographer_id'],))
        photographer = cursor.fetchone()
        if photographer:
            cart_items.append({
                'photographer_id': item['photographer_id'],
                'photographer_name': photographer[0],
                'booking_date': item['booking_date'],
                'price': item['price'],
                'service': item.get('service', 'Photography Session')
            })
            total += float(item['price'])
    cursor.close()

    return render_template('checkout.html', cart_items=cart_items, total=total)


@app.route('/customer/checkout/process', methods=['POST'])
@customer_required
def checkout_process():
    """Process the checkout and create bookings for all cart items"""
    cart = session.get('cart', [])

    if not cart:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('customer_browse'))

    # Payment details (in production, you'd process these with a payment gateway)
    name = request.form.get('name')
    contact = request.form.get('contact')
    email = request.form.get('email')
    address = request.form.get('address')

    cursor = mysql.connection.cursor()

    # Create bookings for all cart items
    booking_count = 0
    for item in cart:
        cursor.execute('''
                       INSERT INTO bookings (customer_id, photographer_id, booking_date, total_price, status)
                       VALUES (%s, %s, %s, %s, %s)
                       ''', (session['id'], item['photographer_id'], item['booking_date'], item['price'], 'confirmed'))
        booking_count += 1

    mysql.connection.commit()
    cursor.close()

    # Clear cart after successful checkout
    session['cart'] = []
    session.modified = True

    flash(f'Payment successful! {booking_count} booking(s) have been confirmed.', 'success')
    return redirect(url_for('customer_dashboard'))


# ==================== ERROR HANDLERS ====================

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)