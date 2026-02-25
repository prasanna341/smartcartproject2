from flask import Flask, render_template, request, flash, session, redirect
import sqlite3
import config
from flask_mail import Mail, Message
from flask import make_response
from pdf_generator import generate_pdf
import random
import bcrypt
import os
from werkzeug.utils import secure_filename
import razorpay
import traceback
import os
print(os.path.abspath("smartcart.db"))

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

UPLOAD_FOLDER = 'static/uploads/product_images'
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# ----------------------------
# EMAIL CONFIGURATION
# ----------------------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = config.MAIL_USE_SSL
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER

mail = Mail(app)

# ----------------------------
# SQLite DATABASE CONNECTION
# ----------------------------
def get_db_connection():
    conn = sqlite3.connect("smartcart.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
#---------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------
# ================================
# ADMIN AUTHENTICATION (SQLITE3)
# ================================

# --------------------------------
# ROUTE 1: ADMIN SIGNUP
# --------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    # Check if email already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email = ?", (email,))
    existing_admin = cursor.fetchone()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return render_template('admin/admin_signup.html')

    # Store temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # Generate OTP
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # Send OTP email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# --------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# --------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# --------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# --------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password.decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password_str)
    )
    conn.commit()
    conn.close()

    # Clear session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# --------------------------------
# ROUTE 4: ADMIN LOGIN
# --------------------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
    admin = cursor.fetchone()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    stored_hashed_password = admin['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html",
                           admin_name=session['admin_name'])


# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO products 
        (name, description, category, price, image, admin_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, description, category, price, filename, admin_id))

    conn.commit()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE 9: DISPLAY ADMIN PRODUCTS ONLY
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']
    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get categories
    cursor.execute("SELECT DISTINCT category FROM products WHERE admin_id = ?", (admin_id,))
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    conn.close()

    return render_template("admin/item_list.html",
                           products=products,
                           categories=categories)


# =================================================================
# ROUTE 10: VIEW SINGLE PRODUCT
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()
    conn.close()

    if not product:
        flash("Unauthorized Access!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, session['admin_id']))

    product = cursor.fetchone()
    conn.close()

    if not product:
        flash("Unauthorized Access!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

# =================================================================
# ROUTE 12: UPDATE PRODUCT
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    if not product:
        conn.close()
        flash("Unauthorized Access!", "danger")
        return redirect('/admin/item-list')

    old_image = product['image']

    # Handle image update
    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)

        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        new_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_path)

        old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image)
        if os.path.exists(old_path):
            os.remove(old_path)

        final_image = new_filename
    else:
        final_image = old_image

    cursor.execute("""
        UPDATE products
        SET name = ?, description = ?, category = ?, price = ?, image = ?
        WHERE product_id = ? AND admin_id = ?
    """, (name, description, category, price, final_image, item_id, admin_id))

    conn.commit()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# DELETE PRODUCT
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT image FROM products
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    if not product:
        conn.close()
        flash("Unauthorized Access!", "danger")
        return redirect('/admin/item-list')

    image_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image'])

    if os.path.exists(image_path):
        os.remove(image_path)

    cursor.execute("""
        DELETE FROM products
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    conn.commit()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


#=====================================================================================
#===========================#USER MODULE==============================================
#======================================================================================


@app.route("/")
def home():
    return redirect("/user-register")

#⭐ ROUTE 1: User Registration (GET + POST)
# =================================================================
# ROUTE 16: USER REGISTRATION
# =================================================================
# ==========================================================
# USER REGISTER
# ==========================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form.get('name').strip()
    email = request.form.get('email').strip()

    session['user_signup_name'] = name
    session['user_signup_email'] = email

    if 'user_otp' not in session:
        session['user_otp'] = str(random.randint(100000, 999999))

    otp = session['user_otp']

    try:
        msg = Message(
            subject="SmartCart - OTP Verification",
            recipients=[email]
        )

        msg.body = f"""
Hello {name},

Your SmartCart OTP is: {otp}

Do not share this OTP with anyone.
"""
        mail.send(msg)
        flash("OTP sent to your email", "success")

    except Exception as e:
        print("Mail Error:", e)
        flash("Error sending OTP. Check mail configuration.", "danger")
        return redirect('/user-register')

    return redirect('/user-verify-otp')


# ==========================================================
# VERIFY OTP (GET + POST) + SAVE USER
# ==========================================================
@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():

    if request.method == 'GET':
        return render_template("user/user_verify_otp.html")

    entered_otp = request.form.get('otp').strip()
    password = request.form.get('password')

    session_otp = session.get('user_otp')

    if not session_otp:
        flash("Session expired. Please register again.", "danger")
        return redirect('/user-register')

    if entered_otp != session_otp:
        flash("Invalid OTP", "danger")
        return redirect('/user-verify-otp')

    # Hash password
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    )

    # Convert bytes → string for SQLite
    hashed_password_str = hashed_password.decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (name, email, password)
        VALUES (?, ?, ?)
    """, (
        session['user_signup_name'],
        session['user_signup_email'],
        hashed_password_str
    ))

    conn.commit()
    conn.close()

    session.pop('user_otp', None)
    session.pop('user_signup_name', None)
    session.pop('user_signup_email', None)

    flash("Registration Successful", "success")
    return redirect('/user/user-login')


# ==========================================================
# USER LOGIN
# ==========================================================
@app.route('/user/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    conn.close()

    if not user:
        flash("User not found", "danger")
        return redirect('/user/user-login')

    stored_password = user['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        flash("Wrong Password", "danger")
        return redirect('/user/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login Successful", "success")
    return redirect('/user/user-dashboard')


# ==========================================================
# USER DASHBOARD (Protected)
# ==========================================================
@app.route('/user/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    return render_template(
        "user/user_home.html",
        user_name=session['user_name']
    )


# ==========================================================
# USER LOGOUT
# ==========================================================
@app.route('/user-logout')
def user_logout():

    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session.pop('cart', None)
    session.pop('razorpay_order_id', None)

    flash("Logged out successfully.", "success")
    return redirect('/user/user-login')


# ==========================================================
# ROUTE 20: USER PRODUCT LISTING (SEARCH + FILTER)
# ==========================================================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get active categories
    cursor.execute("SELECT DISTINCT category FROM products WHERE status='Active'")
    categories = cursor.fetchall()

    # Base query
    query = "SELECT * FROM products WHERE status='Active'"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# ==========================================================
# ROUTE 21: USER PRODUCT DETAILS
# ==========================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND status='Active'",
        (product_id,)
    )

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)


# ==========================================================
# ADD ITEM TO CART
# ==========================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM cart
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE cart
            SET quantity = quantity + 1
            WHERE user_id=? AND product_id=?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, 1)
        """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item added to cart!", "success")
    return redirect(request.referrer)


# ==========================================================
# VIEW CART PAGE
# ==========================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, p.name, p.price, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    grand_total = sum(item['price'] * item['quantity'] for item in cart_items)

    cursor.close()
    conn.close()

    return render_template(
        "user/cart.html",
        cart=cart_items,
        grand_total=grand_total
    )


# ==========================================================
# INCREASE QUANTITY
# ==========================================================
@app.route('/user/cart/increase/<int:pid>')
def increase_quantity(pid):

    if 'user_id' not in session:
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart 
        SET quantity = quantity + 1
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')


# ==========================================================
# DECREASE QUANTITY
# ==========================================================
@app.route('/user/cart/decrease/<int:pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check current quantity
    cursor.execute("""
        SELECT quantity FROM cart 
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    item = cursor.fetchone()

    if item:
        if item['quantity'] > 1:
            cursor.execute("""
                UPDATE cart
                SET quantity = quantity - 1
                WHERE user_id=? AND product_id=?
            """, (session['user_id'], pid))
        else:
            cursor.execute("""
                DELETE FROM cart
                WHERE user_id=? AND product_id=?
            """, (session['user_id'], pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')


# ==========================================================
# REMOVE ITEM COMPLETELY
# ==========================================================
@app.route('/user/cart/remove/<int:pid>')
def remove_from_cart(pid):

    if 'user_id' not in session:
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cart
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item removed!", "success")
    return redirect('/user/cart')


# ==========================================================
# ROUTE: CREATE RAZORPAY ORDER
# ==========================================================
@app.route('/user/pay', methods=['GET', 'POST'])
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    # Get address_id from URL
    address_id = request.args.get('address_id')

    if not address_id:
        flash("Please select delivery address!", "danger")
        return redirect('/user/address')

    session['selected_address_id'] = address_id

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, p.name, p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    if not cart_items:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    total_amount = sum(item['price'] * item['quantity'] for item in cart_items)
    razorpay_amount = int(total_amount * 100)

    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    cursor.close()
    conn.close()

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# ==========================================================
# USER ADDRESS (SQLite3)
# ==========================================================
@app.route('/user/address', methods=['GET', 'POST'])
def user_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':

        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        address_line = request.form.get('address_line')
        city = request.form.get('city')
        state = request.form.get('state')
        pincode = request.form.get('pincode')

        if not all([full_name, phone, address_line, city, state, pincode]):
            flash("Please fill all fields!", "danger")
            return redirect('/user/address')

        cursor.execute("""
            INSERT INTO user_addresses
            (user_id, full_name, phone, address_line, city, state, pincode)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session['user_id'],
            full_name,
            phone,
            address_line,
            city,
            state,
            pincode
        ))

        conn.commit()
        flash("Address added successfully!", "success")

    cursor.execute("""
        SELECT * FROM user_addresses
        WHERE user_id=? ORDER BY created_at DESC
    """, (session['user_id'],))

    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/address.html", addresses=addresses)


# ==========================================================
# PAYMENT SUCCESS PAGE
# ==========================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )


# ==========================================================
# VERIFY PAYMENT + STORE ORDER (SQLite3)
# ==========================================================
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not razorpay_payment_id or not razorpay_order_id or not razorpay_signature:
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        print("SIGNATURE ERROR:", e)
        flash("Payment verification failed.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']
    address_id = session.get('selected_address_id')

    if not address_id:
        flash("Please select delivery address.", "danger")
        return redirect('/user/address')

    address_id = int(address_id)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Validate address
        cursor.execute("""
            SELECT address_id FROM user_addresses
            WHERE address_id=? AND user_id=?
        """, (address_id, user_id))

        valid_address = cursor.fetchone()

        if not valid_address:
            flash("Selected address is invalid.", "danger")
            return redirect('/user/address')

        # Fetch cart items
        cursor.execute("""
            SELECT c.product_id, c.quantity, p.name, p.price
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = ?
        """, (user_id,))

        cart_items = cursor.fetchall()

        if not cart_items:
            flash("Cart is empty.", "danger")
            return redirect('/user/products')

        total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

        # Insert order
        cursor.execute("""
            INSERT INTO orders
            (user_id, address_id, razorpay_order_id,
             razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            address_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'Paid'
        ))

        order_id = cursor.lastrowid

        # Insert order items
        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items
                (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (
                order_id,
                item['product_id'],
                item['name'],
                item['quantity'],
                item['price']
            ))

        # Clear cart
        cursor.execute("DELETE FROM cart WHERE user_id=?", (user_id,))

        session.pop('selected_address_id', None)

        conn.commit()

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_id}")

    except Exception as e:
        conn.rollback()
        print("ORDER DATABASE ERROR:", e)
        flash("There was an error saving your order.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()


# ==========================================================
# ORDER SUCCESS
# ==========================================================
# app.py
from datetime import datetime

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order
    cursor.execute(
        "SELECT * FROM orders WHERE order_id=? AND user_id=?",
        (order_db_id, session['user_id'])
    )
    order = cursor.fetchone()

    # Fetch order items
    cursor.execute(
        "SELECT * FROM order_items WHERE order_id=?",
        (order_db_id,)
    )
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    # -----------------------------
    # FIX for SQLite3 created_at (TEXT)
    # Convert string to datetime
    # -----------------------------
    if order['created_at']:
        order = dict(order)  # convert Row object to dict
        order['created_at'] = datetime.strptime(order['created_at'], "%Y-%m-%d %H:%M:%S")

    return render_template("user/order_success.html", order=order, items=items)

# ==========================================================
# MY ORDERS
# ==========================================================
@app.route('/user/my-orders')
def my_orders():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC",
        (session['user_id'],)
    )

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# ==========================================================
# DOWNLOAD INVOICE PDF
# ==========================================================
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch order
    cursor.execute("""
        SELECT * FROM orders 
        WHERE order_id=? AND user_id=?
    """, (order_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # 2️⃣ Fetch order items
    cursor.execute("""
        SELECT * FROM order_items 
        WHERE order_id=?
    """, (order_id,))
    items = cursor.fetchall()

    # 3️⃣ Fetch user details
    cursor.execute("""
        SELECT name, email 
        FROM users 
        WHERE user_id=?
    """, (session['user_id'],))
    user = cursor.fetchone()

    # 4️⃣ Fetch address using order.address_id ✅ NEW
    address = None
    if order['address_id']:
        cursor.execute("""
            SELECT * FROM user_addresses
            WHERE address_id=?
        """, (order['address_id'],))
        address = cursor.fetchone()

    cursor.close()
    conn.close()

    # 5️⃣ Pass address also to template ✅
    html = render_template(
        "user/invoice.html",
        order=order,
        items=items,
        user=user,
        address=address   # 👈 IMPORTANT
    )

    pdf = generate_pdf(html)

    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

# ==========================================================
# STATIC PAGES
# ==========================================================
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')


#--------------------------------------------------------------------------------------------------
#Run the application
#---------------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)