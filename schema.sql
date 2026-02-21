PRAGMA foreign_keys = ON;

-- =========================
-- Admin Table
-- =========================
CREATE TABLE IF NOT EXISTS admin (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    password TEXT,
    profile_image TEXT
);

-- =========================
-- Users Table
-- =========================
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

-- =========================
-- Products Table
-- =========================
CREATE TABLE IF NOT EXISTS products (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    category TEXT,
    price REAL NOT NULL,
    image TEXT,
    status TEXT DEFAULT 'Active',
    admin_id INTEGER NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admin(admin_id)
);

-- =========================
-- Items Table (optional cart/admin items)
-- =========================
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    admin_id INTEGER,
    FOREIGN KEY (admin_id) REFERENCES admin(admin_id)
);

-- =========================
-- User Addresses Table
-- =========================
CREATE TABLE IF NOT EXISTS user_addresses (
    address_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    full_name TEXT,
    phone TEXT,
    address_line TEXT,
    city TEXT,
    state TEXT,
    pincode TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- =========================
-- Orders Table
-- =========================
CREATE TABLE IF NOT EXISTS orders (
    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    razorpay_order_id TEXT,
    razorpay_payment_id TEXT,
    amount REAL,
    payment_status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    address_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (address_id) REFERENCES user_addresses(address_id)
);

-- =========================
-- Order Items Table
-- =========================
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    product_name TEXT,
    quantity INTEGER,
    price REAL,
    FOREIGN KEY (order_id) REFERENCES orders(order_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);

-- =========================
-- CART TABLE
-- =========================
CREATE TABLE IF NOT EXISTS cart (
    cart_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1 CHECK(quantity > 0),

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE,

    UNIQUE(user_id, product_id)
);