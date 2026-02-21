import sqlite3

def init_db():
    conn = sqlite3.connect('smartcart.db')
    conn.execute("PRAGMA foreign_keys = ON")

    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())

    conn.commit()
    conn.close()

    print("Database initialized from schema.sql ✅")


if __name__ == "__main__":
    init_db()