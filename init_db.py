import sqlite3

conn = sqlite3.connect('database/expense_tracker.db')
c = conn.cursor()

# Create users table
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        security_question TEXT,
        security_answer TEXT
    )
''')

# Create transactions table
c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        type TEXT,
        category TEXT,
        amount REAL,
        date TEXT,
        description TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

conn.commit()
conn.close()

print("Database initialized successfully.")
