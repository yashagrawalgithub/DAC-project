import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('dac_database.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        level TEXT NOT NULL CHECK(level IN ('top', 'medium', 'low'))
    )
    ''')

    # Create sensitive_data table (Table 1 in your requirements)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sensitive_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data TEXT NOT NULL,
        owner_level TEXT NOT NULL CHECK(owner_level IN ('top', 'medium', 'low')),
        access_granted_to TEXT
    )
    ''')

    # Create grants table to track permissions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_id INTEGER NOT NULL,
        granter_level TEXT NOT NULL,
        grantee_level TEXT NOT NULL,
        FOREIGN KEY (data_id) REFERENCES sensitive_data(id)
    )
    ''')

    # Insert dummy users if they don't exist
    users = [
        ('Dean', generate_password_hash('dean123'), 'top'),
        ('HOD', generate_password_hash('hod123'), 'medium'),
        ('Yash Agrawal', generate_password_hash('yashag123'), 'low'),
        ('Yash Arora', generate_password_hash('yashar123'), 'low')
    ]

    for user in users:
        try:
            cursor.execute('INSERT INTO users (username, password, level) VALUES (?, ?, ?)', user)
        except sqlite3.IntegrityError:
            pass  # User already exists

    data = [
        ('Faculty Details(TOP)', 'top', None),
        ('Salaries (TOP)', 'top', None),
        ('Upcoming Seminar Details (MEDIUM)', 'medium', None),
        ('Attendance (LOW)', 'low', None),
        ('Student Grades (TOP)', 'top', None)
    ]

    for item in data:
        cursor.execute('''
        INSERT OR IGNORE INTO sensitive_data (data, owner_level, access_granted_to) 
        VALUES (?, ?, ?)
        ''', item)

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")