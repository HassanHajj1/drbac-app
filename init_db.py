from db_connection import get_db_connection
 
# Connect to PostgreSQL
conn = get_db_connection()
cur = conn.cursor()
 
# Create users table
cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255),
    role VARCHAR(255)
)
''')
 
# Create blocked_users table
cur.execute('''
CREATE TABLE IF NOT EXISTS blocked_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')
 
# Create login_attempts table
cur.execute('''
CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_level VARCHAR(255)
)
''')
 
# Create active_sessions table
cur.execute('''
CREATE TABLE IF NOT EXISTS active_sessions (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')
 
# Commit changes and close connection
conn.commit()
cur.close()
conn.close()
 
print("✅ Tables created successfully.")