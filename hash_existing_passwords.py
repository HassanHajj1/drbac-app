import psycopg2
from utils import hash_password  # your existing hashing function
 
# Connect to the external Render PostgreSQL database
conn = psycopg2.connect(
    host="dpg-d09q58ili9vc73ao3le0-a.oregon-postgres.render.com",
    port=5432,
    database="drbac_db",
    user="drbac_db_user",
    password="riTsJExkMR0QBrb9P9fK6R5nInSi1HcQ"
)
 
cur = conn.cursor()
 
# Fetch all user passwords
cur.execute("SELECT id, password FROM users")
users = cur.fetchall()
 
# Hash and update each one
for user_id, plain_pass in users:
    hashed = hash_password(plain_pass)
    cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user_id))
 
conn.commit()
cur.close()
conn.close()
 
print("✅ All passwords hashed successfully.")