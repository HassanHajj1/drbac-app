import psycopg2
 
def get_db_connection():
    conn = psycopg2.connect(
        dbname='drbac_db',
        user='drbac_user',    # or 'postgres' if you want
        password='Admin123@',
        host='localhost',
        port='5432'
    )
    return conn