import psycopg2
import os
def get_db_connection():
   conn = psycopg2.connect(
       dbname='drbac_db',
       user='drbac_db_user',
       password='riTsJExkMR0QBrb9P9fK6R5nInSi1HcQ',
       host='dpg-d09q58ili9vc73ao3le0-a.oregon-postgres.render.com',
       port='5432'
   )
   return conn