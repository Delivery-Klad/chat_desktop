import psycopg2

con = psycopg2.connect(
            host="localhost",
            database="postgres",
            user="postgres",
            port="5432",
            password="0258")
cur = con.cursor()

cur.execute("GRANT SELECT, INSERT ON test_gr TO user_access")
#print(cur.fetchall())
cur.execute("SELECT table_catalog, table_schema, table_name, privilege_type "
            "FROM information_schema.table_privileges WHERE grantee = 'register'")
print(cur.fetchall())
# cur.execute("DROP TABLE users CASCADE")
#cur.execute("DELETE FROM users WHERE login='dakak'")
con.commit()
