import psycopg2

con = psycopg2.connect(
            host="localhost",
            database="postgres",
            user="postgres",
            port="5432",
            password="0258")
cur = con.cursor()


# cur.execute("CREATE ROLE user_access NOCREATEDB")
cur.execute("GRANT SELECT, INSERT, UPDATE (password) ON users TO user_access")
cur.execute("GRANT SELECT, INSERT, DELETE ON messages TO user_access")
con.commit()
