import psycopg2

con = psycopg2.connect(
            host="localhost",
            database="postgres",
            user="dakak1",
            port="5432",
            password="13371337DAda")
cur = con.cursor()


cur.execute("SELECT * FROM users")
print(cur.fetchall())
# cur.execute("DROP TABLE users CASCADE")
cur.execute("DELETE FROM users WHERE login='dakak1'")
con.commit()
