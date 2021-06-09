import dropbox
import psycopg2
import requests

# dbx = dropbox.Dropbox('eCp2HTOUrNUAAAAAAAAAASLGV_nwg-uK-KcCXkZTWnT66l2rg9-W6CAGKZnMTiLI')

# result = dbx.sharing_create_shared_link_with_settings('/test.txt')

# print(result.url)
# import yadisk
# y = yadisk.YaDisk(token="AgAAAABITC7sAAav1g3D_G43akSwv85Xg-yPrCY")
# y.upload("test.txt", "/destination.txt")
# print(y.get_download_link('/destination.txt'))
# print(y.get_disk_info())


"""def pg_connect():
    try:
        con = psycopg2.connect(
            host="ec2-54-75-244-161.eu-west-1.compute.amazonaws.com",
            database="d8fi2kbfpchos",
            user="iutnqyyujjskrr",
            port="5432",
            password="45be3b8ccf0ce93d0e142ec546edaa8a067370f5c050b92b4c181730fb2c9814")
        cur = con.cursor()
        # cur.execute("DELETE FROM users WHERE id>2")
        # con.commit()
        cur.execute("SELECT * FROM users")
        res = cur.fetchall()
        for i in res:
            print(i)
        return con, cur
    except Exception as e:
        print(e)


# pg_connect()
from datetime import datetime, timezone

d = datetime.now(timezone.utc).astimezone()
utc_offset = d.utcoffset()
print(utc_offset)"""

print(requests.get(f"http://chat-b4ckend.herokuapp.com/chat/get_users?name=chat_gr").json())
