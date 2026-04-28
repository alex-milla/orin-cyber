import sqlite3
conn = sqlite3.connect('hosting/data/orinsec.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
print('Tables:')
for r in cursor.fetchall():
    print(r[0])
conn.close()
