
#%%
import sqlite3

db = sqlite3.connect("asan.db")

q = db.execute("select * from sqlite_schema where type = 'view'")
data = q.fetchall()
columns = [dd[0] for dd in q.description]

#%%
indices = {nn: ii for ii, nn in enumerate(columns)}

print(columns)
print(indices)

def get(run, name):
    return run[indices[name]]

#%%

views = []

for dd in data:
    name = get(dd, "name")
    views.append(name)

print(views)

#%%
for vv in views:
    db.execute(f"drop view if exists {vv}")























