import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        passwd="password",
        port="33060",
        database="graph"
    )

db = get_connection()
cursor = db.cursor()

# So I have successful added entries into the database, now the next issue I am facing is -
# how do we retrieve all the data for a specific domain. My idea is to introduce a history, this allows
# an apex domain, to be linked to a list of relationships. which in turn those relationships can
# show all the nodes. im assuming through a join or a union but I shall learn and find out.
# The reason i have chosen this is because we want historical data, which means we want 
# SELECT * FROM Scans WHERE apex_domain = "example.com"
# Which means we also no longer have to store the timestamp in every single relationship, 
# but instead just within the scan. Now i have heard about unions and joins so that is the first
# thing I will try to do, is retrieve the data for a specific relationship.abs

# Now the first thing we need to do, is somehow retrieve the new primary key, of every
# insert within our relationship transaction, and scan to create our relationship scan_relationship

query = ("""
INSERT INTO relationships(source_hash, target_hash, relationship_type)
VALUES(%s, %s, %s)
ON DUPLICATE KEY UPDATE
    relationship_id = LAST_INSERT_ID(relationship_id)
""")
# mock relationships
values = [("5f221a4eaf8861f57e11989027bb02e214110c631f55770444100d3cae917d59", "b595062edbd16ec52d91b1e6ab0d6d999ae91407de27dd21e2904124564ccc26", "virustotal"), ("058017f6d110062678e6ed560b30e893e429da34f1203f73c3afae2c4b9f955b", "04a7cfccdd2684fa34522745629975f80956c5f08fb2a8154f1d429a2dd0138e", "RELATIONSHIP2"), ("04a7cfccdd2684fa34522745629975f80956c5f08fb2a8154f1d429a2dd0138e", "058017f6d110062678e6ed560b30e893e429da34f1203f73c3afae2c4b9f955b", "RELATIONSHIP1")]

relationship_ids = []

# Itterate through our values
for source, target, relationship_type in values:
    # None of this is commited until we run session.commit() so we can freely itterate
    # rather than using executemany.
    cursor.execute(query, (source, target, relationship_type))

    # lastrowid returns the last row that was inserted/updated as part of this session.
    # this allows us to maintain multiple instances without them conflicting with each other.
    # the "fake" UPDATE also allows us to trick the lastrowid to think that we inserted new dat
    relationship_ids.append(cursor.lastrowid) 

print(relationship_ids)

# THIS NOW WORKS!! which means i can simply return this value from the function and pass it to
# the write_scan_relationship():
