import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        passwd="password",
        port="33060",
        database="graph"
    )
