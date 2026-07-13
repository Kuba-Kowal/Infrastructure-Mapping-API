from persistence.db.connection import *
from datetime import datetime

def write_scan_relationship(graph: Graph, relationship_ids: list[int], scan_id, connection) -> None:
    try:
        # CONNECT TO THE DB & CREATE A POINTER
        cursor = connection.cursor()

        # CREATE ITERABLE OF SCAN <> RELATIONSHIP IDS AND INSERT INTO DB.
        scan_to_relationship_query = """
        INSERT IGNORE INTO scan_relationships (scan_id, relationship_id)
        VALUES (%s, %s)
        """

        rows = [(scan_id, relationship_id) for relationship_id in relationship_ids]

        cursor.executemany(scan_to_relationship_query, (rows))

        connection.commit()
    
        # IN CASE OF AN ERROR DO NOT COMMIT TO PRESERVE INTEGRITY
    except mysql.connector.Error as err:
        connection.rollback()
        print(err)
        print("TRANSACTION ABORTED & ROLLED BACK. DB NOT UPDATED WITH SCANS_RELATIONSHIPS")
    finally:
        cursor.close()