from persistence.db.connection import *
from persistence.mappers.edge_mapper import map_edges


def write_edges(graph: Graph) -> list[int]:
    edges = map_edges(graph)

    try:
        connection = get_connection()
        
        cursor = connection.cursor()

        query = ("""
        INSERT INTO relationships(source_hash, target_hash, relationship_type)
        VALUES(%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            relationship_id = LAST_INSERT_ID(relationship_id)
        """)

        relationship_ids = []

        # Itterate through our values
        for source, target, relationship_type in edges:
            cursor.execute(query, (source, target, relationship_type))

            relationship_ids.append(cursor.lastrowid) 

        connection.commit()

    except mysql.connector.Error as err:
        connection.rollback()
        print(err)
        print("TRANSACTION ABORTED & ROLLED BACK. DB NOT UPDATED WITH EDGES")
    finally:
        cursor.close()

    return relationship_ids
