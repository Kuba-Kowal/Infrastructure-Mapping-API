from persistence.db.connection import *
from persistence.mappers.node_mapper import map_nodes


def write_nodes(graph: Graph) -> None:
    try:
        connection = get_connection()
            
        cursor = connection.cursor()

        nodes = map_nodes(graph)

        sql = """
        INSERT IGNORE INTO nodes (node_hash, type, data, properties)
        VALUES (%s, %s, %s, %s)
        """

        cursor.executemany(sql, nodes)
        connection.commit()

    except mysql.connector.Error as err:
        connection.rollback()
        print(err)
        print("TRANSACTION ABORTED & ROLLED BACK. DB NOT UPDATED WITH NODES")
    finally:
        cursor.close()