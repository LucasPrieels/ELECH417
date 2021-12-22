#!/usr/bin/python3
# https://www.postgresqltutorial.com/postgresql-python/connect/
import psycopg2
from config import config

def connect():
    """ Connect to the PostgreSQL database server """
    conn = None
    try:
        # read connection parameters
        params = config()

        # connect to the PostgreSQL server
        print('Connecting to the PostgreSQL database...')
        conn = psycopg2.connect(**params)
        print("Connected !")
        # create a cursor
        cur = conn.cursor()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            return conn


def disconnect(connection) :
    connection.close()
    print('Database connection closed.')

if __name__ == '__main__':
    connect()
