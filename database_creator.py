import psycopg2
from psycopg2.extras import RealDictCursor
from credential import *


class DatabaseCreator:

    def __init__(self):

        self.db_connection = psycopg2.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD)

        self.cursor = self.db_connection.cursor(cursor_factory=RealDictCursor)

    def create(self):

        self.cursor.execute(f"""create schema if not exists {SCHEMA};""")

        self._create_chunks_table()
        self._create_nodes_table()
        self._create_shared_nodes_table()
        self._create_state_table()

        self.db_connection.commit()

    def _create_chunks_table(self):

        self.cursor.execute(f"""create table if not exists {SCHEMA}.chunks (
                          id serial primary key,
                          transaction_key bytea,
                          chunk_id integer,
                          chunk bytea);""")

    def _create_nodes_table(self):

        self.cursor.execute(f"""create table if not exists {SCHEMA}.nodes (
                          id serial primary key,
                          address varchar(128) unique not null,
                          host varchar(128),
                          verified_at timestamp,
                          public_key bytea,
                          status integer);""")

    def _create_shared_nodes_table(self):

        self.cursor.execute(f"""create table if not exists {SCHEMA}.shared_nodes (
                          id serial primary key,
                          address varchar(128),
                          host varchar(128),
                          public_key bytea);""")


    def _create_state_table(self):

        self.cursor.execute(f"""create table if not exists {SCHEMA}.state (
                          sharing_pointer integer default 0);""")

