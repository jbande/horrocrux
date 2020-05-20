import psycopg2
import requests
from psycopg2.extras import RealDictCursor
from file_encrypter import Encryptor
import base64
from credential import *

NODE_IS_UP = 0
NODE_NOT_RESPONDING = 1
NODE_INVALIDATED = 2


class Node:
    def __init__(self, row):
        self.host = row['host']
        self.address = row['address']


class Discoverer:

    def __init__(self):

        self.chunks_db_connection = psycopg2.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD)

        self.cursor = self.chunks_db_connection.cursor(cursor_factory=RealDictCursor)
        self.nodes_list = []

        self.verify_path = '{node}/verify'

    def insert_node(self, host, address, public_key):

        query = f"""SELECT count(*) from public.nodes where address = '{address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commint()
        result = self.cursor.fetchone()

        if int(result['count']) > 0:
            query = f"""UPDATE public.nodes SET
            host = '{host}',
            verified_at = CURRENT_TIMESTAMP();"""
        else:
            query = f"""INSERT INTO public.nodes (host, address, public_key, verified_at, status) 
            VALUES ('{host}', '{address}', {psycopg2.Binary(public_key)}, CURRENT_TIMESTAMP(), {NODE_IS_UP});"""

        self.cursor.execute(query)
        self.chunks_db_connection.commint()


    def update_node_status(self, address, status):
        """Update the status of a node."""

        query = f"""UPDATE public.nodes SET
        status = {status},
        verified_at = CURRENT_TIMESTAMP() 
        where address = '{address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commint()

    def get_list_of_nodes(self):

        query = f"""select host, address from public.nodes order by verified_at;"""
        self.cursor.execute(query)
        self.chunks_db_connection.commint()
        self._transform_nodes(self.cursor.fetchall())

    def get_public_key_for_node(self, node):
        query = f"""select public_key from public.node where address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commint()
        result = self.cursor.fetchone()
        return result['public_key']


    def _transform_nodes(self, rows):
        for row in rows:
            self.nodes_list.append(Node(row))


    def verify_node(self, node):
        """In the local node, this function validates remote node identity and also verify if node is responding.
        The function also updates the node status. Intended to be used before sending/requesting chunks to/from t
        he remote node"""

        # We generate a token
        token = Encryptor.get_secret_token()

        # We send the token to te remote node, ask him to encrypt the token with his public key and
        # send the response back to us.

        try:
            response = requests.post(url=self.verify_path.format(node.host), json={'token': base64.b64encode(token)})
        except requests.exceptions.RequestException as e:  # This is the correct syntax
            self.update_node_status(node.address, status=NODE_NOT_RESPONDING)
            return NODE_NOT_RESPONDING

        response_json = response.json()
        encrypted_token = base64.b64decode(response_json['encrypted-token'])

        # We fetch our locally stored public key of the remote node
        stored_public_key = self.get_public_key_for_node(node)

        # We also encrypt the token of the remote node with our stored version of the remote node public key
        local_encrypted_token = Encryptor.encrypt_with_public_key(stored_public_key, token)

        # If encryption matches the remote node pass validation
        if encrypted_token == local_encrypted_token:
            self.update_node_status(node.address, status=NODE_IS_UP)
            return NODE_IS_UP
        else:
            self.update_node_status(node.address, status=NODE_INVALIDATED)
            return NODE_INVALIDATED

    @staticmethod
    def respond_to_verify_node(response_json):
        """In the remote node, this is the function responding to the function above 'verify_node'.
        this function receives a token encrypt the token using the local public key and send re response back."""

        validation_token = base64.b64decode(response_json['encrypted-token'])
        encryptor = Encryptor()
        encryptor.read_pub_key()
        encrypted_token = encryptor.encrypt(validation_token)
        return encrypted_token


    def hello(self):
        """When this node wants to connect with an new node. The local node should send its public key"""
        pass

    def respond_to_hello(self):
        """Respond when the node receives a hello request"""
        pass
