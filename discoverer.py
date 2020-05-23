import psycopg2
import requests
from psycopg2.extras import RealDictCursor
from file_encrypter import Encryptor
import base64
from credential import *
from utils import byte_type_from_network, byte_type_to_network
from cryptography.hazmat.primitives import serialization
from random import randrange

NODE_IS_UP = 0
NODE_NOT_RESPONDING = 1
NODE_INVALIDATED = 2

HELLO_ACCEPTED = 3
HELLO_REJECTED = 4

NODE_UNVALIDATED = 5
SHARED_NODES_ACCEPTED = 6

class Node:
    def __init__(self, row):
        self.host = row['host']
        self.address = row['address']
        self.public_key = bytes(row['public_key'])


class Discoverer:

    def __init__(self):

        self.chunks_db_connection = psycopg2.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD)

        self.cursor = self.chunks_db_connection.cursor(cursor_factory=RealDictCursor)
        self.nodes_list = []

        self.verify_path = 'http://{node}:5000/verify'
        self.hello_path = 'http://{node}:5000/hello'
        self.sharing_path = 'http://{node}:5000/sharing'

    def insert_node(self, host, address, public_key):

        query = f"""SELECT count(*) from public.nodes where address = '{address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        result = self.cursor.fetchone()

        if int(result['count']) > 0:
            query = f"""UPDATE public.nodes SET
            host = '{host}',
            verified_at = CURRENT_TIMESTAMP;"""
        else:
            query = f"""INSERT INTO public.nodes (host, address, public_key, verified_at, status) 
            VALUES ('{host}', '{address}', {psycopg2.Binary(public_key)}, CURRENT_TIMESTAMP, {NODE_IS_UP});"""

        self.cursor.execute(query)
        self.chunks_db_connection.commit()


    def insert_shared_node(self, node):

        # First check if we have a node with that address
        query = f"""SELECT count(*) from public.nodes where address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        node_exists = self.cursor.fetchone()['count']

        if node_exists > 0:
            # Then check if the shared node totally identical to the info we have on that node

            query = f"""SELECT count(*) from public.nodes 
            where address = '{node.address}' and host = '{node.host}' and public_key = {psycopg2.Binary(node.public_key)};"""
            self.cursor.execute(query)
            self.chunks_db_connection.commit()
            identical_node_count = self.cursor.fetchone()['count']

            if identical_node_count == 0:
                # If it is not identical we first invalidate the node (avoiding sending/receiving
                # transactions to/from it)
                self.update_node_status(node.address, NODE_UNVALIDATED)

                # Enter the node received data to the shared node table for further validation actions.
                query = f"""INSERT INTO public.shared_nodes (host, address, public_key, verified_at, status) 
                            VALUES ('{node.host}', '{node.address}', {psycopg2.Binary(node.public_key)});"""
                self.cursor.execute(query)
                self.chunks_db_connection.commit()

        else:
            # Store in shared nodes awaiting for validation.
            query = f"""INSERT INTO public.shared_nodes (host, address, public_key, verified_at, status) 
                        VALUES ('{node.host}', '{node.address}', {psycopg2.Binary(node.public_key)});"""
            self.cursor.execute(query)
            self.chunks_db_connection.commit()


    def update_node_status(self, address, status):
        """Update the status of a node."""

        query = f"""UPDATE public.nodes SET
        status = {status},
        verified_at = CURRENT_TIMESTAMP 
        where address = '{address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()


    def get_list_of_nodes(self, limit=None, offset=0):

        if limit:
            query = f"""select host, address, public_key 
            from public.nodes order by verified_at limit {limit} offset {offset};"""
        else:
            query = f"""select host, address, public_key 
            from public.nodes order by verified_at;"""

        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        return self._transform_nodes(self.cursor.fetchall())


    def get_count_of_nodes(self):
        query = """select count(*) from public.nodes;"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        row = self.cursor.fetchone()
        return int(row['count'])


    def get_public_key_for_node(self, node):
        query = f"""select public_key from public.nodes where address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        result = self.cursor.fetchone()
        return bytes(result['public_key'])


    def get_next_node(self):

        query = """
        UPDATE public.state
        SET sharing_pointer = the_column + 1
        RETURNING sharing_pointer;"""

        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        row = self.cursor.fetchone()
        offset = int(row['sharing_pointer'])

        nodes_list = self.get_list_of_nodes(limit=1, offset=offset)
        return nodes_list[0]


    def _transform_nodes(self, rows):
        nodes_list = []
        for row in rows:
            nodes_list.append(Node(row))
        return nodes_list

    def _transform_nodes_from_network(self, nodes_list):
        nodes_list = list(map(lambda x: {'address': x['address'],
                                         'host': x['host'],
                                         'public_key': byte_type_from_network(x['public_key'])}, nodes_list))
        return self._transform_nodes(nodes_list)


    def verify_node(self, node):
        """In the local node, this function validates remote node identity and also verify if node is responding.
        The function also updates the node status. This is intended to be used before sending/requesting chunks to/from t
        he remote node"""

        # We generate a token
        token = Encryptor.get_secret_token()

        # We send the token to te remote node, ask him to sign the token with its private key
        try:
            response = requests.post(url=self.verify_path.format(node=node.host),
                                     json={'token': byte_type_to_network(token)})

        except requests.exceptions.RequestException as e:  # This is the correct syntax

            self.update_node_status(node.address, status=NODE_NOT_RESPONDING)
            return NODE_NOT_RESPONDING

        response_json = response.json()
        token_signature = byte_type_from_network(response_json['token-signature'])

        # Validate if the returned signature was build with a the private key associated to our
        # saved public key for the remote node.
        valid = Encryptor.verify_with_signature(token_signature, token, node.public_key)

        if valid:
            self.update_node_status(node.address, status=NODE_IS_UP)
            print("Node valid")
            return NODE_IS_UP
        else:
            self.update_node_status(node.address, status=NODE_INVALIDATED)
            print("Node invalid")
            return NODE_INVALIDATED


    @staticmethod
    def respond_to_verify_node(request):
        """In the remote node, this is the function responding to the function above 'verify_node'.
        this function receives a token encrypt the token using the local public key and send re response back."""

        response_json = request.get_json()

        validation_token = byte_type_from_network(response_json['token'])

        encryptor = Encryptor()

        encryptor.read_pub_key()

        signature = encryptor.sign(validation_token)

        token_signature = byte_type_to_network(signature)

        return token_signature


    def hello(self, node):
        """When this node wants to connect with an new node. The local node should send its public key"""

        encryptor = Encryptor()
        encryptor.read_pub_key()
        encryptor.read_private_key()
        encryptor.read_address()

        public_key = encryptor.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        response = requests.post(url=self.hello_path.format(node=node.host), json={
            'host': 'localhost',
            'address': encryptor.sender_address,
            'public_key': byte_type_to_network(public_key)
        })

        response_json = response.json()

        if response_json['data']['ret'] == HELLO_ACCEPTED:
            self.verify_node(node)
        else:
            self.update_node_status(node.address, status=NODE_INVALIDATED)
            print("Node invalid")
            return NODE_INVALIDATED


    def respond_to_hello(self, request):
        """Respond when the node receives a hello request"""
        request_json = request.get_json()
        host = request_json['host']
        address = request_json['address']

        public_key = byte_type_from_network(request_json['public_key'])

        ret = HELLO_ACCEPTED

        try:
            self.insert_node(host, address, public_key)
        except requests.exceptions.RequestException as e:  # This is the correct syntax
            ret = HELLO_REJECTED
        return ret


    def share_some_nodes(self):

        node = self.get_next_node()

        limit = 5

        count_of_nodes = self.get_count_of_nodes()

        count_of_nodes = count_of_nodes - limit + 1

        random_offset = randrange(0, count_of_nodes)

        nodes_list_to_share = self.get_list_of_nodes(limit=limit, offset=random_offset)

        self.share(node, nodes_list_to_share)


    def share(self, node, nodes_list_to_share):

        nodes_list = list(map(lambda x: {'address': x.address,
                                         'host': x.host,
                                         'public_key': byte_type_to_network(x.public_key)}, nodes_list_to_share))

        data_json = {'data': {'nodes_list': nodes_list}}

        response = requests.post(url=self.sharing_path.format(node=node.host),
                                 json=data_json)


    def respond_to_share(self, request):

        request_json = request.get_json()
        shared_nodes_list = request_json['data']['nodes_list']
        nodes_list = self._transform_nodes_from_network(shared_nodes_list)

        for node in nodes_list:
            self.insert_shared_node(node)

        return SHARED_NODES_ACCEPTED
