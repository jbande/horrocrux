import psycopg2
import requests
from psycopg2.extras import RealDictCursor
from file_encrypter import Encryptor
import base64
from credential import *
from utils import byte_type_from_network, byte_type_to_network
from cryptography.hazmat.primitives import serialization
from random import randrange
import sys
import getopt

NODE_IS_UP = 0
NODE_NOT_RESPONDING = 1
NODE_INVALIDATED = 2

HELLO_ACCEPTED = 3
HELLO_REJECTED = 4

NODE_UNVALIDATED = 5
SHARED_NODES_ACCEPTED = 6
NODE_DOWNGRADED = 7


class Node:
    def __init__(self, row):
        self.host = row['host']
        self.address = row['address']

        if 'public_key' in row:
            self.public_key = bytes(row['public_key'])
        else:
            self.public_key = None


class Discoverer:

    def __init__(self):

        self.chunks_db_connection = psycopg2.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD)

        self.cursor = self.chunks_db_connection.cursor(cursor_factory=RealDictCursor)
        self.nodes_list = []

        self.verify_path = 'http://{node}/verify'
        self.hello_path = 'http://{node}/hello'
        self.sharing_path = 'http://{node}/sharing'

        self.this_node = self.get_this_node()

    def insert_or_update_node(self, node):

        query = f"""SELECT count(*) from {SCHEMA}.nodes where address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        result = self.cursor.fetchone()

        if int(result['count']) > 0:
            query = f"""UPDATE {SCHEMA}.nodes SET
            host = '{node.host}',
            verified_at = CURRENT_TIMESTAMP;"""
        else:
            query = f"""INSERT INTO {SCHEMA}.nodes (host, address, public_key, verified_at, status) 
            VALUES ('{node.host}', '{node.address}', {psycopg2.Binary(node.public_key)}, CURRENT_TIMESTAMP, {NODE_IS_UP});"""

        self.cursor.execute(query)
        self.chunks_db_connection.commit()


    def insert_shared_node(self, node):
        """If we have this node, we check if info received is identical to the info we store about this node.
        If is identical we do nothing. If is not identical, we downgrade the status of the node to NODE_UNVALIDATED,
        and store the info of the node we received in the shared nodes table."""

        print("Inspecting node")

        # First check if we have a node with that address
        if self.have_node_with_this_address(node.address):

            if not self.have_identical_node(node):
                print(f"We have this node {node.address} but data received is not identical")
                self.downgrade_node(node)

        else:
            # save in shared nodes for future validation
            print("Saving new shared node")

            self.save_in_shared_nodes_table(node)


    def have_identical_node(self, node):
        query = f"""SELECT count(*) from {SCHEMA}.nodes 
        where address = '{node.address}' and host = '{node.host}' and public_key = {psycopg2.Binary(node.public_key)};"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        return self.cursor.fetchone()['count'] > 0


    def have_node_with_this_address(self, address):
        query = f"""SELECT count(*) from {SCHEMA}.nodes where address = '{address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        return self.cursor.fetchone()['count'] > 0


    def save_in_shared_nodes_table(self, node):
        # Store in shared nodes awaiting for validation.
        query = f"""INSERT INTO {SCHEMA}.shared_nodes (host, address, public_key) 
                    VALUES ('{node.host}', '{node.address}', {psycopg2.Binary(node.public_key)});"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()


    def delete_from_shared_nodes_table(self, node):
        # Store in shared nodes awaiting for validation.
        query = f"""DELETE FROM {SCHEMA}.shared_nodes 
                    WHERE host = '{node.host}' 
                    and address = '{node.address}' 
                    and public_key = {psycopg2.Binary(node.public_key)};"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()

    def delete_from_shared_nodes_table_by_address(self, node):
        # Store in shared nodes awaiting for validation.
        query = f"""DELETE FROM {SCHEMA}.shared_nodes 
                    WHERE address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()


    def upgrade_node(self, node):
        #self.delete_from_shared_nodes_table_by_address(node)
        self.insert_or_update_node(node)


    def downgrade_node(self, node):
        self.update_node_status(node.address, NODE_DOWNGRADED)

        self.save_in_shared_nodes_table(node)

        # We also save a copy of our stored version
        query = f"""INSERT INTO {SCHEMA}.shared_nodes (host, address, public_key)
        SELECT host, address, public_key from {SCHEMA}.nodes where address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()

    def get_newly_acquired_nodes(self):
        query = f"""select shn.address, shn.host, shn.public_key from {SCHEMA}.shared_nodes shn
        left join {SCHEMA}.nodes n on n.address = shn.address
        where n.id is null;
        """
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        return self._transform_nodes(self.cursor.fetchall())


    def get_downgraded_nodes(self):
        query = f"""select shn.address, shn.host, shn.public_key from {SCHEMA}.shared_nodes shn
        left join {SCHEMA}.nodes n on n.address = shn.address
        where n.id is not null and n.status = {NODE_DOWNGRADED};
        """
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        return self._transform_nodes(self.cursor.fetchall())


    def update_node_status(self, address, status):
        """Update the status of a node."""

        query = f"""UPDATE {SCHEMA}.nodes SET
        status = {status},
        verified_at = CURRENT_TIMESTAMP 
        where address = '{address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()


    def get_list_of_nodes(self, limit=None, offset=0):

        if limit:
            query = f"""select host, address, public_key 
            from {SCHEMA}.nodes order by verified_at limit {limit} offset {offset};"""
        else:
            query = f"""select host, address, public_key 
            from {SCHEMA}.nodes order by verified_at;"""

        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        return self._transform_nodes(self.cursor.fetchall())


    def get_count_of_nodes(self):
        query = """select count(*) from {SCHEMA}.nodes;"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        row = self.cursor.fetchone()
        return int(row['count'])


    def get_public_key_for_node(self, node):
        query = f"""select public_key from {SCHEMA}.nodes where address = '{node.address}';"""
        self.cursor.execute(query)
        self.chunks_db_connection.commit()
        result = self.cursor.fetchone()
        return bytes(result['public_key'])


    def get_next_node(self):

        query = """
        UPDATE {SCHEMA}.state
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
                                     json={
                                         'token': byte_type_to_network(token),
                                         'node': {
                                             'host': self.this_node.host,
                                             'address': self.this_node.address,
                                             'public_key': byte_type_to_network(self.this_node.public_key)
                                         }
                                     })

        except requests.exceptions.RequestException as e:  # This is the correct syntax

            self.update_node_status(node.address, status=NODE_NOT_RESPONDING)
            return False

        response_json = response.json()
        token_signature = byte_type_from_network(response_json['token-signature'])

        # Validate if the returned signature was build with a the private key associated to our
        # saved public key for the remote node.
        return Encryptor.verify_with_signature(token_signature, token, node.public_key)


    def respond_to_verify_node(self, request):
        """In the remote node, this is the function responding to the function above 'verify_node'.
        this function receives a token encrypt the token using the local public key and send re response back."""

        response_json = request.get_json()

        requesting_node = Node({'host': response_json['node']['host'],
                                'address': response_json['node']['address'],
                                'public_key': byte_type_from_network(response_json['node']['public_key'])})

        self.insert_shared_node(requesting_node)

        validation_token = byte_type_from_network(response_json['token'])

        encryptor = Encryptor()

        encryptor.read_pub_key()

        signature = encryptor.sign(validation_token)

        token_signature = byte_type_to_network(signature)

        return token_signature


    @staticmethod
    def get_this_node():

        encryptor = Encryptor()
        encryptor.read_pub_key()
        encryptor.read_private_key()
        encryptor.read_address()

        public_key = encryptor.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return Node({'host': f"{HOST}:{PORT}", 'address': encryptor.sender_address, 'public_key': public_key})

    def show_this_node(self):

        print(self.this_node.address)
        print(self.this_node.host)
        print(self.this_node.public_key)


    def hello(self, node):
        """When this node wants to connect with an new node for the first time.
        The local node should send its public key, if return status is HELLO_ACCEPTED
        then the remote node is validated by calling"""

        response = requests.post(url=self.hello_path.format(node=node.host), json={
            'host': self.this_node.host,
            'address': self.this_node.address,
            'public_key': byte_type_to_network(self.this_node.public_key)
        })

        response_json = response.json()

        if response_json['data']['ret'] == HELLO_ACCEPTED:
            self.update_node_status(node.address, status=NODE_UNVALIDATED)
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
            self.insert_or_update_node(host, address, public_key)
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


    def discover(self):

        # Say hello to newly acquired nodes
        newly_acquired_nodes = discoverer.get_newly_acquired_nodes()
        newly_accepted = {}
        for n in newly_acquired_nodes:
            if n.address not in newly_accepted:
                if discoverer.verify_node(n):
                    discoverer.upgrade_node(n)
                    newly_accepted[n.address] = True
                else:
                    self.delete_from_shared_nodes_table(n)

        downgraded_nodes = discoverer.get_downgraded_nodes()
        downgraded_accepted = {}
        for n in downgraded_nodes:
            if n.address not in downgraded_accepted:
                if discoverer.verify_node(n):
                    discoverer.upgrade_node(n)
                    downgraded_accepted[n.address] = True
                else:
                    self.update_node_status(n.address, status=NODE_INVALIDATED)


           # if valid:
           #     self.update_node_status(node.address, status=NODE_IS_UP)
           #     print("Node valid")
           #     return NODE_IS_UP
           # else:
           #     self.update_node_status(node.address, status=NODE_INVALIDATED)
           #     print("Node invalid")
           #     return NODE_INVALIDATED


    def save_my_data(self):
        node = self.this_node
        self.save_in_shared_nodes_table(node)


if __name__ == "__main__":

    discoverer = Discoverer()

    discoverer.show_this_node()

    #discoverer.save_my_data()

    usage = """"""

    action = None

    opts, args = getopt.getopt(sys.argv[1:], "hsd", [
        "show_node",
        "discover"
    ])

    # print opts

    for opt, arg in opts:
        if opt == '-h':
            print(usage)
            sys.exit()

        elif opt in ("-s", "--show_node"):
            action = 'show_node'
        elif opt in ("-d", "--discover"):
            action = 'discover'

    if action == 'show_node':
        print("This node ----------------------")
        discoverer.show_this_node()
    elif action == 'discover':
        discoverer.discover()
