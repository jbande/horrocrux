import requests
from file_encrypter import Encryptor
from discoverer import Discoverer
import base64
from cryptography.hazmat.primitives import serialization


def test_hello():

    encryptor = Encryptor()
    encryptor.read_pub_key()
    encryptor.read_private_key()
    encryptor.read_address()

    public_key = encryptor.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print_json_public = base64.b64encode(public_key).decode("utf-8")

    url = 'http://localhost:5000/hello'
    x = requests.post(url=url, json={
        'host': 'localhost',
        'address': encryptor.sender_address,
        'public_key': print_json_public
    })

    print(x)

def test_verify_node():

    encryptor = Encryptor()
    encryptor.read_pub_key()
    encryptor.read_private_key()
    encryptor.read_address()


def verify_node_test():

    disco = Discoverer()

    disco.get_list_of_nodes()

    n1 = disco.nodes_list[0]

    ret = disco.verify_node(n1)



    #disco.verify_node(n1)


if __name__ == "__main__":

    verify_node_test()
    #test_hello()