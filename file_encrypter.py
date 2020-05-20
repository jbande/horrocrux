import cryptography
import psycopg2
import requests
from psycopg2.extras import RealDictCursor
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from credential import *
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os
import random
import string

CHUNK_SIZE = 440


class Encryptor:

    def __init__(self,
                 keys_dir_path=None,
                 private_key_file_name='key.pem',
                 public_key_file_name='key.pem.pub'):

        self.private_key = None
        self.public_key = None

        self.keys_dir_path = keys_dir_path

        self.private_key_file_name = private_key_file_name
        self.public_key_file_name = public_key_file_name

        self.private_key_file = self.private_key_file_name
        self.public_key_file = self.public_key_file_name

        self.transaction_secret = None

        self.transaction_key = None

        self.file_path = None

        if self.keys_dir_path:
            if not os.path.isdir(self.keys_dir_path):
                print("directory path not valid")
                exit(-1)
            self.private_key_file = os.path.join(self.keys_dir_path, self.private_key_file_name)
            self.public_key_file = os.path.join(self.keys_dir_path, self.public_key_file_name)

        self.chunks_db_connection = psycopg2.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD)

        self.cursor = self.chunks_db_connection.cursor(cursor_factory=RealDictCursor)

        self.file_number = 1

        self.sender_address = None

        self.transaction_index_file_path = None


    def generate_keys(self):
        """Generates public and private keys and store them in given location"""

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        pem_priv = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pem_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_file, 'wb') as f:
            f.write(pem_priv)

        with open(self.public_key_file, 'wb') as f:
            f.write(pem_pub)

        print(f"Private key stored in: {self.private_key_file}")
        print(f"Public key stored in: {self.public_key_file}")


    @staticmethod
    def store_file(file_path):
        """Creates and encryptor for the given file. Generates the public and private keys, generates the
        file index, encrypt the file and store de file in the network. The public key, private key and the index
        is stored in the local file ./files_data."""

        file_path_sp = file_path.split('/')

        file_name = file_path_sp[-1]

        timestamp = datetime.timestamp(datetime.now())

        enc = Encryptor(keys_dir_path='./files_data',
                        private_key_file_name=f"{file_name}-{timestamp}{'.key.prv'}",
                        public_key_file_name=f"{file_name}-{timestamp}{'.key.pub'}")

        enc.generate_keys()

        enc.transaction_secret = Encryptor.get_secret_token()

        enc.transaction_key = enc.encrypt(enc.transaction_secret)[:32]

        enc.transaction_index_file_path = os.path.join('./files_data', f"{file_name}-{timestamp}{'.index'}")

        enc.file_path = file_path

        enc._encrypt_and_store_file()


    def _encrypt_and_store_file(self):
        """Splits a given file in chunks, encrypt each chunk and spread chunks in the network"""

        with open(self.transaction_index_file_path, 'wb') as i:
            i.write(self.transaction_secret + b'\n')
            i.write(self.transaction_key)

        with open(self.file_path, 'rb') as f:
            chunk = f.read(CHUNK_SIZE)

            while chunk:

                enc_chunk = self.encrypt(chunk)

                query = f"""INSERT INTO public.chunks (transaction_key, chunk_id, chunk) 
                VALUES ({psycopg2.Binary(self.transaction_key)}, {self.file_number}, {psycopg2.Binary(enc_chunk)})
                """
                self.cursor.execute(query)

                self.file_number += 1
                chunk = f.read(CHUNK_SIZE)

            self.chunks_db_connection.commit()

        print(f"{self.file_number} blocks encrypted and stored in database.")
        print(f"{self.transaction_index_file_path} file generated.")

    def recover(self, recovered_file_path, file_index_path):

        self.read_index(file_index_path)

        self.read_private_key()

        query = f"""select * from public.chunks 
        where transaction_key = {psycopg2.Binary(self.transaction_key)}
        order by chunk_id"""

        self.cursor.execute(query)

        rows = self.cursor.fetchall()

        with open(recovered_file_path, "wb") as recovered_file:

            for row in rows:

                line = self.decrypt(bytes(row["chunk"]))

                recovered_file.write(line)

    def read_private_key(self):
        with open(self.private_key_file, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )


    def read_pub_key(self):
        with open(self.public_key_file, "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )


    def encrypt(self, data):
        """Encrypt data using current encryptor public key"""
        self.read_pub_key()

        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        #print(public_key_bytes)

        encrypted = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def encrypt_and_sign(self, data):
        self.read_pub_key()
        encrypted_data = self.encrypt(data)

        self.read_private_key()

        signature = self.private_key.sign(data,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                                          hashes.SHA256())

        return encrypted_data, signature

    def sign(self, data):

        self.read_private_key()

        signature = self.private_key.sign(data,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                                          hashes.SHA256())

        return signature


    @staticmethod
    def verify_with_signature(signature, message, public_key_bytes):

        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        ret = True

        try:
            public_key.verify(signature,
                              message,
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except InvalidSignature as e:
            ret = False

        return ret

    @staticmethod
    def get_signature(message, private_key):

        signature = private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

        return signature

    @staticmethod
    def encrypt_with_public_key(public_key_bytes, data):
        """Entrypt data using param public_key"""

        #print(public_key_bytes)
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt(self, encrypted_data):
        self.read_private_key()

        original_data = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_data


    def read_address(self):
        with open(self.public_key_file, "rb") as key_file:

            key_file.readline()
            self.sender_address = key_file.readline()[:64].decode("utf-8")
            print(f"Sender address: {self.sender_address}")


    def read_index(self, file_path):
        with open(file_path, "rb") as index_file:
            self.transaction_secret = index_file.readline()
            self.transaction_key = index_file.readline()

    @classmethod
    def get_secret_token(cls):
        return bytes(''.join(random.choices(string.ascii_uppercase + string.digits, k=20)), 'utf-8')


if __name__ == "__main__":

    #generate_keys()
    #encrypted_msg = encrypt()
    #decrypt(encrypted_msg)

    #encryptor = Encryptor(keys_dir_path='/home/bande/10-Documents/01-Ruby/')
    #encryptor.generate_keys()

    #encryptor.encrypt_file('sample_file')
    #encryptor.encrypt_file('/home/bande/10-Documents/11-Linux/Linux_System_Administration.pdf')

    #f = open("sample_file", "r")
    #print(f.read(5))

    #encryptor = Encryptor()

    #encryptor.decrypt_file('sample_fileenc')

    #encryptor.generate_keys()

    #encryptor.read_pub_key()

    #encryptor.rip_and_store_file('/home/bande/enctesting/Lebalink_ad.png')

    #encryptor.rip_and_store_file('/home/bande/10-Documents/01-Ruby/Practical_Ruby_Projects.pdf')

    #encryptor.recover(recovered_file_path='/home/bande/10-Documents/01-Ruby/Practical_Ruby_Projects-recovered.pdf',
    #                  file_index_path='/home/bande/10-Documents/01-Ruby/Practical_Ruby_Projects.pdf.transaction.index')

    #encryptor.read_address()

    Encryptor.store_file('/home/bande/enctesting/Lebalink_ad.png')