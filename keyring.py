''' The keyring data-type holds many keys of the cypher program, It is encrypted with a \
        password based key (using PBKDF2) and a random nonce, using ChaCha20-Poly1305 
        Stream cipher mode It is the only thing a user requires to use the program, 
        It cannot be recovered if the password is forgotten'''

import os


from Crypto.Cipher import ChaCha20_Poly1305 as chacipher
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes as rand
from Crypto.Util.Padding import pad, unpad


import keys

class Keyring(object):
    """An encrypted object to contain multiple keys, Enc data is stored in the format\
            salt[32] + nonce[32] + tag[32] + ciphertext"""

    def __init__(self):
        self.salt_len = 32
        self.key_len = 32
        self.nonce_len = 32
        self.tag_len = 32
        self.enc_data = None

    def encrypt(self, password):
        salt = rand(self.salt_len)
        key = PBKDF2(password, salt)
        cip = chacipher.new(key = key)
        ct, tag = cip.encrypt_and_digest(self.raw_data)
        nonce = cip.nonce
        nonce = pad(nonce, self.nonce_len)
        tag = pad(tag, self.tag_len)

        self.enc_data = salt + nonce + tag + ct


    def decrypt(self, password):
        if not self.enc_data:
            print("Load data first")
            return
        buf = 0
        salt = self.enc_data[buf:buf+self.salt_len]
        buf += self.salt_len
        nonce = self.enc_data[buf:buf+self.nonce_len]
        nonce = unpad(nonce, self.nonce_len)
        buf += self.nonce_len
        tag = self.enc_data[buf:buf+self.tag_len]
        tag = unpad(tag, self.tag_len)
        buf += self.tag_len
        ct = self.enc_data[buf:]
        key = PBKDF2(password, salt)
        cip = chacipher.new(key=key, nonce=nonce)
        self.data = cip.decrypt_and_verify(ct, tag)


    def load(self, file_name):
        self.file_name = file_name
        with open(file_name, 'rb') as red:
            self.enc_data = red.read()
        # ToDo: Decrypt and convert to tarfile format
        

    def save(self):
        if self.enc_data:
            with open(self.file_name, 'wb') as wir:
                wir.write(self.enc_data)
        else:
            print("Encrypt data first")

    def create(self):
        pass

    def search_key(self):
        pass

    def import_key(self):
        pass

    def export_key(self):
        pass

if __name__ == "__main__":
    hope = Keyring()
    print("successful")
