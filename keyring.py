''' The keyring data-type holds many keys of the cypher program, It is encrypted with a \
        password based key (using PBKDF2) and a random nonce, using ChaCha20-Poly1305 
        Stream cipher mode It is the only thing a user requires to use the program, 
        It cannot be recovered if the password is forgotten. The data is saved in pickle
        format and then encrypted to get the final ".keyring" format'''

import os
import pickle


from Crypto.Cipher import ChaCha20_Poly1305 as chacipher
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes as rand
from Crypto.Util.Padding import pad, unpad


import keys

class Keyring(object):
    """An encrypted object to contain multiple keys, Enc data is stored in the format\
            salt[32] + nonce[32] + tag[32] + ciphertext"""

    def __init__(self, file_name=None):
        self.salt_len = 32
        self.key_len = 32
        self.nonce_len = 32
        self.tag_len = 32

        self.enc_data = None
        self.pk_data = None

        if file_name:
            self.file_name = file_name
        self.keys = {} # Dict to contain key's b-hash to keyobject

    def encrypt(self, password):
        if not self.pk_data:
            return print("Load the pickled data into data")
        self.pk_data = pickle.dumps(self.keys)

        salt = rand(self.salt_len)
        key = PBKDF2(password, salt, dkLen = self.key_len)
        cip = chacipher.new(key = key)
        ct, tag = cip.encrypt_and_digest(self.pk_data)
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
        key = PBKDF2(password, salt, dkLen=self.key_len)
        cip = chacipher.new(key=key, nonce=nonce)
        try:
            self.pk_data = cip.decrypt_and_verify(ct, tag)
            self.keys = pickle.loads(self.pk_data)
        except (KeyError,ValueError) as e:
            print("Invalid data for decryption")


    def load(self, file_name):
        self.file_name = file_name
        with open(file_name, 'rb') as red:
            self.enc_data = red.read()
        # ToDo: Decrypt and convert to pickle format
        

    def save(self):
        if self.enc_data:
            if not self.file_name:
                return print("Provide a filename")
            with open(self.file_name, 'wb') as wir:
                wir.write(self.enc_data)
        else:
            print("Encrypt data first")


    def create(self, password):
        self.file_name = "new.kring"
        self.keys = {}
        self.pk_data = pickle.dumps(self.keys)
        self.encrypt(password)
        self.save()


    def search_key(self, bsh):
        """Returns the key_obj correspoding to the bsh"""
        if bsh in self.keys:
            return self.keys[bsh]
        else:
            return None

    def import_key(self, key_obj):
        if not isinstance(key_obj, keys.Key):
            raise TypeError("Invalid key")
        else:
            self.keys[key_obj.bsh] = key_obj

    def export_key(self, bsh):
        if not self.keys.get(bsh, None):
            return print("That key doesn't exist")
        else:
            return self.keys[bsh]

if __name__ == "__main__":
    hope = Keyring()

    print("successful")
