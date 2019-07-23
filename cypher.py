from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes as rand
from Crypto.Util.Padding import pad, unpad

class Cipher(object):
    """Cipher class to encrypt and decrypt data, Expects data to be correctly formatted"""

    def __init__(self, file_object, func='e'):
        """Use func to specify whether encrypting or decrypting"""
        if func == 'e':
            assert file_object.readable(), "Cannot read the file"
        elif func == 'd':
            assert file_object.writable(), "Cannot write to the file"

        self.file = file_object
        self.file_name = file_object.name


    def encrypt(self):
        """Encrypts the file and returns the nonce, ciphertext and tag"""
        pass

    def decrypt(self):
        """Decrypts the file and returns the plaintext"""
        pass

    def hash(self, inp):
        """Gets the SHA256 hash of the input object"""
        pass


if __name__ == "__main__":

    with open('test.txt','rb') as red:
        ob = Cipher(red)

    print("Succesful")
