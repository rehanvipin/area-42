from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes as rand
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

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
        """Encrypts the file and returns the key"""
        pass

    def decrypt(self, key):
        """Decrypts the file and returns the plaintext"""
        pass

    def hash(self, inp, hexd = False):
        """Returns the SHA256 hash of the input object"""
       ob = SHA256.new()
       ob.update(inp)

       return ob.hexdigest() if hexd else ob.digest()


if __name__ == "__main__":

    with open('test.txt','rb') as red:
        ob = Cipher(red)

    print("Succesful")
