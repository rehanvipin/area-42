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
        data = pad(self.file.read(), 16)
        key = rand(16)
        enc = AES.new(key, AES.MODE_GCM)
        ct, tag = enc.encrypt_and_digest(data)
        nonce = enc.nonce
        body = nonce + tag + ct
        hsh, bsh = self.shahash(body)
        with open(hsh+'.lckd','wb') as wir:
            wir.write(bsh + body)
        return key


    def decrypt(self, key):
        """Decrypts the file and returns the plaintext"""
        


    def shahash(self, inp, hexd = False):
        """Returns the SHA256 hash of the input object"""
        ob = SHA256.new()
        ob.update(inp)
        return ob.hexdigest(), ob.digest()


if __name__ == "__main__":

    red = open('test.txt','rb')
    ob = Cipher(red)
    ob.encrypt()

    red.close()


    print("Succesful")
