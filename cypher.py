from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes as rand
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

import keys

class Cipher(object):
    """Cipher class to encrypt and decrypt data, Expects data to be correctly formatted"""

    def __init__(self, file_object, func='e'):
        """Use func to specify whether encrypting or decrypting"""
        assert file_object.readable(), "Cannot read the file"

        self.file = file_object
        self.file_name = file_object.name

        self.block_size = 16
        self.key_size = 16
        self.nonce_pad = 32
        self.tag_pad = 32


    def encrypt(self):
        """Encrypts the file and returns the key"""
        data = pad(self.file.read(), self.block_size)
        key = rand(self.key_size)
        enc = AES.new(key, AES.MODE_GCM)
        ct, tag = enc.encrypt_and_digest(data)
        nonce = pad(enc.nonce, self.nonce_pad)
        body = nonce + pad(tag, self.tag_pad) + ct
        hsh, bsh = self.shahash(body)
        with open(hsh+'.lckd','wb') as wir:
            wir.write(bsh + body)

        # Creating the key object and saving the data to the file
        key_obj = keys.Key(hsh)
        key_obj.fix(key, bsh, hsh, self.file_name)
        key_obj.save(key_obj.file)

        return key_obj


    def decrypt(self, keyfile_name):
        """Decrypts the file and returns the plaintext"""
        key_obj = keys.Key(keyfile_name, 'd')
        bsh = self.file.read(32)
        if bsh != key_obj.bsh:
            print('Unable to decrypt')

        nonce = unpad(self.file.read(self.nonce_pad), self.nonce_pad)
        tag = unpad(self.file.read(self.tag_pad), self.tag_pad)
        ct = self.file.read()

        dec = AES.new(key_obj.key, AES.MODE_GCM, nonce=nonce)
        data = dec.decrypt_and_verify(ct, tag)
        data = unpad(data, self.block_size)

        with open(key_obj.file_name, 'wb') as wir:
            wir.write(data)

    def shahash(self, inp, hexd = False):
        """Returns the SHA256 hash of the input object"""
        ob = SHA256.new()
        ob.update(inp)
        return ob.hexdigest(), ob.digest()


def test_encrypt(test_file):
    # Test for encryption
    red = open(test_file,'rb')
    ob = Cipher(red)
    ob.encrypt()

    red.close()

def test_decrypt(test_file):
    # Test for decryption
    blu = open(test_file + '.lckd', 'rb')
    ob = Cipher(blu, 'd')
    ob.decrypt(test_file + '.key')
    blu.close()


if __name__ == "__main__":
    """ Uncomment either one of the tests """
    # test_encrypt('test.jpeg')
    test_decrypt('xd')
    print("Succesful")
