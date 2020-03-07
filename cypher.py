import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes as rand
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

import keys

class Cipher(object):
    """Cipher class to encrypt and decrypt data, Expects data to be correctly formatted\
        Important: Hash length is 32 bytes, any use of 32 represents hash usage"""

    def __init__(self, file_object, func='e'):
        """Use func to specify whether encrypting or decrypting, expects an object\
                pointing to the plaintext or the ciphertext"""
        assert file_object.readable(), f"Cannot read the file {file_object.name}"

        self.file = file_object
        self.file_name = file_object.name

        self.block_size = 16
        self.key_size = 32
        self.nonce_pad = 32
        self.tag_pad = 32


    def encrypt(self):
        """Encrypts the file Saves into lckd file and returns the key"""
        data = pad(self.file.read(), self.block_size)
        key = rand(self.key_size)
        enc = AES.new(key, AES.MODE_GCM)
        ct, tag = enc.encrypt_and_digest(data)
        del data # Saves memory
        nonce = pad(enc.nonce, self.nonce_pad)
        body = nonce + pad(tag, self.tag_pad) + ct
        hsh, bsh = self.shahash(body)
        with open(hsh+'.lckd','wb') as wir:
            wir.write(bsh + body)

        del body

        # Creating the key object, doesn't save data to file
        key_obj = keys.Key()
        key_obj.fix(key, bsh, hsh, self.file_name)

        return key_obj


    def decrypt(self, key_obj):
        """Decrypts the file and saves the plaintext needs key object as param"""
        bsh = self.file.read(32)
        if bsh != key_obj.bsh:
            raise ValueError('Cannot Decrypt Incorrect Data')

        nonce = unpad(self.file.read(self.nonce_pad), self.nonce_pad)
        tag = unpad(self.file.read(self.tag_pad), self.tag_pad)
        ct = self.file.read()

        dec = AES.new(key_obj.key, AES.MODE_GCM, nonce=nonce)
        try:
            data = dec.decrypt_and_verify(ct, tag)
        except (KeyError, ValueError) as e:
            print("Cannot decrypt data")
        finally:
            self.file.close()
        del ct # Saves memory
        data = unpad(data, self.block_size)

        with open(key_obj.file_name, 'wb') as wir:
            wir.write(data)

        del data

    def shahash(self, inp, hexd = False):
        """Returns the SHA256 hash of the input object"""
        ob = SHA256.new()
        ob.update(inp)
        return ob.hexdigest(), ob.digest()


def test_encrypt(test_file):
    # Test for encryption
    red = open(test_file,'rb')
    ob = Cipher(red)
    try:
        kd = ob.encrypt()
        kd.save(kd.hsh + '.key')
    finally:
        red.close()

def test_decrypt(test_file):
    # Test for decryption
    blu = open(test_file + '.lckd', 'rb')
    ob = Cipher(blu, 'd')
    try:
        key_file_name = test_file + '.key'
        key_obj = keys.Key(key_file_name, 'd')
        ob.decrypt(key_obj)
    finally:
        blu.close()


if __name__ == "__main__":
    """ Uncomment either one of the tests """
    if len(sys.argv) > 1:
        if sys.argv[1] == 'e':
            test_encrypt(sys.argv[2])
        elif sys.argv[1] == 'd':
            test_decrypt(sys.argv[2])
        else:
            print("Invalid argument")
    else:
        print("Encrypting test.txt")
        test_encrypt('test.txt')
        # test_decrypt('lmao')
    print("Succesful")
