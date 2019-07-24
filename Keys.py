from Crypto.Util.Padding import pad, unpad

import os

class Key(object):
    """A single key, for encrypting or decrypting an Cipher object"""

    def __init__(self, fname=None, mode='e'):
        """ fname is used to load data from the keyfile, only for decryption """
        # mode e does nothing, only for description
        if mode=='e':
            self.key = b''
            # bsh is the hash in bytes form hsh is in hex format
            # hex format is used to name the keyfile, bsh is used to compare with 
            # the ciphertext object for identification
            self.bsh = b''
            self.hsh = ''
            # file_name is the original name of the big file
            self.file_name = ''
        elif mode=='d':
            # while using decryption, entire filename is provided
            if os.path.exists(os.curdir + '/' +fname):
                self.load(fname)
        #Else simply create the object, without any params

    def __repr__(self):
        try:
            return f"key: {self.key} \nhash: {self.bsh} \nfilename: {self.file_name}"
        except AttributeError as a:
            print(a)
            print("Fill in the object first")

    def load(self, fname):
        """ Gets details from file and puts them in the object """
        with open(fname, 'rb') as red:
            payload = red.read()
        self.key = payload[:16]
        self.bsh = payload[16:48]
        self.file_name = unpad(payload[48:],64).decode()
        

    def save(self, fname):
        """ Given details, saves them to file in correct format"""
        payload = b''
        payload += self.key
        payload += self.bsh
        name = self.file_name.encode()
        name = pad(name, 64)
        payload += name
        with open(fname, 'wb') as wir:
            wir.write(payload)


    def fix(self, key, bsh, hsh, file_name):
        """ Utility function to quickly add the object's data """
        self.key = key
        self.bsh = bsh
        self.hsh = hsh
        self.file_name = file_name


if __name__ == "__main__":
    keyer = Key('test.key')
    print('Successful')
