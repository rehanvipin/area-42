from Crypto.Util.Padding import pad, unpad

class Key(object):
    """A single key, for encrypting or decrypting an Cipher object"""

    def __init__(self, **kwargs):
        try:
            self.key = kwargs['key']
            self.hash = kwargs['hash']
            self.fname = kwargs['fname']

            self.fname_len = 64
        except KeyError as k:
            print(k)
            exit()

    def save(self):
        """Saves the keyfile to a temporary location before adding"""
        fname = pad(bytes(self.fname), self.fname_len)
        with open(self.hash.decode(), 'wb') as wir:
            wir.write(self.key + self.hash + fname)


