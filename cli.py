""" Command line version of area-42, works on any OS, provided with the required permissions.\
    Needs a config.json file to tell it the location of the keyring file, or a temp.json file \
    for temporary purpose. Can use the encrypt and decrypt option only for now """
import argparse
import os
import json
import getpass


import cypher
import keyring


def main():
    stats = {} # Contains info about keyring and use
    parsi = argparse.ArgumentParser()
    parsi.add_argument('-c','--config', action='store_true', help='specify the location of the config file')
    parsi.add_argument('-e','--encrypt', action='store_true', help='Use to encrypt a file')
    parsi.add_argument('-d','--decrypt', action='store_true', help='Use to decrypt a file, Need to specify the config\
            first')
    parsi.add_argument('-t','--temp', action='store_true', help='Use for temporary configuration')
    parsi.add_argument('file', help='The required file, keyring or to encrypt or to decrypt')
    parsed = parsi.parse_args()

    # Set the configuration file 
    home_path = os.path.join(os.path.expanduser('~'), 'area_config.json')
    if parsed.config:
        stats['kring'] = os.path.abspath(parsed.file) if os.path.exists(parsed.file) else print('Cannot file specified keyring file, set to None')
        stats['used']  = 0
        with open('./temp_config.json' if parsed.temp else home_path, 'w') as wir:
            json.dump(stats, wir)
    elif parsed.temp:
        stats['kring'] = os.path.abspath(parsed.file) if os.path.exists(parsed.file) else print('Cannot file specified keyring file, set to None')
        stats['used']  = 0
        with open('./temp_config.json' if parsed.temp else home_path, 'w') as wir:
            json.dump(stats, wir)
    elif not (os.path.exists(home_path) or os.path.exists('./temp_config.json')):
        raise ValueError("Specify the config file first, use -h option to know how to use")
    
    try:
        with open(home_path) as red:
            stats = json.load(red)
    except FileNotFoundError as e:
        with open('./temp_config.json') as red:
            stats = json.load(red)

    kring = keyring.Keyring()
    password = getpass.getpass(prompt="Enter your password(or a new one): ", stream=None)
    #Making a new keyring for the user, if they choose to encrypt
    if parsed.encrypt and not stats['kring']:
        kring.create(password)
        stats['kring'] = os.path.abspath('new.kring')
    elif not stats['kring']:
        print("Cannot find the required keyring, quitting")
        exit()

    kring.load(stats['kring'])
    kring.decrypt(password)

    # Now to the actual encryption and decryption
    if parsed.encrypt:
        with open(parsed.file, 'rb') as red:
            cip = cypher.Cipher(red)
            key = cip.encrypt()
            kring.import_key(key)
            stats['used'] += 1
    elif parsed.decrypt:
        # Getting the bsh of the file, eliminate this later
        with open(parsed.file, 'rb') as tmp:
            bsh = tmp.read(32)
        with open(parsed.file, 'rb') as red:
            cip = cypher.Cipher(red,'d')
            key = kring.search_key(bsh)
            cip.decrypt(key)
            stats['used'] += 1

    kring.encrypt(password)
    kring.save()
    
    try:
        with open(home_path, 'w') as red:
            stats = json.dump(stats, red)
    except FileNotFoundError as e:
        with open('./temp_config.json', 'w') as red:
            stats = json.dump(stats, red)
       

if __name__ == "__main__":
    main()
else:
    assert 1==0, "Do not import cli, why would you do that?"
