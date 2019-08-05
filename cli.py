""" Command line version of area-42, works on any OS, provided with the required permissions.\
    Needs a config.json file to tell it the location of the keyring file, or a temp.json file \
    for temporary purpose. Can use the encrypt and decrypt option only for now """
import argparse
import os
import json
import getpass


import cypher
import keyring


def gen_key(temp):
    password = getpass.getpass(prompt="Enter new password: ", stream=None)
    repeat = getpass.getpass(prompt="Repeat password: ", stream=None)
    if password != repeat:
        return print("Passwords do not match")
    fname = input(f"New keyring location (deafult: {os.curdir}/ufo.kring): ")

    kring = keyring.Keyring()
    try:
        kring.create(password, fname)
        print("Created successfully")
    except FileNotFoundError:
        print(f"Cannot create a file {fname}")


def encrypt(fil, kring):
    cip = cypher.Cipher(fil)
    key = cip.encrypt()
    kring.import_key(key)
    return key


def decrypt(fil, kring):
    cip = cypher.Cipher(fil, 'd')
    bsh = fil.read(32)
    fil.seek(0,0)
    key = kring.search_key(bsh)
    if not key:
        print("Cannot decrypt file, Key not found")
        return fil.close()
    cip.decrypt(key)


def main():
    stats = {} # Contains info about keyring and use

    #The parser, to be used in cli as -> python cli.py --gen -ct -ed --kfile [kfile] [file]
    parsi = argparse.ArgumentParser()
    parsi.add_argument('-c','--config', action='store_true', help='specify the location of the config file')
    parsi.add_argument('-e','--encrypt', action='store_true', help='Use to encrypt a file')
    parsi.add_argument('-d','--decrypt', action='store_true', help='Use to decrypt a file, Need to specify the config first')
    parsi.add_argument('-t','--temp', action='store_true', help='Use for temporary configuration')
    parsi.add_argument('--gen', action='store_true', help='Use to generate keyring')
    parsi.add_argument('--kfile', help='location of keyring file')
    parsi.add_argument('--file', nargs='+', help='The location of file(s) to encrypt or to decrypt')
    parsed = parsi.parse_args()

    # Set the configuration file 
    home_config_path = os.path.join(os.path.expanduser('~'), 'area_config.json')
    temp_config_path = os.path.join(os.curdir, 'temp_config.json')

    #Sets the temporary status
    temp = parsed.temp

    #Deal with the parsed values

    if parsed.gen:
        gen_key(temp)
        exit()

    if parsed.config:
        path = parsed.kfile
        if path and not os.path.exists(path):
            raise ValueError('Cannot find specified keyring, Use --gen to generate one')
        elif not path:
            print("Enter a kfile name using the --kfile option")
        stats['kring'] = path
        stats['used'] = 0

        if parsed.temp:
            with open(temp_config_path, 'w') as wir:
                json.dump(stats, wir)
        else:
            with open(home_config_path, 'w') as wir:
                json.dump(stats, wir)
        exit()

    ipfiles = parsed.file
    if not ipfiles:
        exit()
    faults = list(filter(lambda x: not os.path.exists(x), ipfiles))
    if faults:
        print("Cannot find the following files: ", *faults)
        exit()

    #Get the kring for all further actions
    if temp:
        with open(temp_config_path, 'r') as red:
            stats = json.load(red)
    else:
        with open(home_config_path, 'r') as red:
            stats = json.load(red)


    if parsed.encrypt:
        password = getpass.getpass(prompt="Enter master password: ", stream=None)
        kring = keyring.Keyring(stats['kring'])
        kring.load()
        kring.decrypt(password)
        for msg in ipfiles:
            try:
                fil = open(msg, 'rb')
                encrypt(fil, kring)
            finally:
                fil.close()
            stats['used'] += 1

        kring.encrypt(password)
        kring.save()

        del kring

    if parsed.decrypt:
        password = getpass.getpass(prompt="Enter master password: ", stream=None)
        kring = keyring.Keyring(stats['kring'])
        kring.load()
        kring.decrypt(password)

        for msg in ipfiles:
            try:
                fil = open(msg, 'rb')
                decrypt(fil, kring)
            finally:
                fil.close()
            stats['used'] += 1

        del kring

    # Recording all the changes to stats
    if temp:
        with open(temp_config_path, 'w') as wir:
            json.dump(stats, wir)
    else:
        with open(home_config_path, 'w') as wir:
            json.dump(stats, wir)

if __name__ == "__main__":
    main()
else:
    print("Created by ice-cold-articuno")
