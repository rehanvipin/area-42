""" Command line version of area-42, works on any OS, provided with the required permissions.\
    Needs a config.json file to tell it the location of the keyring file, or a temp.json file \
    for temporary purpose. Can use the encrypt and decrypt option only for now """
import argparse
import os
import json
import getpass


import cypher
import keyring
import keys


Usage = """
usage: cli.py [-h] [-e] [-d] [-t] [--gen] [--gen_konf] [--kfile KFILE]
              [--export_key EXPORT_KEY] [--import_key IMPORT_KEY]
              [file [file ...]]

positional arguments:
  file                  The location of file(s) to encrypt or to decrypt

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt         Use to encrypt a file
  -d, --decrypt         Use to decrypt a file, Need to specify the config
                        first
  -t, --temp            Use for temporary configuration
  --gen                 Use to generate keyring
  --gen_konf            Used to make a configuration file, will be placed in
                        ~/area_config.json
  --kfile KFILE         location of keyring file
  --export_key EXPORT_KEY
                        Export the key for an encrypted input file, given the
                        password
  --import_key IMPORT_KEY
                        Import a key, given the key-file, into the keyring,
                        need the keyring password
"""


def gen_key(temp):
    password = getpass.getpass(prompt="Enter new password: ", stream=None)
    repeat = getpass.getpass(prompt="Repeat password: ", stream=None)
    if password != repeat:
        return print("Passwords do not match")
    fname = input(f"New keyring location (deafult: {os.curdir}/ufo.kring): ")
    if not fname:
        fname = os.path.join(os.curdir, 'ufo.kring')

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
    fil.seek(0, 0)
    key = kring.search_key(bsh)
    if not key:
        print("Cannot decrypt file, Key not found")
        return fil.close()
    try:
        cip.decrypt(key)
    except (ValueError, KeyError) as e:
        print("Cannot decrypt file", fil.name, "Corrupt data")


def main():
    stats = {}  # Contains info about keyring and use

    # The parser, to be used in cli as -> python cli.py --gen -ct -ed --kfile [kfile] [file]
    parsi = argparse.ArgumentParser()
    # parsi.add_argument('-c', '--config', action='store_true',
    #                    help='specify the location of the config file')
    parsi.add_argument('-e', '--encrypt', action='store_true',
                       help='Use to encrypt a file')
    parsi.add_argument('-d', '--decrypt', action='store_true',
                       help='Use to decrypt a file, Need to specify the config first')
    parsi.add_argument('-t', '--temp', action='store_true',
                       help='Use for temporary configuration')
    parsi.add_argument('--gen', action='store_true',
                       help='Use to generate keyring')
    parsi.add_argument('--gen_konf', action='store_true',
                       help='Used to make a configuration file, will be placed in ~/area_config.json')
    parsi.add_argument('--kfile', help='location of keyring file')
    parsi.add_argument('--export_key', 
    help='Export the key for an encrypted input file, given the password')
    parsi.add_argument('--import_key',
    help='Import a key, given the key-file, into the keyring, need the keyring password')
    parsi.add_argument('file', nargs='*',
                       help='The location of file(s) to encrypt or to decrypt')
    parsed = parsi.parse_args()

    if not any([parsed.encrypt, parsed.decrypt, parsed.temp, parsed.gen, parsed.kfile, \
    	parsed.gen_konf ,parsed.file, parsed.export_key, parsed.import_key]):
    	print(Usage)

    # Set the configuration file
    home_config_path = os.path.join(
        os.path.expanduser('~'), 'area_config.json')
    temp_config_path = os.path.join(os.curdir, 'temp_config.json')

    # Sets the temporary status
    temp = parsed.temp

    # Deal with the parsed values

    if parsed.gen:
        gen_key(temp)
        exit()
    
    if parsed.gen_konf:
        usage_stat = 0
        config_path = home_config_path
        if temp:
            config_path = temp_config_path
        if os.path.exists(config_path):
            print("Found a configuration file, updating it")
            with open(config_path) as red:
                temp_stats = json.load(red)
                usage_stat = temp_stats["used"]
        if not parsed.kfile:
            print("Could not a find a key-file")
            exit()
        stats = {"kring":parsed.kfile, "used":usage_stat}
        with open(config_path, "w") as wire:
            json.dump(stats, wire)
        print("Placed the configuration file in : ", config_path)
        exit()
    
    # Get the kring for all further actions
    if temp:
        with open(temp_config_path, 'r') as red:
            stats = json.load(red)
    else:
        with open(home_config_path, 'r') as red:
            stats = json.load(red)
    
    if parsed.export_key:
        #Get the keyring ready for the operations
        password = getpass.getpass(
            prompt="Enter master password: ", stream=None)
        kring = keyring.Keyring(stats['kring'])
        kring.load()
        kring.decrypt(password)

        # The parsed.export_key will be a file-name, of an encrypted file
        # Need to get the hash from it, search if it exists and
        # if it does export the key from the keyring
        with open(parsed.export_key, "rb") as red:
            bsh = red.read(32)
        #Got the binary hash, now to search with it
        key_to_export = kring.search_key(bsh)
        if not key_to_export:
            print("Could not find the key for this file in your keyring")
            exit()
        key_file_name = parsed.export_key+".key"
        key_to_export.save(key_file_name)

        print("Saved the key to the current directory")
        exit()
    
    if parsed.import_key:
        #Get the keyring ready for the operations
        password = getpass.getpass(
            prompt="Enter master password: ", stream=None)
        kring = keyring.Keyring(stats['kring'])
        kring.load()
        kring.decrypt(password)

        # Getting the key and adding it to the key-ring
        # Thank previous self for making these nice functions
        key_to_import = keys.Key(parsed.import_key, 'd')
        kring.import_key(key_to_import)
        kring.encrypt(password)
        kring.save()
        print("Added the key to the keyring")
        exit()

    # if parsed.config:
    #     path = parsed.kfile
    #     if path and not os.path.exists(path):
    #         raise ValueError(
    #             'Cannot find specified keyring, Use --gen to generate one')
    #     elif not path:
    #         print("Enter a kfile name using the --kfile option")
    #     stats['kring'] = os.path.join(os.curdir, path)
    #     stats['used'] = 0

    #     if parsed.temp:
    #         with open(temp_config_path, 'w') as wir:
    #             json.dump(stats, wir)
    #     else:
    #         with open(home_config_path, 'w') as wir:
    #             json.dump(stats, wir)
    #     exit()

    ipfiles = parsed.file
    if not ipfiles:
        exit()

    # Now need to get files and encrypt them
    # dirs = True
    # direcs = []
    # files = ipfiles
    # while dirs:
    #     for ifile in files:
    #         if os._isdir(ifile):
    #             direcs.append(ifile)

    faults = list(filter(lambda x: not os.path.exists(x), ipfiles))
    if faults:
        print("Cannot find the following files: ", *faults)
        exit()

    if parsed.encrypt:
        password = getpass.getpass(
            prompt="Enter master password: ", stream=None)
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
        password = getpass.getpass(
            prompt="Enter master password: ", stream=None)
        kring = keyring.Keyring(stats['kring'])
        kring.load()
        kring.decrypt(password)

        for msg in ipfiles:
            try:
                fil = open(msg, 'rb')
                decrypt(fil, kring)
            except (KeyError, ValueError) as e:
                print(e)
                print("Cannot decrypt ", fil.name)
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
