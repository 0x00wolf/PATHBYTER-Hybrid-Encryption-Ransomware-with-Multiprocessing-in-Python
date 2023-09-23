import json
from os import getpid, remove
from base64 import b64encode, b64decode


def __json_loads():
    with open('poc_db.json', 'r') as f:
        data = json.loads(f.read())
    
    return data


def __json_dump(json_db):
    with open('poc_db.json', 'w') as f:
        json.dump(json_db, f)


def init_PoC():
    message = 'Hello World!'
    target_files = []
    for i in range(10):
        file_name = f'helloworld{i+1}.txt'
        target_files.append(file_name)
        with open(file_name, 'w') as f:
            f.write(message * (i + 1))
    json_string = {'RSA session private keys': {}, 
                   'dummy file contents': {'before encryption': message,
                                           'after decryption': ''}}
    print("\n[*] POC - Dummy files generated.\n[*] Copying contents of 'helloworld1.txt' to 'poc_db.json'\n")
    with open('poc_db.json', 'w') as f:
        json.dump(json_string, f)

    return target_files


def add_sess_key(rsa_privkey):
    b64_privkey = b64encode(rsa_privkey).decode('utf-8')
    poc_db = __json_loads()
    poc_db['RSA session private keys']['before encryption'] = b64_privkey
    __json_dump(poc_db)
    print("\n[*] POC - Saving RSA session private key to 'poc_db.json'\n")


def add_dec_sess_key(rsa_privkey):
    poc_db = __json_loads()
    poc_db['RSA session private keys']['after decryption'] = rsa_privkey
    __json_dump(poc_db)
    print("\n[*] POC - Saving decrypted RSA session private key to 'poc_db.json'\n")


def check_file():
    with open('helloworld1.txt', 'r') as f:
        message = f.read()
    poc_db = __json_loads()
    poc_db['dummy file contents']['after decryption'] = message
    __json_dump(poc_db)
    print("\n[*] POC - Saving contents of decrypted 'helloworld1.txt' to 'poc_db.json'\n")


def check_rsa_session_key():
    check = input("\n>> Hit enter to perform checks on the contents of 'poc_db.json'\n")
    poc_db = __json_loads()
    if poc_db['RSA session private keys']['before encryption'] == \
        str(poc_db['RSA session private keys']['after decryption']):
            print('[*] RSA session private key matches entry after decryption: PASS')
    else:
        print('[*] RSA session private key matches entry after decryption: FAIL')


def check_dummy_file_contents():
    poc_db = __json_loads()
    if poc_db['dummy file contents']['before encryption'] == \
        poc_db['dummy file contents']['after decryption']:
            print('[*] Decrypted file contents match original file contents: PASS')
    else:
        print('[*] Decrypted file contents match original file contents: FAIL')


def print_encrypted_file(file_path):
    print(f'[*] File: {file_path} ~ encrypted in process {getpid()}')


def add_decrypted_idcard(idcard):
    _idcard = eval(idcard)
    poc_db = __json_loads()
    poc_db['Decrypted ID card:'] = _idcard
    __json_dump(poc_db)


def print_encrypted_db():
    with open('donotdelete.json', 'r') as f:
        encrypted_db = f.read()
    print(f"[*] Encrypted JSON Stub:\n{json.dumps(encrypted_db, indent=4)}")
    

def db_dumps():
    with open('poc_db.json', 'r') as f:
        data = json.loads(f.read())
    print(json.dumps(data, indent=4))


def clean_up():
    for i in range(10):
        file_name = f'helloworld{i+1}.txt'
        remove(file_name)
    print("\n[*] POC - Deleting dummy files\n")


def check_1():
    check = input("[!] Manually check the contents of the 'helloworld1.txt'\n\n>> Hit enter to begin the 'ransomware' attack")
    return check


def check_2():
    pause = input("[!] Manually check to see that the './helloworld1.txt' is encrypted\n\n>> Hit enter to begin decryption")
    return pause
