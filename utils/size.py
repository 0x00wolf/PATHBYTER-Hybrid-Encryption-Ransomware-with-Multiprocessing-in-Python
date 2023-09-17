"""This was the test I used to determine the size in bytes of encrypted key and nonce that would be appended to each file. 
By determining the size I was able to concat the encoded JSON string to the encrypted file. When it came time to decrypt the file
I could read the entire file into a variable, slice off the correct number of bytes from the end of the file to retreive the JSON string, 
and create a new variable which was the file with the last 314 bytes removed."""
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

