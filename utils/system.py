# A portable class I made for fetching useful information about a box.
from requests import get
from requests.exceptions import RequestException
from platform import processor, architecture, machine
from platform import system as sys_os
from os import getlogin, cpu_count, system, walk
from os.path import join, expanduser
from uuid import uuid4


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
