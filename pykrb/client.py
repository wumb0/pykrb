""" This is the client implementation for the kerberos authentication model """
import sys
from krb import *
from utils import register

def main():
    try:
        register("kdc.db", "dad", "password", "example.com")
    except: pass
    dad = TGTRequest()
    dad.user_id = "dad@EXAMPLE.COM"
    dad.tgs_id = "TGS"
    dad.send(("127.0.0.1", 8888))


if __name__ == '__main__':
    sys.exit(main())
