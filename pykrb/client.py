""" This is the client implementation for the kerberos authentication model """
import sys
from krb import *
from utils import *
import socket
from hashlib import sha256
from getpass import getpass
from base64 import b64decode

def main():
    try:
        register("kdc.db", "dad", "password", "example.com")
    except: pass
    dad = TGTRequest()
    dad.user_id = "dad@EXAMPLE.COM"
    dad.tgs_id = "TGS"
    sock = socket.socket()
    sock.connect(("127.0.0.1", 8888))
    dad.send(sock)
    c = sha256(getpass("Password: ")+"dad@EXAMPLE.COM")
    sess = TGSSessionKey(blob=decrypt_data(sock.recv(1024)[1:], c.digest()))
    print("Moving onto tgt")
    r = sock.recv(1024)[1:]
    print(len(r))
    tgt = TGT(blob=decrypt_data(r, b64decode("j1uWfG0YVLufknNAY3xVJAdja5vhKpzBg3GKnfkXXRs=")))
    print(tgt.session_key)

if __name__ == '__main__':
    sys.exit(main())
