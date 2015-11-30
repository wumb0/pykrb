""" This is the client implementation for the kerberos authentication model """
import sys
from krb import *
from utils import *
import socket
from hashlib import sha256
from getpass import getpass
from base64 import b64decode as b64d

def main():
    try:
        register("kdc.db", "dad", "password", "example.com")
    except: pass
    dad = TGTRequest()
    dad.user_id = "dad@EXAMPLE.COM"
    dad.tgs_id = "TGS"
    sock = socket.socket(type=socket.SOCK_DGRAM)
    addr = ("127.0.0.1", 8888)
    dad.send(sock, addr)
    #c = sha256(getpass("Password: ")+"dad@EXAMPLE.COM")
    c = sha256("passworddad@EXAMPLE.COM")
    sess = TGSSessionKey(blob=decrypt_data(sock.recv(1024)[1:], c.digest()))
    tgt_enc = sock.recv(1024)
    sock.sendto(tgt_enc, addr)
    auth = Authenticator(user_id=dad.user_id)
    auth.send(sock, sess.session_key, addr)
    svc_req = ServiceTicketRequest(svc_name="HTTP")
    svc_req.send(sock, addr)


if __name__ == '__main__':
    sys.exit(main())
