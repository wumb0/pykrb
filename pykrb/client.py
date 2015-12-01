""" This is the client implementation for the kerberos authentication model """
from krb import *
from utils import *
import socket
from hashlib import sha256
from getpass import getpass
from struct import unpack, pack
from select import select

def main():
    try:
        register("kdc.db", "dad", "password", "example.com")
    except: pass
    dad = TGTRequest()
    dad.tgs_id = "TGS"
    dad.user_id = "dad@EXAMPLE.COM"
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
    svc_req = ServiceTicketRequest(svc_id="HTTP@EXAMPLE.COM")
    svc_req.send(sock, addr)
    svc_tkt = sock.recv(1024)
    svcsess = ServiceSessionKey(blob=decrypt_data(sock.recv(1024)[1:], sess.session_key))
    saddr = ("127.0.0.1", 8889)
    auth = Authenticator(user_id=dad.user_id)
    auth.send(sock, svcsess.session_key, saddr)
    sock.sendto(svc_tkt, saddr)
    svcauth = Authenticator(blob=decrypt_data(sock.recv(1024)[1:], svcsess.session_key))
    print(svcauth.user_id)

class Client(object):
    def __init__(self, name, realm, auth_ip, auth_port, auth_id="TGS"):
        self.sock = socket.socket(type=socket.SOCK_DGRAM)
        self.name = name
        self.realm = realm.upper()
        self.auth_addr = (auth_ip, int(auth_port))
        self.auth_id = auth_id
        self.name_realm = "@".join([self.name, self.realm])
        self.secret_key = None
        self.ksession = None
        self.tgt = None
        self.ssession = None
        self.stkt = None

    def kinit(self, password=None):
        if not password:
            password = getpass("Kinit password: ")
        self.secret_key = sha256(password+self.name +"@"+self.realm.upper()).digest()
        req = TGTRequest()
        req.user_id = self.name_realm
        req.tgs_id = self.auth_id
        req.send(self.sock, self.auth_addr)
        data = []
        data.append(self.recv(self.auth_addr))
        data.append(self.recv(self.auth_addr))
        for i in data:
            if i[0] == TGS_SESS_KEY:
                self.ksession = TGSSessionKey(blob=decrypt_data(i[1], self.secret_key))
            if i[0] == TGT_RESP:
                self.tgt = pack("!b", i[0]) + i[1]

    def request_svc_tkt(self, svc_name, svc_realm):
        if not self.ksession or not self.tgt:
            raise KrbException("TGS Session key or TGT are blank, run kinit")
        self.sock.sendto(self.tgt, self.auth_addr)
        auth = Authenticator(user_id=self.name_realm)
        auth.send(self.sock, self.ksession.session_key, self.auth_addr)
        req = ServiceTicketRequest(svc_id='@'.join([svc_name, svc_realm]))
        req.send(self.sock, self.auth_addr)
        data = []
        data.append(self.recv(self.auth_addr))
        data.append(self.recv(self.auth_addr))
        for i in data:
            if i[0] == SVC_SESS_KEY:
                self.ssession = ServiceSessionKey(blob=decrypt_data(i[1], self.ksession.session_key))
            if i[0] == SVC_TKT_RESP:
                self.stkt = pack("!b", SVC_TKT_RESP) + i[1]

    def app_auth(self, svc_ip, svc_port):
        saddr = (svc_ip, svc_port)
        if not self.stkt or not self.ssession:
            raise KrbException("Service session key or ticket are blank, run request_svc_tkt")
        auth = Authenticator(user_id=self.name_realm)
        auth.send(self.sock, self.ssession.session_key, saddr)
        self.sock.sendto(self.stkt, saddr)
        authblob = self.recv(saddr)
        self.svcauth = Authenticator(blob=decrypt_data(authblob[1], self.ssession.session_key))

    def recv(self, addr, bytes=1024):
        inp = select([self.sock], [], [], 5)
        if inp[0]:
            data = self.sock.recv(bytes)
            dtype, = unpack("!b", data[0])
            if dtype == KRB_ERR:
                raise KrbException(data[1:])
            else:
                return (dtype, data[1:])
        else:
            raise KrbException("Server response timeout")

    def export_keyfile(self, filename=None):
        fname = "{}.{}-pykrb.key".format(self.name, self.realm)
        if not self.secret_key:
            self.secret_key = sha256(getpass("Kinit password: ")+self.name +"@"+self.realm.upper()).digest()
        if filename:
            fname = filename
        with open(fname, "w") as f:
            f.write("|".join([self.service_name, self.realm, b64encode(self.secret_key)]))

class KrbException(Exception):
    pass

if __name__ == '__main__':
    cli = Client("dad", "example.com", "127.0.0.1", 8888)
    cli.kinit("password")
    cli.request_svc_tkt("HTTP", cli.realm)
    cli.app_auth('127.0.0.1', 8889)
    print("Service name from service authenticator: " + cli.svcauth.user_id)
