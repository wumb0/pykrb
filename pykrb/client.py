""" This is the client implementation for the kerberos authentication model """
from krb import TGSSessionKey, TGTRequest, Authenticator, ServiceSessionKey, \
    ServiceTicketRequest, TGT_RESP, TGS_SESS_KEY, SVC_SESS_KEY, SVC_TKT_RESP, KRB_ERR
from utils import decrypt_data
import socket
from base64 import b64encode
from hashlib import sha256
from getpass import getpass
from struct import unpack, pack
from select import select

class Client(object):
    """Client object
       Inhertis: object
    """
    def __init__(self, name, realm, auth_ip, auth_port, auth_id="TGS"):
        """Initializes the client object"""
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
        """Communicates with the Auth server to get the TGT and TGS Session key"""
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
        """Communicates with the TGS to get the service ticket and the service session key"""
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
        """Authenticates to a requested application"""
        saddr = (svc_ip, svc_port)
        if not self.stkt or not self.ssession:
            raise KrbException("Service session key or ticket are blank, run request_svc_tkt")
        auth = Authenticator(user_id=self.name_realm)
        auth.send(self.sock, self.ssession.session_key, saddr)
        self.sock.sendto(self.stkt, saddr)
        authblob = self.recv(saddr)
        self.svcauth = Authenticator(blob=decrypt_data(authblob[1], self.ssession.session_key))

    def recv(self, addr, bytes=1024, timeout=5):
        """Custom receive function that has a timeout and error handling"""
        inp = select([self.sock], [], [], timeout)
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
        """Exports the user's information to a keyfile"""
        fname = "{}.{}-pykrb.key".format(self.name, self.realm)
        if not self.secret_key:
            self.secret_key = sha256(getpass("Kinit password: ")+self.name +"@"+self.realm.upper()).digest()
        if filename:
            fname = filename
        with open(fname, "w") as f:
            f.write("|".join([self.service_name, self.realm, b64encode(self.secret_key)]))

class KrbException(Exception):
    """Basic custom exception for the client library
       Inherits: Exception
    """
    pass
