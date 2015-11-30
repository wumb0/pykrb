from datetime import datetime, timedelta
from struct import pack, unpack
from Crypto import Random
from utils import *
import socket

""" Packet Types """
TGT_REQ  = 0
TGS_SESS_KEY = 1
TGT_RESP = 2
CLI_AUTH = 3
SVC_TKT_REQ = 4
SVC_TKT_RESP = 5
SVC_SESS_KEY = 6
KRB_ERR = 99

""" client request functions """
class TGTRequest():
    user_id = ""
    tgs_id = "TGS"
    net_addr = "0.0.0.0"
    req_validity = datetime.now() + timedelta(days=1)

    def __init__(self, blob=None):
        if blob:
            user_id_len, = unpack("!h", blob[:2])
            self.user_id = blob[2:user_id_len+2]
            cursor = blob[user_id_len+2:]
            tgs_id_len, = unpack("!h", cursor[:2])
            self.tgs_id = cursor[2:tgs_id_len+2]
            cursor = cursor[tgs_id_len+2:]
            self.net_addr = socket.inet_ntoa(cursor[:4])
            self.req_validity = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])

    def send(self, sock, addr):
        p  = pack("!b", TGT_REQ)
        p += pack("!h", len(self.user_id))
        p += self.user_id
        p += pack("!h", len(self.tgs_id))
        p += self.tgs_id
        p += socket.inet_aton(sock.getsockname()[0])
        p += pack("!I", int(self.req_validity.strftime("%s")))
        sock.sendto(p, addr)

""" server response functions """
class TGSSessionKey():
    tgs_id = "TGS"
    valid_until= datetime.now() + timedelta(days=1)
    timestamp = datetime.now()

    def __init__(self, blob=None):
        self.session_key = Random.new().read(32)
        if blob:
            tgs_id_len, = unpack("!h", blob[:2])
            self.tgs_id = blob[2:tgs_id_len+2]
            cursor = blob[tgs_id_len+2:]
            self.valid_until = datetime.fromtimestamp(unpack("!I", cursor[:4])[0])
            self.timestamp = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])
            self.session_key = cursor[8:40]


    def send(self, sock, key, addr):
        p  = pack("!h", len(self.tgs_id))
        p += str(self.tgs_id)
        p += pack("!I", int(self.valid_until.strftime("%s")))
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p += self.session_key
        p  = pack("!b", TGS_SESS_KEY) + encrypt_data(p, key)
        sock.sendto(p, addr)

class TGT():
    timestamp = datetime.now()

    def __init__(self, blob=None, client_id="", tgs_id="TGS", net_addr='0.0.0.0',
                 valid_until=datetime.now() + timedelta(days=1), session_key=""):
        if blob:
            client_id_len, = unpack("!h", blob[:2])
            self.client_id = blob[2:client_id_len+2]
            cursor = blob[client_id_len+2:]
            tgs_id_len, = unpack("!h", cursor[:2])
            self.tgs_id = cursor[2:tgs_id_len+2]
            cursor = cursor[tgs_id_len+2:]
            self.net_addr = socket.inet_ntoa(cursor[:4])
            self.valid_until = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])
            self.timestamp = datetime.fromtimestamp(unpack("!I", cursor[8:12])[0])
            self.session_key = cursor[12:44]
        else:
            self.client_id = client_id
            self.tgs_id = tgs_id
            self.net_addr = net_addr
            self.valid_until = valid_until
            self.session_key = session_key

    def send(self, sock, key, addr):
        p  = pack("!h", len(self.client_id))
        p += self.client_id
        p += pack("!h", len(self.tgs_id))
        p += self.tgs_id
        p += socket.inet_aton(self.net_addr)
        p  = str(p)
        p += pack("!I", int(self.valid_until.strftime("%s")))
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p += self.session_key
        p  = pack("!b", TGT_RESP) + encrypt_data(p, key)
        sock.sendto(p, addr)

class Authenticator():
    timestamp = datetime.now()

    def __init__(self, blob=None, user_id=""):
        if blob:
            user_id_len, = unpack("!h", blob[:2])
            self.user_id = blob[2:user_id_len+2]
            self.timestamp = datetime.fromtimestamp(unpack("!I", blob[user_id_len+2:user_id_len+6])[0])
        else:
            self.user_id = user_id

    def send(self, sock, key, addr):
        p  = pack("!h", len(self.user_id))
        p += self.user_id
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p = pack("!b", CLI_AUTH) + encrypt_data(p, key)
        sock.sendto(p, addr)


class ServiceTicketRequest():
    def __init__(self, blob=None, svc_name="", lifetime=datetime.now() + timedelta(days=1)):
        if blob:
            svc_name_len, = unpack("!h", blob[:2])
            self.svc_name = blob[2:svc_name_len+2]
            self.lifetime = datetime.fromtimestamp(unpack("!I", blob[svc_name_len+2:svc_name_len+6])[0])
        else:
            self.lifetime = lifetime
            self.svc_name = svc_name

    def send(self, sock, addr):
        p  = pack("!b", SVC_TKT_REQ)
        p += pack("!h", len(self.svc_name))
        p += self.svc_name
        p += pack("!I", int(self.lifetime.strftime("%s")))
        sock.sendto(p, addr)


class ServiceSessionKey():
    pass

class ServiceTicket():

class KrbError():
    pass
