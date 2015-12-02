from datetime import datetime, timedelta
from struct import pack, unpack
from Crypto import Random
from utils import encrypt_data
import socket

""" Packet Types """
TGT_REQ = 0
TGS_SESS_KEY = 1
TGT_RESP = 2
CLI_AUTH = 3
SVC_TKT_REQ = 4
SVC_TKT_RESP = 5
SVC_SESS_KEY = 6
KRB_ERR = 99

class TGTRequest(object):
    """Ticket Granting Ticket Request class
       Inherits: object
    """
    user_id = ""
    tgs_id = "TGS"
    net_addr = "0.0.0.0"
    req_validity = datetime.now() + timedelta(days=1)

    def __init__(self, blob=None):
        """Initializes a TGT Request from a binary blob"""
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
        """Creates a binary blob to send over the wire and then sends it unencrypted"""
        p  = pack("!b", TGT_REQ)
        p += pack("!h", len(self.user_id))
        p += self.user_id
        p += pack("!h", len(self.tgs_id))
        p += self.tgs_id
        p += socket.inet_aton(sock.getsockname()[0])
        p += pack("!I", int(self.req_validity.strftime("%s")))
        sock.sendto(p, addr)

class TGSSessionKey(object):
    """Ticket Granting Ticket session key class
       Inherits: object
    """
    timestamp = datetime.now()

    def __init__(self, blob=None, tgs_id="TGS", valid_until = datetime.now() + timedelta(days=1),
                 session_key=Random.new().read(32)):
        """Initializes a TGS session key from a binary blob OR arguments"""
        if blob:
            tgs_id_len, = unpack("!h", blob[:2])
            self.tgs_id = blob[2:tgs_id_len+2]
            cursor = blob[tgs_id_len+2:]
            self.valid_until = datetime.fromtimestamp(unpack("!I", cursor[:4])[0])
            self.timestamp = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])
            self.session_key = cursor[8:40]
        else:
            self.session_key = session_key
            self.tgs_id = tgs_id
            self.valid_until = valid_until

    def send(self, sock, key, addr):
        """Creates a binary blob to send over the wire and then sends it encrypted"""
        p  = pack("!h", len(self.tgs_id))
        p += str(self.tgs_id)
        p += pack("!I", int(self.valid_until.strftime("%s")))
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p += self.session_key
        p  = pack("!b", TGS_SESS_KEY) + encrypt_data(p, key)
        sock.sendto(p, addr)

class TGT(object):
    """Ticket Granting Ticket class
       Inherits: object
    """
    timestamp = datetime.now()

    def __init__(self, blob=None, client_id="", tgs_id="TGS", net_addr='0.0.0.0',
                 valid_until=datetime.now() + timedelta(days=1), session_key=Random.new().read(32)):
        """Initializes a TGT from a binary blob OR arguments"""
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
        """Creates a binary blob to send over the wire and then sends it encrypted"""
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

class Authenticator(object):
    """Client/Service authenticator class
       Inherits: object
    """
    timestamp = datetime.now()

    def __init__(self, blob=None, user_id=""):
        """Initializes a client authenticator from a binary blob OR arguments"""
        if blob:
            user_id_len, = unpack("!h", blob[:2])
            self.user_id = blob[2:user_id_len+2]
            self.timestamp = datetime.fromtimestamp(unpack("!I", blob[user_id_len+2:user_id_len+6])[0])
        else:
            self.user_id = user_id

    def send(self, sock, key, addr):
        """Creates a binary blob to send over the wire and then sends it encrypted"""
        p  = pack("!h", len(self.user_id))
        p += self.user_id
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p = pack("!b", CLI_AUTH) + encrypt_data(p, key)
        sock.sendto(p, addr)


class ServiceTicketRequest(object):
    """Service ticket request class
       Inherits: object
    """
    def __init__(self, blob=None, svc_id="", lifetime=datetime.now() + timedelta(days=1)):
        """Initializes a service ticket request from a binary blob OR arguments"""
        if blob:
            svc_id_len, = unpack("!h", blob[:2])
            self.svc_id = blob[2:svc_id_len+2]
            self.lifetime = datetime.fromtimestamp(unpack("!I", blob[svc_id_len+2:svc_id_len+6])[0])
        else:
            self.lifetime = lifetime
            self.svc_id = svc_id

    def send(self, sock, addr):
        """Creates a binary blob to send over the wire and then sends it unencrypted"""
        p  = pack("!b", SVC_TKT_REQ)
        p += pack("!h", len(self.svc_id))
        p += self.svc_id
        p += pack("!I", int(self.lifetime.strftime("%s")))
        sock.sendto(p, addr)


class ServiceTicket(object):
    """Service ticket class
       Inherits: object
    """
    timestamp = datetime.now()

    def __init__(self, blob=None, client_id="", svc_id="", net_addr='0.0.0.0',
                 valid_until=datetime.now() + timedelta(days=1), session_key=Random.new().read(32)):
        """Initializes a service ticket from a binary blob OR arguments"""
        if blob:
            client_id_len, = unpack("!h", blob[:2])
            self.client_id = blob[2:client_id_len+2]
            cursor = blob[client_id_len+2:]
            svc_id_len, = unpack("!h", cursor[:2])
            self.svc_id = cursor[2:svc_id_len+2]
            cursor = cursor[svc_id_len+2:]
            self.net_addr = socket.inet_ntoa(cursor[:4])
            self.valid_until = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])
            self.timestamp = datetime.fromtimestamp(unpack("!I", cursor[8:12])[0])
            self.session_key = cursor[12:44]
        else:
            self.client_id = client_id
            self.svc_id = svc_id
            self.net_addr = net_addr
            self.valid_until = valid_until
            self.session_key = session_key

    def send(self, sock, key, addr):
        """Creates a binary blob to send over the wire and then sends it encrypted"""
        p  = pack("!h", len(self.client_id))
        p += self.client_id
        p += pack("!h", len(self.svc_id))
        p += self.svc_id
        p += socket.inet_aton(self.net_addr)
        p  = str(p)
        p += pack("!I", int(self.valid_until.strftime("%s")))
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p += self.session_key
        p  = pack("!b", SVC_TKT_RESP) + encrypt_data(p, key)
        sock.sendto(p, addr)

class ServiceSessionKey(object):
    """Service session key class
       Inherits: object
    """
    timestamp = datetime.now()

    def __init__(self, blob=None, svc_id="", valid_until=datetime.now() + timedelta(days=1),
                 session_key=Random.new().read(32)):
        """Initializes a service session key from a binary blob OR arguments"""
        if blob:
            svc_id_len, = unpack("!h", blob[:2])
            self.svc_id = blob[2:svc_id_len+2]
            cursor = blob[svc_id_len+2:]
            self.valid_until = datetime.fromtimestamp(unpack("!I", cursor[:4])[0])
            self.timestamp = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])
            self.session_key = cursor[8:40]
        else:
            self.svc_id = svc_id
            self.valid_until = valid_until
            self.session_key = session_key

    def send(self, sock, key, addr):
        """Creates a binary blob to send over the wire and then sends it encrypted"""
        p  = pack("!h", len(self.svc_id))
        p += str(self.svc_id)
        p += pack("!I", int(self.valid_until.strftime("%s")))
        p += pack("!I", int(self.timestamp.strftime("%s")))
        p += self.session_key
        p  = pack("!b", SVC_SESS_KEY) + encrypt_data(p, key)
        sock.sendto(p, addr)

class KrbError(object):
    """Error response class
       Inherits: object
    """
    def __init__(self, error="General failure"):
        """Initializes a krb error with a default or user defined message"""
        self.error = error

    def send(self, sock, addr):
        """Creates a binary blob to send over the wire and then sends it unencrypted"""
        p  = pack("!b", KRB_ERR)
        p += self.error
        sock.sendto(p, addr)
