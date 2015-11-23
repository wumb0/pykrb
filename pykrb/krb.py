from datetime import datetime, timedelta
from struct import pack, unpack
import socket

""" Packet Types """
TGT_REQ  = 0
TGT_RESP = 1

""" client request functions """
class TGTRequest():
    user_id = ""
    tgs_id = "TGS"
    net_addr = "0.0.0.0"
    req_validity = datetime.now() + timedelta(days=1)

    def __init__(self, blob=None):
        if blob:
            cursor = blob[1:]
            user_id_len, = unpack("!h", cursor[:2])
            self.user_id = cursor[2:user_id_len+2]
            cursor = cursor[user_id_len+2:]
            tgs_id_len, = unpack("!h", cursor[:2])
            self.tgs_id = cursor[2:tgs_id_len+2]
            cursor = cursor[tgs_id_len+2:]
            self.net_addr = socket.inet_ntoa(cursor[:4])
            self.req_validity = datetime.fromtimestamp(unpack("!I", cursor[4:8])[0])

    def send(self, conn_tuple):
        sock = socket.socket()
        sock.connect(conn_tuple)
        p  = pack("!b", TGT_REQ)
        p += pack("!h", len(self.user_id))
        p += self.user_id
        p += pack("!h", len(self.tgs_id))
        p += self.tgs_id
        p += socket.inet_aton(sock.getsockname()[0])
        p += pack("!I", int(self.req_validity.strftime("%s")))
        print(p)
        sock.send(p)
        sock.close()

""" server response functions """
class TGSSessionKey():
    id = 0
    service_id = 0
    timestamp = datetime.now()
    net_addr = 0
    valid_until = datetime.now() + timedelta(days=1)
    session_key = ""


class TGSSecretKey():
    service_id = 0
    timestamp = datetime.now()
    valid_until = datetime.now() + timedelta(days=1)
    session_key = ""
