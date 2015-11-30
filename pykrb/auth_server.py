""" Server implementation """
from krb import *
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from kdc import *
from utils import *
from os import urandom
from base64 import b64decode as b64d

class KerberosAuthServerProtocol(DatagramProtocol):
    def datagramReceived(self, data, addr):
        print("Connection from {}".format(addr[0]))
        dtype = unpack("!b", data[0])[0]
        if not addr[0] in self.clients.keys():
            self.clients[addr[0]] = dict()
        if dtype == TGT_REQ:
            print("Got tgt req")
            tgtreq = TGTRequest(blob=data[1:])
            self.clients[addr[0]]["TGT_REQ"] = tgtreq
            name, realm = tgtreq.user_id.split("@")
            try:
                client = self.session.query(KDC).filter_by(name=name, realm=realm).one()
            except:
                self.transport.loseConnection()
                return
            skey = TGSSessionKey()
            skey.tgs_id = self.tgs.name
            skey.valid_until = tgtreq.req_validity
            tgt = TGT(client_id=client.name_realm, tgs_id=self.tgs.name,
                      net_addr=tgtreq.net_addr, valid_until=tgtreq.req_validity,
                      session_key=skey.session_key)
            skey.send(self.transport.socket, b64d(client.secret_key), addr)
            tgt.send(self.transport.socket, b64d(self.tgs.secret_key), addr)
        if dtype == CLI_AUTH:
            print("Got cli_auth")
            self.clients[addr[0]]["CLI_AUTH_BLOB"] = data[1:]
        if dtype == SVC_TKT_REQ:
            print("Got svc tkt req")
            auth = Authenticator(blob=decrypt_data(self.clients[addr[0]]["CLI_AUTH_BLOB"], self.clients[addr[0]]["TGT"].session_key))
            if (self.clients[addr[0]]["TGT"].client_id == auth.user_id and
                (self.clients[addr[0]]["TGT_REQ"].net_addr == '0.0.0.0' or
                 self.clients[addr[0]]["TGT"].net_addr == addr[0])):
                self.clients[addr[0]]["SVC_TKT_REQ"] = ServiceTicketRequest(blob=data[1:])

        if dtype == TGT_RESP:
            print("Got tgt resp")
            self.clients[addr[0]]["TGT"] = TGT(blob=decrypt_data(data[1:], b64d(self.tgs.secret_key)))

    def __init__(self, realm, servicedbfile="kdc.db"):
        self.clients = {}
        self.session = CreateAndGetSession(servicedbfile)
        try:
            tgs = self.session.query(KDC).filter_by(id=1).one()
        except:
            tgs = register(servicedbfile, "TGS", urandom(32), realm)
        self.tgs = tgs

if __name__ == '__main__':
    print("Listening on 8888...")
    reactor.listenUDP(8888, KerberosAuthServerProtocol("example.com"))
    reactor.run()
