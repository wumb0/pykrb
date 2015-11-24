""" Server implementation """
from krb import *
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from kdc import *
from utils import *
from os import urandom
from base64 import b64decode

class KerberosAuthServerProtocol(Protocol):
    def dataReceived(self, data):
        dtype = unpack("!b", data[0])[0]
        if dtype == TGT_REQ:
            tgtreq = TGTRequest(blob=data[1:])
            name, realm = tgtreq.user_id.split("@")
            try:
                client = self.factory.session.query(KDC).filter_by(name=name, realm=realm).one()
            except:
                self.transport.loseConnection()
                return
            skey = TGSSessionKey()
            skey.tgs_id = self.factory.tgs.name
            skey.valid_until = tgtreq.req_validity
            skey.send(self.transport.socket, b64decode(client.secret_key))
            tgt = TGT(client_id=client.name, tgs_id=self.factory.tgs.name,
                      net_addr=tgtreq.net_addr, valid_until=tgtreq.req_validity,
                      session_key=skey.session_key)
            tgt.send(self.transport.socket, b64decode(self.factory.tgs.secret_key))

class KerberosAuthServer(Factory):
    protocol = KerberosAuthServerProtocol

    def __init__(self, realm, servicedbfile="kdc.db"):
        self.session = CreateAndGetSession(servicedbfile)
        try:
            tgs = self.session.query(KDC).filter_by(id=1).one()
        except:
            tgs = register(servicedbfile, "TGS", urandom(32), realm)
        self.tgs = tgs




if __name__ == '__main__':
    print("Listening on 8888...")
    ep = TCP4ServerEndpoint(reactor, 8888)
    ep.listen(KerberosAuthServer("example.com"))
    reactor.run()
