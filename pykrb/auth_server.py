""" Server implementation """
from krb import *
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from kdc import *
from utils import register, check_client
from os import urandom

class KerberosAuthServerProtocol(Protocol):
    def dataReceived(self, data):
        dtype = unpack("!b", data[0])[0]
        if dtype == TGT_REQ:
            tgtreq = TGTRequest(blob=data)
            name, realm = tgtreq.user_id.split("@")
            try:
                self.factory.session.query(KDC).filter_by(name=name, realm=realm).one()
            except:
                pass #send name not found in realm


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
