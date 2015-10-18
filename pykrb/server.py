""" Server implementation """
from kerberos import *
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor

class KerberosServerProtocol(Protocol):
    def connectionMade(self):
        self.transport.write("hello\r\n")
        self.transport.loseConnection()


class KerberosServer(Factory):
    protocol = KerberosServerProtocol


if __name__ == '__main__':
    print("Listening on 8888...")
    ep = TCP4ServerEndpoint(reactor, 8888)
    ep.listen(KerberosServer())
    reactor.run()
