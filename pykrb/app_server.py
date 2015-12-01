from krb import *
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from kdc import *
from utils import *
from base64 import b64decode as b64d

class KerberosAppServerProtocol(DatagramProtocol):
    def datagramReceived(self, data, addr):
        print("Connection from {}".format(addr[0]))
        sock = self.transport.socket
        dtype = unpack("!b", data[0])[0]
        if not addr[0] in self.clients.keys():
            self.clients[addr[0]] = dict()

        if dtype == CLI_AUTH:
            print("Got client auth")
            self.clients[addr[0]]["CLI_AUTH_BLOB"] = data[1:]

        if dtype == SVC_TKT_RESP:
            try:
                stkt = ServiceTicket(blob=decrypt_data(data[1:], self.secret_key))
            except:
                KrbError("Cannot decrypt service ticket").send(sock, addr)
                return
            try:
                cliauth = Authenticator(blob=decrypt_data(self.clients[addr[0]]["CLI_AUTH_BLOB"], stkt.session_key))
            except:
                KrbError("Cannot decrypt client authenticator").send(sock, addr)
                return
            if cliauth.user_id != stkt.client_id:
                KrbError("Client authenticator user id does not match service ticket id").send(sock, addr)
            elif stkt.net_addr != '0.0.0.0' and stkt.net_addr != addr[0]:
                KrbError("Network addresses of the client and the service ticket do not match").send(sock, addr)
            else:
                svcauth = Authenticator(user_id=self.name_realm)
                print("Sending svcauth")
                svcauth.send(sock, stkt.session_key, addr)

    def __init__(self, keyfile="app.key"):
        with open(keyfile) as f:
            self.name, self.realm, self.key = f.readline().split("|")
        self.secret_key = b64d(self.key)
        self.name_realm = self.name+"@"+self.realm.upper()
        self.clients = {}

if __name__ == '__main__':
    print("Listening on 8889...")
    reactor.listenUDP(8889, KerberosAppServerProtocol("HTTP.example.com-pykrb.key"))
    reactor.run()
