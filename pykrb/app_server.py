from krb import *
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.task import LoopingCall
from twisted.internet import reactor
from kdc import *
from utils import *
from base64 import b64decode, b64encode
from threading import Thread
from Crypto import Random

class AppServer(Thread):
    def __init__(self, service_name="", realm="", secret_key=Random.new().read(32), ip='0.0.0.0', port=8888, service_keyfile=None):
        self.service_name = service_name
        self.realm = realm.upper()
        self.secret_key = secret_key
        self.ip = ip
        self.port = port
        self.stopping = False
        if service_keyfile:
            with open(service_keyfile) as f:
                self.service_name, self.realm, self.secret_key = f.readline().split("|")
                self.secret_key = b64decode(self.secret_key)
        if len(self.secret_key) != 32:
            raise Exception("Secret key must be 32 bytes long")
        super(AppServer, self).__init__()

    def check_stop(self):
        if self.stopping:
            reactor.stop()

    def authenticated_clients(self):
        cli = []
        for i in self.clients.keys():
            if "AUTHENTICATED" in self.clients[i].keys() and self.clients[i]["AUTHENTICATED"] == True:
                cli.append(i)
        return cli

    def run(self):
        loopcall = LoopingCall(self.check_stop)
        loopcall.start(1)
        kprotocol = KerberosAppServerProtocol(self.service_name, self.realm, self.secret_key)
        self.clients = kprotocol.clients
        reactor.listenUDP(self.port, kprotocol, interface=self.ip)
        reactor.run(installSignalHandlers=0)

    def stop(self):
        self.stopping = True

    def export_keyfile(self, filename=None):
        fname = "{}.{}-pykrb.key".format(self.service_name, self.realm)
        if filename:
            fname = filename
        with open(fname, "w") as f:
            f.write("|".join([self.service_name, self.realm, b64encode(self.secret_key)]))

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

        elif dtype == SVC_TKT_RESP:
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
                self.clients[addr[0]]["AUTHENTICATED"] = True
                print("Client "+addr[0]+" authenticated successfully")

        else:
            KrbError("Unknown or incorrect protocol").send(sock, addr)

    def __init__(self, service_name, realm, secret_key):
        self.name = service_name
        self.realm = realm
        self.secret_key = secret_key
        self.name_realm = self.name+"@"+self.realm.upper()
        self.clients = {}
