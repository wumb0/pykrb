from krb import ServiceTicket, Authenticator, CLI_AUTH, KrbError, SVC_TKT_RESP
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.task import LoopingCall
from twisted.internet import reactor
from utils import decrypt_data
from base64 import b64decode, b64encode
from threading import Thread
from Crypto import Random
from struct import unpack

class AppServer(Thread):
    """Application server class
       Inherits: Thread
    """

    def __init__(self, service_name="", realm="", secret_key=Random.new().read(32), ip='0.0.0.0', port=8888, service_keyfile=None):
        """Class constructor
           Builds the application server
           If a keyfile is specified it overwrites the specified service_name, realm, and secret key
        """
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
        """Function that is run every second to check if there was a request to stop the reactor"""
        if self.stopping:
            reactor.stop()

    def authenticated_clients(self):
        """Return a list of authenticated clients"""
        cli = []
        for i in self.clients.keys():
            if "AUTHENTICATED" in self.clients[i].keys() and self.clients[i]["AUTHENTICATED"] is True:
                cli.append(i)
        return cli

    def run(self):
        """Runs the reactor that serves the application protocol"""
        loopcall = LoopingCall(self.check_stop)
        loopcall.start(1)
        kprotocol = KerberosAppServerProtocol(self.service_name, self.realm, self.secret_key)
        self.clients = kprotocol.clients
        reactor.listenUDP(self.port, kprotocol, interface=self.ip)
        reactor.run(installSignalHandlers=0)

    def stop(self):
        """Set the stopping variable so that the reactor stops on the next check_stop call"""
        self.stopping = True

    def export_keyfile(self, filename=None):
        """Exports the service keyfile"""
        fname = "{}.{}-pykrb.key".format(self.service_name, self.realm)
        if filename:
            fname = filename
        with open(fname, "w") as f:
            f.write("|".join([self.service_name, self.realm, b64encode(self.secret_key)]))

class KerberosAppServerProtocol(DatagramProtocol):
    """Defines how the application server behaves
       Inherits: twisted DatagramProtocol
    """
    def datagramReceived(self, data, addr):
        """Handle a received datagram"""
        print("Connection from {}".format(addr[0]))
        sock = self.transport.socket

        # get the data type and keep track of clients
        dtype = unpack("!b", data[0])[0]
        if not addr[0] in self.clients.keys():
            self.clients[addr[0]] = dict()

        # client authenticator received
        if dtype == CLI_AUTH:
            print("Got client auth")
            self.clients[addr[0]]["CLI_AUTH_BLOB"] = data[1:]

        # Encrypted service ticket received
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

        # unknown type
        else:
            KrbError("Unknown or incorrect protocol").send(sock, addr)

    def __init__(self, service_name, realm, secret_key):
        """Initializes the application server protocol"""
        self.name = service_name
        self.realm = realm
        self.secret_key = secret_key
        self.name_realm = self.name+"@"+self.realm.upper()
        self.clients = {}
