from krb import TGTRequest, TGT, TGSSessionKey, Authenticator, ServiceTicketRequest, \
    ServiceTicket, ServiceSessionKey, KrbError, TGT_REQ, CLI_AUTH, SVC_TKT_REQ, TGT_RESP
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from kdc import KDC, CreateAndGetSession
from utils import decrypt_data, register
from struct import unpack
from Crypto import Random

class KerberosAuthServerProtocol(DatagramProtocol):
    """Authentication server protocol class
       Inherits: twisted DatagramProtocol
    """
    def datagramReceived(self, data, addr):
        """Receives a datagram from the reactor and decides what to do with it"""
        print("Connection from {}".format(addr[0]))
        sock = self.transport.socket

        # Get data type and maintain clients dict
        dtype = unpack("!b", data[0])[0]
        if not addr[0] in self.clients.keys():
            self.clients[addr[0]] = dict()

        # Ticket Granting Ticket Request packet received
        if dtype == TGT_REQ:
            print("Got tgt req")
            try:
                tgtreq = TGTRequest(blob=data[1:])
            except:
                KrbError("Malformed TGT Request").send(sock, addr)
            self.clients[addr[0]]["TGT_REQ"] = tgtreq
            try:
                # lookup the client in the KDC database
                name, realm = tgtreq.user_id.split("@")
                client = self.session.query(KDC).filter_by(name=name, realm=realm).one()
            except:
                KrbError("Client is not in the KDC database or name is invalid").send(sock, addr)
                return
            # create and send the TGS session key and TGT to the client
            skey = TGSSessionKey(tgs_id=self.tgs.name, valid_until=tgtreq.req_validity)
            tgt = TGT(client_id=client.name_realm, tgs_id=self.tgs.name,
                      net_addr=tgtreq.net_addr, valid_until=tgtreq.req_validity,
                      session_key=skey.session_key)
            skey.send(sock, client.secret_key_raw, addr)
            tgt.send(sock, self.tgs.secret_key_raw, addr)

        # Client Authenticator packet received, store it for later
        elif dtype == CLI_AUTH:
            print("Got cli_auth")
            self.clients[addr[0]]["CLI_AUTH_BLOB"] = data[1:]

        # Service ticket request received
        elif dtype == SVC_TKT_REQ:
            print("Got svc tkt req")
            try:
                # Decrypt the authenticator that was received previously
                auth = Authenticator(blob=decrypt_data(self.clients[addr[0]]["CLI_AUTH_BLOB"], self.clients[addr[0]]["TGT"].session_key))
            except:
                KrbError("Cannot decrypt client authenticator").send(sock, addr)
                return
            # do some checks
            if self.clients[addr[0]]["TGT"].client_id != auth.user_id:
                KrbError("Authenticator user ID does not match user id in the TGT").send(sock, addr)
            elif (self.clients[addr[0]]["TGT_REQ"].net_addr != '0.0.0.0' and
                    self.clients[addr[0]]["TGT"].net_addr != addr[0]):
                KrbError("Network addresses of the client and the TGT do not match").send(sock, addr)
            else:
                # checks passed, parse service ticket request from client
                svctktreq = ServiceTicketRequest(blob=data[1:])
                svcname, svcrealm = svctktreq.svc_id.split("@")
                try:
                    # look up the service in the KDC database
                    svc = self.session.query(KDC).filter_by(name=svcname, realm=svcrealm).one()
                except:
                    KrbError("The requested service does not exist in the database").send(sock, addr)
                # create and send the service ticket and service session key to the client
                svctkt = ServiceTicket(client_id=self.clients[addr[0]]["TGT"].client_id,
                                    svc_id=svc.name_realm,
                                    net_addr=self.clients[addr[0]]["TGT"].net_addr,
                                    valid_until=self.clients[addr[0]]["TGT"].valid_until)
                svc_sess_key = ServiceSessionKey(svc_id=svc.name_realm,
                                                session_key=svctkt.session_key,
                                                valid_until=self.clients[addr[0]]["TGT"].valid_until)
                svctkt.send(sock, svc.secret_key_raw, addr)
                svc_sess_key.send(sock, self.clients[addr[0]]["TGT"].session_key, addr)

        # TGT received from client
        elif dtype == TGT_RESP:
            print("Got tgt resp")
            try:
                self.clients[addr[0]]["TGT"] = TGT(blob=decrypt_data(data[1:], self.tgs.secret_key_raw))
            except:
                KrbError("Cannot decrypt received TGT").send(sock, addr)

        # Unknown packet type received
        else:
            print("Unknown packet type: " + str(dtype))
            KrbError("Unknown packet type").send(sock, addr)

    def __init__(self, tgsname, realm, kdcfile):
        """Initializes the Authentication server protocol with a name, realm, and KDC db file"""
        self.clients = {}
        self.session = CreateAndGetSession(kdcfile)
        try:
            tgs = self.session.query(KDC).filter_by(id=1).one()
        except:
            tgs = register(kdcfile, tgsname, Random.new().read(32), realm)
            if tgs.name != tgsname or tgs.realm != realm or tgs.id != 1:
                raise Exception("TGS must be id 1 and match the name and realm the server was constructed with")
        self.tgs = tgs

class AuthServer(object):
    """Authentication server class
       Inherits: object
    """
    def __init__(self, tgsname, realm, interface='0.0.0.0', port=8888, kdcfile='kdc.db'):
        """Creates a twisted reactor, initializes the authentication protocol, and starts the reactor"""
        reactor.listenUDP(port, KerberosAuthServerProtocol(tgsname, realm, kdcfile), interface=interface)
        reactor.run()
