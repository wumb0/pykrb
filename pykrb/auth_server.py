""" Server implementation """
from krb import *
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from kdc import *
from utils import *
from os import urandom

class KerberosAuthServerProtocol(DatagramProtocol):
    def datagramReceived(self, data, addr):
        print("Connection from {}".format(addr[0]))
        sock = self.transport.socket
        dtype = unpack("!b", data[0])[0]
        if not addr[0] in self.clients.keys():
            self.clients[addr[0]] = dict()

        if dtype == TGT_REQ:
            print("Got tgt req")
            try:
                tgtreq = TGTRequest(blob=data[1:])
            except:
                KrbError("Malformed TGT Request").send(sock, addr)
            self.clients[addr[0]]["TGT_REQ"] = tgtreq
            try:
                name, realm = tgtreq.user_id.split("@")
                client = self.session.query(KDC).filter_by(name=name, realm=realm).one()
            except:
                KrbError("Client is not in the KDC database or name is invalid").send(sock, addr)
                return
            skey = TGSSessionKey(tgs_id=self.tgs.name, valid_until=tgtreq.req_validity)
            tgt = TGT(client_id=client.name_realm, tgs_id=self.tgs.name,
                      net_addr=tgtreq.net_addr, valid_until=tgtreq.req_validity,
                      session_key=skey.session_key)
            skey.send(sock, client.secret_key_raw, addr)
            tgt.send(sock, self.tgs.secret_key_raw, addr)

        if dtype == CLI_AUTH:
            print("Got cli_auth")
            self.clients[addr[0]]["CLI_AUTH_BLOB"] = data[1:]

        if dtype == SVC_TKT_REQ:
            print("Got svc tkt req")
            try:
                auth = Authenticator(blob=decrypt_data(self.clients[addr[0]]["CLI_AUTH_BLOB"], self.clients[addr[0]]["TGT"].session_key))
            except:
                KrbError("Cannot decrypt client authenticator").send(sock, addr)
                return
            if self.clients[addr[0]]["TGT"].client_id != auth.user_id:
                KrbError("Authenticator user ID does not match user id in the TGT").send(sock, addr)
            elif (self.clients[addr[0]]["TGT_REQ"].net_addr != '0.0.0.0' and
                    self.clients[addr[0]]["TGT"].net_addr != addr[0]):
                KrbError("Network addresses of the client and the TGT do not match").send(sock, addr)
            else:
                svctktreq = ServiceTicketRequest(blob=data[1:])
                svcname, svcrealm = svctktreq.svc_id.split("@")
                try:
                    svc = self.session.query(KDC).filter_by(name=svcname, realm=svcrealm).one()
                except:
                    KrbError("The requested service does not exist in the database").send(sock, addr)
                svctkt = ServiceTicket(client_id=self.clients[addr[0]]["TGT"].client_id,
                                    svc_id=svc.name_realm,
                                    net_addr=self.clients[addr[0]]["TGT"].net_addr,
                                    valid_until=self.clients[addr[0]]["TGT"].valid_until)
                svc_sess_key = ServiceSessionKey(svc_id=svc.name_realm,
                                                session_key=svctkt.session_key,
                                                valid_until=self.clients[addr[0]]["TGT"].valid_until)
                svctkt.send(sock, svc.secret_key_raw, addr)
                svc_sess_key.send(sock, self.clients[addr[0]]["TGT"].session_key, addr)

        if dtype == TGT_RESP:
            print("Got tgt resp")
            try:
                self.clients[addr[0]]["TGT"] = TGT(blob=decrypt_data(data[1:], self.tgs.secret_key_raw))
            except:
                KrbError("Cannot decrypt received TGT").send(sock, addr)

        else:
            KrbError("Unknown packet type").send(sock, addr)

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
