import SimpleHTTPServer, SocketServer
from pykrb.app_server import AppServer
import signal
from sys import exit

PORT = 8081
krb = AppServer(service_keyfile="pykrb/HTTP.example.com-pykrb.key", port=8889)
krb.start()
def sigint(a, b):
    krb.stop()
    exit(0)
signal.signal(signal.SIGINT, sigint)

class KrbHTTP(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.client_address[0] in krb.authenticated_clients():
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.wfile.write("<html><body>")
            self.wfile.write("Unauthorized")
            self.wfile.write("</body></html>")
            return


Handler = KrbHTTP
httpd = SocketServer.TCPServer(("", PORT), Handler)


print "serving at port", PORT
httpd.serve_forever()
