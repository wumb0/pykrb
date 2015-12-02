import SimpleHTTPServer, SocketServer
from pykrb.app_server import AppServer
import signal
from sys import exit

HTTPPORT = 8081

# set up the application server from the keyfile specified
krb = AppServer(service_keyfile="pykrb/HTTP.example.com-pykrb.key", port=8889)
krb.start()

# in case of sigint, the app server must be stopped first
def sigint(a, b):
    krb.stop()
    exit(0)
signal.signal(signal.SIGINT, sigint)

class KrbHTTP(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """Simple file browser HTTP server that authenticates based on authenticated IPs of kerberos clients"""
    def do_GET(self):
        """When an HTTP GET request comes in this function is run to handle it"""
        if self.client_address[0] in krb.authenticated_clients():
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.wfile.write("<html><body>")
            self.wfile.write("Unauthorized")
            self.wfile.write("</body></html>")
            return


# create the HTTP server and serve it
Handler = KrbHTTP
httpd = SocketServer.TCPServer(("", HTTPPORT), Handler)
print "serving at port", PORT
httpd.serve_forever()
