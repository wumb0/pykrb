from pykrb.auth_server import AuthServer
from sys import argv

# creates an authentication server called TGS in the realm example.com and stores the KDC database in a file called kdc.db
AuthServer("TGS", "example.com", port=int(argv[1]), kdcfile='./kdc.db')
