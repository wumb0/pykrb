from pykrb.auth_server import AuthServer
from sys import argv

AuthServer("example.com", port=int(argv[1]), kdcfile='./kdc.db')
