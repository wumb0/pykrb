""" Server implementation """
from datetime import datetime, timedelta
#from twisted.spread.jelly import jelly, unjelly
from pickle import loads, dumps
import sys
import socket
from kerberos import *


def main():
    s = socket.socket()
    s.bind((socket.gethostname(), 8888))
    s.listen(5)
    print("Listening on 8888...")
    (c, caddr) = s.accept()
    print("Connection from " + caddr[0])
    req = loads(c.recv(2048))
    print("User ID received: " + str(req.user_id))
    c.close()
    s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
