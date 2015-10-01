""" This is the client implementation for the kerberos authentication model """
from datetime import datetime, timedelta
import sys
from kerberos import *
import socket
from pickle import loads, dumps

def main():
    dad = TGTRequest()
    dad.user_id = 69
    s = socket.socket()
    s.connect((socket.gethostname(), 8888))
    pick = dumps(dad)
    s.send(str(pick))
    s.close()


if __name__ == '__main__':
    sys.exit(main())
