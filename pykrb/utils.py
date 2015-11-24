from kdc import *
from hashlib import sha256
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto import Random

def register(dbfile, name, password, realm):
    session = CreateAndGetSession(dbfile)
    toadd = KDC(name=name, realm=realm.upper(),
                secret_key=b64encode(sha256(password+name+'@'+realm.upper()).digest()))
    session.add(toadd)
    session.commit()
    return toadd

def encrypt_data(data, key):
    data += '\x00' * (AES.block_size - (len(data) % AES.block_size))
    iv = Random.new().read(AES.block_size)
    c = AES.new(key, AES.MODE_CBC, iv)
    return iv + c.encrypt(data)

def decrypt_data(data, key):
    iv = data[:AES.block_size]
    c = AES.new(key, AES.MODE_CBC, iv)
    return c.decrypt(data[AES.block_size:])
