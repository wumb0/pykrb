from datetime import datetime, timedelta

""" client request functions """
class TGTRequest():
    user_id = -1
    tgs_id = 1
    net_addr = 0
    valid_until = datetime.now() + timedelta(days=1)

""" server response functions """
class TGSSessionKey():
    id = 0
    service_id = 0
    timestamp = datetime.now()
    net_addr = 0
    valid_until = datetime.now() + timedelta(days=1)
    session_key = ""


class TGSSecretKey():
    service_id = 0
    timestamp = datetime.now()
    valid_until = datetime.now() + timedelta(days=1)
    session_key = ""
