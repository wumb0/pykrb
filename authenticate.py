from pykrb.client import Client
from pykrb.utils import register

cli = Client("jaime", "example.com", "127.0.0.1", 8888)
cli.kinit()
cli.request_svc_tkt("HTTP", cli.realm)
cli.app_auth('127.0.0.1', 8889)
print("Service name from service authenticator: " + cli.svcauth.user_id)
