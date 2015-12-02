from pykrb.client import Client
from pykrb.utils import register

# creates a client object, and then runs the three functions required to
# authenticate with the auth server, request a service ticket, and authenticate
# with the application server
cli = Client("jaime", "example.com", "127.0.0.1", 8888)
cli.kinit()
cli.request_svc_tkt("HTTP", cli.realm)
cli.app_auth('127.0.0.1', 8889)
print("Service name from service authenticator: " + cli.svcauth.user_id)
