# Constants for nmos-oauth defining file and directory locations
import os

NMOSOAUTH_DIR = '/var/nmosoauth'
CERT_FILE = 'certificate.pem'
PRIVKEY_FILE = 'privkey.pem'
CERT_PATH = os.path.join(NMOSOAUTH_DIR, CERT_FILE)
CERT_ENDPOINT = '/certs'
CERT_KEY = 'default'
DATABASE_NAME = 'oauth_db'
