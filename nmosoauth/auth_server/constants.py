# Constants for nmos-oauth defining file and directory locations
import os

NMOSOAUTH_DIR = '/var/nmosoauth'
CERT_FILE = 'certificate.pem'
CERT_PATH = os.path.join(NMOSOAUTH_DIR, CERT_FILE)
PRIVKEY_FILE = 'privkey.pem'
PRIVKEY_PATH = os.path.join(NMOSOAUTH_DIR, PRIVKEY_FILE)
CERT_ENDPOINT = '/certs'
CERT_KEY = 'default'
DATABASE_NAME = 'oauth_db'
