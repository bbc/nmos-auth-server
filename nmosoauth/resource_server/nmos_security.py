import os
import requests
from requests.exceptions import RequestException
from functools import wraps
from flask import request
from urlparse import parse_qs
from OpenSSL import crypto

from nmoscommon.mdnsbridge import IppmDNSBridge
from nmoscommon.nmoscommonconfig import config as _config
from nmoscommon.logger import Logger as defaultLogger
from authlib.specs.rfc7519 import jwt
from authlib.specs.rfc6749.errors import MissingAuthorizationError, \
    UnsupportedTokenTypeError

from .claims_options import IS_XX_CLAIMS
from .claims_validator import JWTClaimsValidator
from ..constants import CERT_ENDPOINT, CERT_PATH, CERT_KEY

MDNS_SERVICE_TYPE = "nmos-auth"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OAUTH_MODE = _config.get('oauth_mode', True)


class NmosSecurity(object):

    def __init__(self, condition=OAUTH_MODE, claimsOptions=IS_XX_CLAIMS,
                 certificate=None):
        self.condition = condition
        self.claimsOptions = claimsOptions
        self.certificate = certificate
        self.bridge = IppmDNSBridge()
        self.logger = defaultLogger("nmossecurity")

    def getHrefFromService(self, serviceType):
        return self.bridge.getHref(serviceType)

    def getCertFromEndpoint(self):
        try:
            href = self.getHrefFromService(MDNS_SERVICE_TYPE)
            certHref = href + CERT_ENDPOINT
            self.logger.writeInfo('cert href is: {}'.format(certHref))
            cert = requests.get(certHref, timeout=0.5, proxies={'http': ''})
            cert.raise_for_status()  # Raise error if status !=200
        except RequestException as e:
            self.logger.writeError("Error: {0!s}".format(e))
            self.logger.writeError("Cannot find certificate at {}. Is the Auth Server Running?".format(certHref))
            raise

        contentType = cert.headers['content-type'].split(";")[0]
        if contentType == "application/json":
            try:
                if len(cert.json()) > 1:
                    self.logger.writeWarning("Multiple certificates at Endpoint. Returning First Instance.")
                cert = cert.json()[CERT_KEY]
                return cert
            except KeyError as e:
                self.logger.writeError("Error: {}. Endpoint contains: {}".format(str(e), cert.json()))
                raise
        else:
            self.logger.writeError("Incorrect Content-Type. Expected 'application/json but got {}".format(contentType))
            raise ValueError

    def getCertFromFile(self, filename):
        try:
            if filename is not None:
                with open(filename, 'r') as myfile:
                    cert_data = myfile.read()
                    self.certificate = cert_data
                    return cert_data
        except OSError:
            self.logger.writeError("File does not exist or you do not have permission to open it")
            raise

    def extractPublicKey(self, certificate):
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        pubKeyObject = crtObj.get_pubkey()
        pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
        if pubKeyString is None:
            self.logger.writeError("Public Key could not be extracted from certificate")
            raise ValueError
        else:
            return pubKeyString

    def getPublicKey(self):
        if self.certificate is None:
            self.logger.writeInfo("Fetching Certificate...")
            try:
                self.logger.writeInfo("Trying to fetch cert using mDNS...")
                cert = self.getCertFromEndpoint()
            except Exception as e:
                self.logger.writeError("Error: {0!s}. Trying to fetch Cert From File...".format(e))
                cert = self.getCertFromFile(CERT_PATH)
            self.certificate = cert
        pubKey = self.extractPublicKey(self.certificate)
        return pubKey

    def processAccessToken(self, auth_string):
        token_type, token_string = auth_string.split(None, 1)
        if token_string == "null" or token_string == "":
            raise MissingAuthorizationError()
        if token_type.lower() != "bearer":
            raise UnsupportedTokenTypeError()
        pubKey = self.getPublicKey()
        claims = jwt.decode(s=token_string, key=pubKey,
                            claims_cls=JWTClaimsValidator,
                            claims_options=self.claimsOptions,
                            claims_params=None)
        claims.validate()

    def handleHttpAuth(self):
        """Handle bearer token string ("Bearer xAgy65...") in "Authorzation" Request Header"""
        auth_string = request.headers.get('Authorization', None)
        if auth_string is None:
            raise MissingAuthorizationError()
        self.processAccessToken(auth_string)

    def handleSocketAuth(self, *args, **kwargs):
        """Handle bearer token string ("Bearer xAgy65...") in Websocket URL Query Param"""
        ws = args[0]
        environment = ws.environ
        auth_header = environment.get('HTTP_AUTHORIZATION', None)
        if auth_header is not None:
            self.logger.writeInfo("auth header string is {}".format(auth_header))
            auth_string = auth_header
        else:
            self.logger.writeWarning("Websocket does not have auth header, looking in query string..")
            query_string = environment.get('QUERY_STRING', None)
            if query_string is not None:
                try:
                    auth_string = parse_qs(query_string)['authorization'][0]
                except KeyError:
                    self.logger.writeError("'authorization' URL param doesn't exist. Websocket authentication failed.")
                    raise MissingAuthorizationError()
        self.processAccessToken(auth_string)

    def JWTRequired(self):
        def JWTDecorator(func):
            @wraps(func)
            def processAccessToken(*args, **kwargs):
                print(args)
                if ('Upgrade' in request.headers.keys() and 'websocket' == request.headers['Upgrade'].lower()):
                    self.logger.writeInfo("Using Socket handler")
                    self.handleSocketAuth(*args, **kwargs)
                else:
                    self.logger.writeInfo("Using HTTP handler")
                    self.handleHttpAuth()
                return func(*args, **kwargs)
            return processAccessToken
        return JWTDecorator

    def __call__(self, func):
        if not self.condition:
            # Return the function unchanged, not decorated.
            return func

        # Return decorated function
        decorator = self.JWTRequired()
        return decorator(func)
