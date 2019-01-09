import os
import requests
from requests.exceptions import RequestException
from functools import wraps
from flask import request

from nmoscommon.mdnsbridge import IppmDNSBridge
from nmoscommon.nmoscommonconfig import config as _config
from authlib.specs.rfc7519 import jwt
from authlib.specs.rfc7519.claims import JWTClaims
from authlib.specs.rfc6749.errors import MissingAuthorizationError, \
    UnsupportedTokenTypeError
# from authlib.flask.error import raise_http_exception
# from authlib.specs.rfc7519.errors import InvalidClaimError, MissingClaimError
# from claims_options import IS_XX_CLAIMS

IS_XX_CLAIMS = {
    "iat": {"essential": True},
    "nbf": {"essential": False},
    "exp": {"essential": True},
    "iss": {"essential": True},
    "sub": {"essential": True},
    "aud": {"essential": True},
    "scope": {"essential": True},
    "x-nmos-api": {"essential": True}
}

CERT_ENDPOINT = "/certs"
CERT_FILE_PATH = "certs/certificate.pem"
MDNS_SERVICE_TYPE = "nmos-security"
SCRIPT_DIR = os.path.dirname(__file__)
OAUTH_MODE = _config.get('oauth_mode', True)


class JWTClaimsValidator(JWTClaims):

    def __init__(self, payload, header, options=None, params=None):  # for clarity only
        super(JWTClaimsValidator, self).__init__(payload, header, options=None, params=None)

    def validate_iss(self):
        super(JWTClaimsValidator, self).validate_iss()
        pass

    def validate_sub(self):
        super(JWTClaimsValidator, self).validate_sub()
        pass

    def validate_aud(self):
        super(JWTClaimsValidator, self).validate_aud()
        pass

    def validate_nmos(self):
        print("YOU ARE IN THE FUNC VALIDATE NMOS API")
        pass

    def validate(self, now=None, leeway=0):
        super(JWTClaimsValidator, self).validate()
        self.validate_nmos()


class NmosSecurity(object):

    def __init__(self, condition=OAUTH_MODE, claimsOptions=IS_XX_CLAIMS,
                 certificate=None):
        self.condition = condition
        self.claimsOptions = claimsOptions
        self.certificate = certificate
        self.decorator = None
        self.bridge = IppmDNSBridge()

    def getHrefFromService(self, serviceType):
        return self.bridge.getHref(serviceType)

    def getCertFromEndpoint(self):
        try:
            href = self.getHrefFromService(MDNS_SERVICE_TYPE)
            certHref = href + CERT_ENDPOINT
            print('cert href is: {}'.format(certHref))
            cert = requests.get(certHref, timeout=0.5, proxies={'http': ''})
            cert.raise_for_status()  # Raise error if status !=200
        except RequestException as e:
            print("Error: {0!s}".format(e))
            print("Cannot find certificate at {}. Is the Auth Server Running?".format(certHref))
            raise

        contentType = cert.headers['content-type'].split(";")[0]
        if contentType == "text/html":
            try:
                if len(cert.json()) > 1:
                    print("Multiple certificates at Endpoint. Returning First Instance.")
                cert = cert.json()[0]
            except ValueError:
                cert = cert.text
            self.certificate = cert
            return cert
        else:
            raise ValueError("Incorrect Content-Type. Expected 'text/html but got {}".format(contentType))

    def getCertFromFile(self, filename):
        abs_cert_path = os.path.join(SCRIPT_DIR, filename)
        try:
            if filename is not None:
                with open(abs_cert_path, 'r') as myfile:
                    cert_data = myfile.read()
                    self.certificate = cert_data
                    return cert_data
        except OSError:
            print("File does not exist or you do not have permission to open it")
            raise

    def extractPublicKey(self, certificate):
        from OpenSSL import crypto

        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        pubKeyObject = crtObj.get_pubkey()
        pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
        if pubKeyString is None:
            raise ValueError(
                "Public Key could not be extracted from certificate")
        else:
            return pubKeyString

    def getPublicKey(self):
        if self.certificate is None:
            print("Fetching Certificate...")
            try:
                print("Trying to fetch cert using mDNS...")
                cert = self.getCertFromEndpoint()
            except Exception as e:
                print("Error: {0!s}. Trying to fetch Cert From File...".format(e))
                cert = self.getCertFromFile(CERT_FILE_PATH)
            self.certificate = cert
        pubKey = self.extractPublicKey(self.certificate)
        return pubKey

    def JWTRequired(self):
        def JWTDecorator(func):
            @wraps(func)
            def processAccessToken(*args, **kwargs):
                auth = request.headers.get('Authorization')
                if not auth:
                    raise MissingAuthorizationError()
                token_type, token_string = auth.split(None, 1)
                if token_string == "null" or token_string == "":
                    raise MissingAuthorizationError()
                if token_type.lower() != "bearer":
                    raise UnsupportedTokenTypeError()
                pubKey = self.getPublicKey()
                claims = jwt.decode(token_string, pubKey,
                                    JWTClaimsValidator, self.claimsOptions, None)
                claims.validate()
                return func(*args, **kwargs)
            return processAccessToken
        return JWTDecorator

    def __call__(self, func):
        if not self.condition:
            # Return the function unchanged, not decorated.
            return func
        # Return decorated function
        self.decorator = self.JWTRequired()
        return self.decorator(func)
