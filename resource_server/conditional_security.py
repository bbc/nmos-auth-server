import requests
from requests import ConnectionError
from functools import wraps
from authlib.specs.rfc7519 import jwt
from flask import request
from authlib.specs.rfc7519.claims import JWTClaims

from authlib.common.errors import AuthlibHTTPError
from authlib.specs.rfc7519.errors import ExpiredTokenError
from authlib.flask.error import raise_http_exception
from .claims_options import IS_XX_CLAIMS
from authlib.specs.rfc6749.errors import *
from authlib.specs.rfc6750.errors import InvalidTokenError
from authlib.specs.rfc6749.errors import MissingAuthorizationError, \
    UnsupportedTokenTypeError
from authlib.specs.rfc7519.errors import InvalidClaimError, MissingClaimError


class JWTClaimsValidator(JWTClaims):

    def __init__(self, payload, header, options=None, params=None):  # for clarity only
        super(JWTClaimsValidator, self).__init__(payload, header, options=None, params=None)

    def validate_iss(self):
        print("YOU ARE IN THE CHILD FUNC VALIDATE_ISS")
        super(JWTClaimsValidator, self).validate_iss()
        pass

    def validate_sub(self):
        print("YOU ARE IN THE CHILD FUNC VALIDATE_SUB")
        super(JWTClaimsValidator, self).validate_sub()
        pass

    def validate_aud(self):
        print("YOU ARE IN THE CHILD FUNC VALIDATE_AUD")
        super(JWTClaimsValidator, self).validate_aud()
        pass

    def validate_nmos_api(self):
        print("YOU ARE IN THE FUNC VALIDATE NMOS API")
        pass

    def validate(self, now=None, leeway=0):
        super(JWTClaimsValidator, self).validate()
        self.validate_nmos_api()

    def validate_exp(self):
        pass


class ConditionalSecurity(object):

    def __init__(self, condition=True, claimsOptions=IS_XX_CLAIMS,
                 certURL="http://127.0.0.1:5000/certs", certificate=None):
        self.condition = condition
        self.claimsOptions = claimsOptions
        self.certificateURL = certURL
        self.certificate = certificate
        self.pubKey = None
        self.decorator = None

    def fetchCertURLFromService(self, MDNSService="_nmos-security._tcp"):
        MDNSServiceReq = requests.get(
            "http://localhost/x-ipstudio/mdnsbridge/v1.0/"
            + MDNSService + "/")
        MDNSServiceReq.raise_for_status()  # check request was succcessful
        MDNSService = MDNSServiceReq.json()
        oauthAddr = MDNSService['representation'][0]['address']
        oauthPort = MDNSService['representation'][0]['port']
        certEndpoint = (
            "http://" + str(oauthAddr) + ":" + str(oauthPort) + '/certs'
        )
        self.certificateURL = certEndpoint
        return certEndpoint

    def fetchCertFromEndpoint(self, url):
            try:
                oauthCerts = requests.get(url)
                oauthCerts.raise_for_status()  # check request was succcessful
            except ConnectionError as e:
                print("Error: " + str(e))
                print("Cannot find Cert Endpoint. Is the Auth Server Running?")
                raise
            if oauthCerts.headers['content-type'].split(";")[0] == "text/html":
                try:
                    if len(oauthCerts.json()) > 1:
                        print("Multiple certificates at Endpoint. Returning First.")
                    cert = oauthCerts.json()[0]
                except ValueError:
                    cert = oauthCerts.text
                self.certificate = cert
                return cert
            else:
                raise Exception("Incorrect Content-Type")

    def fetchCertFromFile(self, filename):
        # script_dir = os.path.dirname(__file__)
        # abs_cert_path = os.path.join(script_dir, filename)
        abs_cert_path = "/project-mcuk/ap/ipp/dannym/rd-apmm-python-oauth/oauth2_server/certs/certificate.pem"
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
            raise Exception(
                "Public Key could not be extracted from certificate")
        else:
            self.pubKey = pubKeyString
            return pubKeyString

    def getPublicKey(self):  # Make sure we have a certificate before extracting
        if self.certificate is None:
            try:  # TODO Add ability to check MDNS security service
                print("Fetching Cert from endpoint " + str(self.certificateURL))
                cert = self.fetchCertFromEndpoint(url=self.certificateURL)
            except Exception as e:
                print("Error: " + str(e) + ". Trying to fetch Cert From File...")
                cert = self.fetchCertFromFile("certs/certificate.pem")
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
                if token_type.lower() != "bearer":
                    raise UnsupportedTokenTypeError()
                if self.pubKey is None:
                    print("Public Key is not set.. fetching...")
                    self.pubKey = self.getPublicKey()
                claims = jwt.decode(token_string, self.pubKey,
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
