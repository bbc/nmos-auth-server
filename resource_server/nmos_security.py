import requests
from requests import ConnectionError
from functools import wraps
from flask import request

from authlib.specs.rfc7519 import jwt
from authlib.specs.rfc7519.claims import JWTClaims
# from claims_options import IS_XX_CLAIMS
from authlib.specs.rfc6749.errors import MissingAuthorizationError, \
    UnsupportedTokenTypeError
# from authlib.flask.error import raise_http_exception
# from authlib.specs.rfc7519.errors import InvalidClaimError, MissingClaimError
from nmoscommon.mdnsbridge import IppmDNSBridge

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

    def validate_nmos(self):
        print("YOU ARE IN THE FUNC VALIDATE NMOS API")
        pass

    def validate(self, now=None, leeway=0):
        super(JWTClaimsValidator, self).validate()
        self.validate_nmos()


class NmosSecurity(object):

    def __init__(self, condition=True, claimsOptions=IS_XX_CLAIMS,
                 certificate=None):
        self.condition = condition
        self.claimsOptions = claimsOptions
        self.certificate = certificate
        self.decorator = None

    def fetchCertEndpointsFromService(self, serviceType="nmos-security"):
        certEndpoints = []
        oauthServices = requests.get(
            "http://localhost/x-ipstudio/mdnsbridge/v1.0/"
            + serviceType + "/")
        oauthServices.raise_for_status()  # check request was succcessful
        oauthServices = oauthServices.json()
        for record in oauthServices:
            oauthAddr = record['representation'][0]['address']
            oauthPort = record['representation'][0]['port']
            certEndpoint = (
                "http://" + str(oauthAddr) + ":" + str(oauthPort) + '/certs'
            )
            certEndpoints.append(certEndpoint)
        print(certEndpoints)
        return certEndpoints

    def fetchServiceEntries(self, serviceType):
        bridge = IppmDNSBridge()
        return bridge.getHref

    def fetchCertFromEndpoint(self):
        try:
            endpoints = self.fetchCertEndpointsFromService("nmos-security")
            print(endpoints)
        except ConnectionError as e:
            print("Error: " + str(e))
            print("Cannot find certificate at {}. Is the Auth Server Running?".format(endpoints))
            raise
        for url in endpoints:
            try:
                oauthCerts = requests.get(url)
                oauthCerts.raise_for_status()
                break
            except Exception as e:
                pass
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
            raise ValueError("Incorrect Content-Type")

    def fetchCertFromFile(self, filename):
        import os
        script_dir = os.path.dirname(__file__)
        abs_cert_path = os.path.join(script_dir, filename)
        print(abs_cert_path)
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
            return pubKeyString

    def getPublicKey(self):
        if self.certificate is None:
            print("Fetching Certificate...")
            try:
                certURL = self.fetchCertFromEndpoint()
                print("Fetching Cert from endpoint " + str(certURL))
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