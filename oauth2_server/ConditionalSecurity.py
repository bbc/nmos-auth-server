import requests
from functools import wraps
from authlib.specs.rfc7519 import jwt
from authlib.specs.rfc6749.errors import MissingAuthorizationError, \
    UnsupportedTokenTypeError
from flask import request


class ConditionalSecurity(object):

    PUB_KEY = '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----
'''
    CLAIMS_OPTIONS = {
        "iat": {"essential": True},
        "exp": {"essential": True},
        "nbf": {"essential": False},
        "sub": {"essential": True,
                "values": ["api access", "API Access"]},
        "scope": {"essential": True,
                  "value": "profile"},
        "iss": {"essential": True}
    }

    def __init__(self, condition=True, pubKeyString=PUB_KEY,
                 claimsOptions=CLAIMS_OPTIONS):
        self.condition = condition
        self.pubKey = pubKeyString
        self.claimsOptions = claimsOptions
        self.certificateURL = None
        self.certificate = None
        self.decorator = None

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
                claims = jwt.decode(token_string, self.pubKey,
                                    None, self.claimsOptions, None)
                claims.validate()
                return func(*args, **kwargs)
            return processAccessToken
        return JWTDecorator

    def fetchCertURL(self, MDNSSecurityService="_nmos-security._tcp"):
        MDNSServiceReq = requests.get(
            "http://localhost/x-ipstudio/mdnsbridge/v1.0/"
            + MDNSSecurityService + "/")
        MDNSServiceReq.raise_for_status()  # check request was succcessful
        MDNSService = MDNSServiceReq.json()
        oauthAddr = MDNSService['representation'][0]['address']
        oauthPort = MDNSService['representation'][0]['port']
        certEndpoint = (
            "http://" + str(oauthAddr) + ":" + str(oauthPort) + '/certs'
        )
        self.certificateURL = certEndpoint
        return certEndpoint

    def fetchCert(self):
        if self.certificateURL is not None:
            oauthCerts = requests.get(self.certificateURL)
            oauthCerts.raise_for_status()  # check request was succcessful
            if len(oauthCerts.json()) > 1:
                print("Multiple certificates at Endpoint. Returning First.")
            self.certificate = oauthCerts.json()[0]
            return self.certificate
        else:
            raise Exception("No Certificate Endpoint Found.")

    def extractPublicKey(self):
        from OpenSSL import crypto
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.certificate)
        pubKeyObject = crtObj.get_pubkey()
        pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
        if pubKeyString is None:
            raise Exception(
                "Public Key could not be extracted from certificate")
        else:
            self.pubKey = pubKeyString
            return self.pubKey

    def __call__(self, func):
        if not self.condition:
            # Return the function unchanged, not decorated.
            return func
        # Return decorated function
        self.decorator = self.JWTRequired()
        return self.decorator(func)
