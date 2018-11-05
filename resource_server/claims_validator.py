from authlib.specs.rfc7519.claims import JWTClaims


class JWTClaimsValidator(JWTClaims):
    def validate_iss(self):
        """The "iss" (issuer) claim identifies the principal that issued the
        JWT.  The processing of this claim is generally application specific.
        The "iss" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        """
        print("WHAT THE HELL AM I DOING??!?!?!")
        print("YOU ARE IN THE CHILD FUNC VALIDATE_ISS")
        self._validate_claim_value('iss')
