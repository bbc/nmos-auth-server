from authlib.specs.rfc7519.claims import JWTClaims
from authlib.specs.rfc7519.errors import InvalidClaimError, MissingClaimError


class JWTClaimsValidator(JWTClaims):

    def __init__(self, payload, header, options=None, params=None):
        super(JWTClaimsValidator, self).__init__(payload, header, options, params)

    def validate_iss(self):  # placeholder
        super(JWTClaimsValidator, self).validate_iss()
        pass

    def validate_sub(self):  # placeholder
        super(JWTClaimsValidator, self).validate_sub()
        pass

    def validate_aud(self):  # placeholder
        super(JWTClaimsValidator, self).validate_aud()
        pass

    def validate_nmos(self):
        claim_name = "x-nmos-api"
        valid_claim_option = self.options.get(claim_name)
        valid_claim_value = valid_claim_option.get('value')

        actual_claim_value = self.get(claim_name)
        if not actual_claim_value:
            raise MissingClaimError(claim_name)
        if not valid_claim_value:
            return

        for attr in valid_claim_value:
            if actual_claim_value.get(attr) != valid_claim_value.get(attr):
                raise InvalidClaimError(claim_name)

    def validate(self, now=None, leeway=0):
        super(JWTClaimsValidator, self).validate()
        self.validate_nmos()
