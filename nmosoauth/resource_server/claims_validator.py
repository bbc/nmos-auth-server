from authlib.specs.rfc7519.claims import JWTClaims
from authlib.specs.rfc7519.errors import InvalidClaimError


class JWTClaimsValidator(JWTClaims):

    def __init__(self, payload, header, options=None, params=None):
        super(JWTClaimsValidator, self).__init__(payload, header, options, params)

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
        claim_name = "x-nmos-api"
        option = self.options.get(claim_name)
        value = self.get(claim_name)
        if not option or not value:
            return

        option_value = option.get('value')
        if option_value and \
                (value.get('name') != option_value.get('name') or value.get('access') != option_value.get('access')):
            raise InvalidClaimError(claim_name)

    def validate(self, now=None, leeway=0):
        super(JWTClaimsValidator, self).validate()
        self.validate_nmos()
