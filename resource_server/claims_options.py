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

IS_04_REG_CLAIMS = {
    "iat": {"essential": True},
    "nbf": {"essential": False},
    "exp": {"essential": True},
    "iss": {"essential": True},
    "sub": {"essential": True},
    "aud": {"essential": True},
    "scope": {"essential": True},
    "x-nmos-api": {"essential": True,
                   "value": ["is-04"],
                   "validate": "validate_nmos"
                   }
}

IS_04_QUERY_CLAIMS = {
    "iat": {"essential": True},
    "nbf": {"essential": False},
    "exp": {"essential": True},
    "iss": {"essential": True},
    "sub": {"essential": True},
    "aud": {"essential": True},
    "scope": {"essential": True},
    "x-nmos-api": {"essential": True,
                   "value": ["is-04"],
                   "validate": "validate_nmos"
                   }
}

IS_04_QUERY_CLAIMS = {
    "iat": {"essential": True},
    "nbf": {"essential": False},
    "exp": {"essential": True},
    "iss": {"essential": True},
    "sub": {"essential": True},
    "aud": {"essential": True},
    "scope": {"essential": True},
    "x-nmos-api": {"essential": True,
                   "value": ["is-04"],
                   "validate": "validate_nmos"
                   }
}

IS_04_QUERY_CLAIMS = {
    "iat": {"essential": True},
    "nbf": {"essential": False},
    "exp": {"essential": True},
    "iss": {"essential": True},
    "sub": {"essential": True},
    "aud": {"essential": True},
    "scope": {"essential": True},
    "x-nmos-api": {"essential": True,
                   "value": ["is-05"],
                   "validate": "validate_nmos"
                   }
}
