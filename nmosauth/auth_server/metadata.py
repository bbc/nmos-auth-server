# Copyright 2019 British Broadcasting Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from socket import getfqdn
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata

from .config import config # noqa E402
from .constants import (
    JWK_ENDPOINT, TOKEN_ENDPOINT, REGISTER_ENDPOINT,
    AUTHORIZATION_ENDPOINT, REVOCATION_ENDPOINT, AUTH_VERSION_ROOT
)

SCOPES_SUPPORTED = ["registration", "node", "query", "connection", "netctrl", "events", "channelmapping"]
GRANT_TYPES_SUPPORTED = ["authorization_code", "refresh_token", "client_credentials"]
RESPONSE_TYPES_SUPPORTED = ["code"]
TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = ["client_secret_basic"]
CODE_CHALLENGE_METHODS_SUPPORTED = ["S256"]


def create_metadata(app):
    protocol = "https" if config.get("https_mode") == "enabled" else "http"
    hostname = protocol + '://' + getfqdn()
    namespace = hostname + AUTH_VERSION_ROOT
    metadata_dict = {
        "issuer": hostname,
        "authorization_endpoint": namespace + AUTHORIZATION_ENDPOINT,
        "token_endpoint": namespace + TOKEN_ENDPOINT,
        "token_endpoint_auth_methods_supported": TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        "token_endpoint_auth_signing_alg_values_supported": [app.config["OAUTH2_JWT_ALG"]],
        "jwks_uri": namespace + JWK_ENDPOINT,
        "registration_endpoint": namespace + REGISTER_ENDPOINT,
        "revocation_endpoint": namespace + REVOCATION_ENDPOINT,
        "scopes_supported": SCOPES_SUPPORTED,
        "response_types_supported": RESPONSE_TYPES_SUPPORTED,
        "grant_types_supported": GRANT_TYPES_SUPPORTED,
        "code_challenge_methods_supported": CODE_CHALLENGE_METHODS_SUPPORTED
    }
    # Validate Metadata
    metadata = AuthorizationServerMetadata(metadata_dict)
    return metadata
