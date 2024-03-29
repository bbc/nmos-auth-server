# NMOS Authorization API Implementation Changelog

## 1.5.0
- Add support for JWT client authentication
- Support registration scope for client_credentials grant

## 1.4.5
- Update JWT contents to contain flat `x-nmos-*` claim structure
- Support JSON body at `/authorize` endpoint

## 1.4.4
- Add fields to metadata endpoint. Add refresh token tests.
- Change request token page to use client credentials grant.

## 1.4.3
- Add validation for server metadata and upper pin werkzeug.

## 1.4.2
- Update Token Generator with current thinking for JWT claims.

## 1.4.1
- Issue new refresh token with each access token refresh.

## 1.4.0
- Upgrade to authlib 0.13 and update client registration view function.

## 1.3.4
- Change from /certs endpoint to serving JSON Web Keys at /jwks.
  Host server metadata endpoint at `/.well-known/oauth-authorization-server`.

## 1.3.3
- Use Python script to generate certs during debian install.

## 1.3.2
- Added further integration tests.

## 1.3.1
- Hash passwords and verify users against password hashes.

## 1.3.0
- Add Resource Owner database to allow one-to-many mapping between clients and end users. Add User page to UI.

## 1.2.0
- Add separate login_required decorator to decorate endpoints.

## 1.1.3
- Add PKCE Support.

## 1.1.2
- Add loading of external config file.

## 1.1.1
- Alter Jenkinsfile to build Python 3 package. Add "expires_in" config dict.

## 1.1.0
- Change scripts to run using Python3. Change 'iss' and 'aud' JWT claim generation.

## 1.0.10
- Change JWT signing algorithm to RS512 in line with BCP-001-02. Alter default scope for Bearer token to be same as in access token.

## 1.0.9
- Allow clients to register using JSON in-line with RFC7591. Change imports in-line with Authlib v0.11 release.

## 1.0.8
- Pin versions of PyOpenSSL and Cryptography to force package upgrades.

## 1.0.7
- Add "authorize" button per client to lead to user authorization page. Alter styling.

## 1.0.6
- Fix Authorization endpoint.

## 1.0.5
- Add ability to load external config. Load static elements locally for running offline.

## 1.0.4
- Move NMOS packages from recommends to depends

## 1.0.3
- Update install instructions in README

## 1.0.2
- Decode bytes objects as string objects for python3 compatibility

## 1.0.1
- Alter cert endpoint to comply with RAML, pin gevent version to 1.2.2

## 1.0.0
- Initial Release
