## Introduction

This is an example of an OAuth 2.0 server in [Authlib](https://authlib.org/) based on the [Authlib Oauth2 Server Example.](https://github.com/authlib/example-oauth2-server)

- Documentation: <https://docs.authlib.org/en/latest/flask/oauth2.html>
- Authlib Repo: <https://github.com/lepture/authlib>

## Getting Started

If not starting the service via `systemctl` / SystemD, then an Authlib environment variable must be set (if using over plain HTTP):

    # disable check https (DO NOT SET THIS IN PRODUCTION)
    $ export AUTHLIB_INSECURE_TRANSPORT=1

This can alternatively be added to the `~/.bashrc` script to persist between terminal closures. **NOTE**: This environment variable must be removed when in a production setting.

Now, you can open your browser at `http://127.0.0.1/x-nmos/auth/v1.0/home/`. Click on the `Signup` link to create an account.

## Creating a Client

Before testing, a client needs to be created:

![create a client](https://user-images.githubusercontent.com/290496/38811988-081814d4-41c6-11e8-88e1-cb6c25a6f82e.png)

Get your `client_id` and `client_secret` for testing. In this example, we
have enabled `password` and `authorization code` grant types.

A token can be obtained using:

```
curl -u ${client_id}:${client_secret} -XPOST http://127.0.0.1:4999/x-nmos/auth/v1.0/token -F grant_type=password -F username=${username} -F password=${password} -F scope=${scope}
```

Use the username and password you used when signing up. For now, you
can read the source in example or follow the tutorial below.

**IMPORTANT**: To test implicit grant, you need to set `token_endpoint_auth_method` to `none`.

## Folder structure

The file structure of the auth server is:

```
auth_server/
  app.py              --- Flask App Configuration Loader
  models.py           --- SQLAlchemy Models
  oauth2.py           --- OAuth 2.0 Provider Configuration
  security_api.py     --- Routes views
  security_service.py --- HTTP Server and mdns registration
  token_generator.py  --- Token Generator class
  handlers.py         --- error handlers
  settings.py         --- Flask Configuration classes
  basic_auth.py       --- Basic Auth Setup
  db_utils            --- Database Utility Funcs
  templates/          --- static content (*.html)
  static/             --- static content (*.js, *.css)
certs/
  generate_cert.sh    --- Cert and Key generation script
```

## Define Models

SQLAlchemy is used as the Object Relational Mapper (ORM) and SQLite as the database software. You can also use other
databases and other ORM engines. Authlib has some built-in SQLAlchemy mixins which makes it easier for creating models.

The models are found in `auth_server/models.py`. The five models are:

- User: you need a user to test and create your application
- OAuth2Client: the oauth client model
- OAuth2AuthorizationCode: for `grant_type=code` flow
- OAuth2Token: save the `access_token` in this model.
- Access Rights: stores API access rights per user, defined during signup

## Implement Grants

The source code is in `auth_server/oauth2.py`. There are four standard grant types:

- Authorization Code Grant
- Implicit Grant
- Client Credentials Grant
- Resource Owner Password Credentials Grant

Refresh Token is implemented as a Grant in Authlib. You don't have to do any thing on Implicit and Client Credentials grants, but there are missing methods to be implemented in other grants.


## Secure Endpoints

Securing ednpoints can be achieved by importing the `RequiresAuth` class from [NmosCommon](https://github.com/bbc/nmos-common):

```bash
from nmoscommon.auth.nmos_auth import RequiresAuth

# apply decorator to endpoint
@route('test-route')
@RequiresAuth(condition=True)
  def testroute(self):
    return (200, "Hello World")
```

## OAuth Routes

For a full list of endpoints please see `auth_server/security_api.py`. A prefix of `x-nmos/auth/v1.0` is prepended to endpoints:


* */token* - for requesting a token
* */signup* - for adding a user
* */register_client* - creating a client
* */certs* - publicly available certificate containing public key (these can be generated using the `generate_cert.sh` script)
* */fetch_token* - this is a user interface for fetching tokens from the auth server using the password credentials grant. This endpoint is purely for testing purposes, and uses JQuery HTTP Requests found in `auth_server/static/main.js` to fetch tokens.
