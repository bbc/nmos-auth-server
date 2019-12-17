## Introduction

This is an example of an OAuth 2.0 server in [Authlib](https://authlib.org/) based on the [Authlib Oauth2 Server Example.](https://github.com/authlib/example-oauth2-server)

- Documentation: <https://docs.authlib.org/en/latest/flask/oauth2.html>
- Authlib Repo: <https://github.com/lepture/authlib>

## Getting Started

If using over plain HTTP, ensure the following environment variable is set (it is set automatically if using the service via SystemD or using the Python executable):

```bash
# disable check https (DO NOT SET THIS IN PRODUCTION)
$ export AUTHLIB_INSECURE_TRANSPORT=1
```

This can alternatively be added to the `~/.bashrc` script to persist between terminal closures.

**NOTE**: This environment variable must be removed when in a production setting as JWT's should *always* be sent over a secured channel.

Now, you can open your browser at `http://127.0.0.1/x-nmos/auth/v1.0/home/` to see the home page of the Authorization Server.

## Signing Up

Click on the `Signup` link to create a user account. Enter your `username` and `password`. This username and password will be used when using the `Password Grant` or whenever Basic Authentication is required.

![signup_screenshot](https://user-images.githubusercontent.com/37411379/56799171-4e10cc80-6810-11e9-877b-b9d034622fc1.png)

**NOTE**: IS-04 and IS-05 Access Rights define the scope of the users permissions when accessing those APIs (the names can be altered to suit the needs of the implementation). The value can be set to *None, Read or Write*.

## Creating a Client

Before testing, a client needs to be created. Click on `Register Client` to register.

![register_client_screenshot](https://user-images.githubusercontent.com/37411379/56798671-279e6180-680f-11e9-82f8-b9a1d236655f.png)

In this example, we have enabled `password` and`authorization code` grant types.

Once a client is registered, a `client_id` and `client_secret` is generated and displayed on the home page with other metadata.

![home_screenshot](https://user-images.githubusercontent.com/37411379/56799872-ab594d80-6811-11e9-9a7c-38a2f2d5e28e.png)

## Retrieving a Token

A simple web form can be found by clicking on `Request Token`.

![fetch_token_screenshot](https://user-images.githubusercontent.com/37411379/56798734-48ff4d80-680f-11e9-9b2b-730ffe2235e1.png)

Alternatively, a token can be obtained from the command line using:

```bash
curl -u ${client_id}:${client_secret} -XPOST http://127.0.0.1:4999/x-nmos/auth/v1.0/token -F grant_type=password -F username=${username} -F password=${password} -F scope=${scope}
```

Use the username and password (and scope if one was supplied) you used when signing up.

**IMPORTANT**: To test implicit grant, you need to set `token_endpoint_auth_method` to `none`.

## Folder structure

The file structure of the auth server is:

```
auth_server/
  app.py              --- Flask App Configuration Loader
  basic_auth.py       --- Basic Auth Setup
  config.py           --- NMOS specific configuration
  db_utils            --- Database Utility Funcs
  handlers.py         --- error handlers
  models.py           --- SQLAlchemy Models
  oauth2.py           --- OAuth 2.0 Provider Configuration
  security_api.py     --- Routes views
  security_service.py --- HTTP Server and mdns registration
  settings.py         --- Flask Configuration classes
  token_generator.py  --- Token Generator class
  templates/          --- static content (*.html)
  static/             --- static content (*.js, *.css)
certs/
  gen_cert.py         --- Cert and Key generation script
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

There is a test route found at `http://localhost:4999/x-nmos/auth/v1.0/test/`

## OAuth Routes

For a full list of endpoints please see `auth_server/security_api.py`. A prefix of `x-nmos/auth/v1.0` is prepended to endpoints:


* */token* - for requesting a token
* */signup* - for adding a user
* */register-client* - creating a client
* */jwks* - contains cryptographic information about public keys to authenticate tokens (these can be generated using the `gen_cert.py` script)
* */fetch_token* - this is a user interface for fetching tokens from the auth server using the password credentials grant. This endpoint is purely for testing purposes, and uses JQuery HTTP Requests found in `auth_server/static/main.js` to fetch tokens.
