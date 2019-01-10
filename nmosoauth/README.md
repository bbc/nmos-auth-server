# Introduction

This is an example of an OAuth 2.0 server in [Authlib](https://authlib.org/) based on the [Authlib Oauth2 Server Example.](https://github.com/authlib/example-oauth2-server)

- Documentation: <https://docs.authlib.org/en/latest/flask/oauth2.html>
- Authlib Repo: <https://github.com/lepture/authlib>

## Getting Started

Set Flask and Authlib environment variables:

    # disable check https (DO NOT SET THIS IN PRODUCTION)
    $ export AUTHLIB_INSECURE_TRANSPORT=1

This can alternatively be added to the `~/.bashrc` script to persist between terminal closures.

Now, you can open your browser with `http://127.0.0.1:4999/`. Click on the `sign-in` link to create an account. 

### Creating a Client

Before testing, a client needs to be created:

![create a client](https://user-images.githubusercontent.com/290496/38811988-081814d4-41c6-11e8-88e1-cb6c25a6f82e.png)

Get your `client_id` and `client_secret` for testing. In this example, we
have enabled `password` grant types, let's try:

```
curl -u ${client_id}:${client_secret} -XPOST http://127.0.0.1:4999/oauth/token -F grant_type=password -F username=${username} -F password=valid -F scope=profile
```

Use the username and password you used when signing up. For now, you
can read the source in example or follow the long boring tutorial below.

**IMPORTANT**: To test implicit grant, you need to `token_endpoint_auth_method` to `none`.

### Folder structure

Here is our Flask website structure:

```
app.py                --- FLASK_APP
oath2_server/
  app.py              --- Flask App Factory
  models.py           --- SQLAlchemy Models
  oauth2.py           --- OAuth 2.0 Provider Configuration
  security_api.py     --- Routes views
  security_service.py --- Service file and mdns registration
  token.py            --- Contains Token Generator class
  templates/          --- static comment (*.js, *.css)
resource_server/
  nmos_security       ---decorator for endpoints
```

## Define Models

SQLAlchemy is used as the Object Relational Mapper (ORM) and SQLite as the database software. You can also use other
databases and other ORM engines. Authlib has some built-in SQLAlchemy mixins which makes it easier for creating models.

The models are found in `oauth2_server/models.py`. The five models are:

- User: you need a user to test and create your application
- OAuth2Client: the oauth client model
- OAuth2AuthorizationCode: for `grant_type=code` flow
- OAuth2Token: save the `access_token` in this model.
- Access Rights: stores API access rights per user, defined during signup

## Implement Grants

The source code is in `oauth2_server/oauth2.py`. There are four standard grant types:

- Authorization Code Grant
- Implicit Grant
- Client Credentials Grant
- Resource Owner Password Credentials Grant

And Refresh Token is implemented as a Grant in Authlib. You don't have to do
any thing on Implicit and Client Credentials grants, but there are missing
methods to be implemented in other grants, checkout the source code in
`oauth2_server/oauth2.py`.


## Secure Endpoints

Securing ednpoints can be achieved by importing the `NmosSecurity` class:

```bash
from nmos_oauth/resource_server/nmos_security import NmosSecurity

# apply decorator to endpoint
@route('/' + APINAME + '/')
@NmosSecurity(condition=SECURITY)
  def __nameindex(self):
    return (200, ["v1.0/"])
```


## OAuth Routes

For OAuth server itself, we only need to implement routes for authentication,
and issuing tokens. Since we have added token revocation feature, we need a
route for revoking too.

Checkout these routes in `oauth2_server/routes.py`. Their paths begin with `/oauth/`.


## Other Routes

Other endpoints include:

* /oauth/token - for requesting a token
* /signup - for adding a user
* /create_client - creating a client
* /certs - publicly available certificate containing public key (these can be generated using the `generate_cert.sh` script)
