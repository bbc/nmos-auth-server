<!---NAME--->
# RD-APMM-PYTHON-OAUTH-SECURITY
<!---/NAME--->

A Flask-based implementation of an OAuth2 Authorisation Server
based on [RFC 6749](https://tools.ietf.org/html/rfc6749) that produces
access tokens in the form of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519)

## Installation

### Requirements

*   Linux (untested on Windows and Mac)
*   Python 2.7 or 3.3+
*   Python Pip

### Steps

```bash
# Install Python setuptools
$ pip install setuptools

# Install the library
$ sudo python setup.py install
```

## Usage

### Getting Started

Please Check the `README.md` in the `oauth2_server` directory for more in-depth instructions on starting the OAuth2 Server

For information regarding building, testing and packaging this repo, please refer to the [Python Templating Library(https://github.com/bbc/rd-apmm-python-lib-template) for more information.

### Basic Usage

```bash
cd oauth2_server
python security_service
```

You can navigate to `http://127.0.0.1:4999/` to find the Login/Signup page of the authorization server in order to perform any admin tasks

## Requirements

* six
* nmoscommon
* Flask
* Flask-SQLAlchemy
* Authlib>=1.1
* Flask-Cors
* requests
* gevent
