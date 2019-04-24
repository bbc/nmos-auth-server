<!---NAME--->
# RD-APMM-PYTHON-OAUTH-SECURITY
<!---/NAME--->

A Flask-based implementation of an OAuth2 Authorisation Server
based on [RFC 6749](https://tools.ietf.org/html/rfc6749) that produces
access tokens in the form of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519).

The implementation is based on the [Authlib](https://authlib.org/) Library.

## Installation

### System Requirements

*   Linux (untested on Windows and Mac)
*   Python 2.7
*   Python Pip

### Python

For setuptools installations:

```bash
# Install Python setuptools
$ pip install setuptools

# Install the service
$ sudo python setup.py install
```

### Debian

For use as a Debian package (on Ubuntu/Debian systems):

```bash
make deb
cd dist/
sudo dpkg -i <name of package>.deb
```

**NOTE FOR USE ON R&D NETWORK**: If there is a dependency clash during installation, you may need to install `python-sqlalchemy` using:

`sudo apt-get install python-sqlalchemy=1.0.11+ds1-1ubuntu2`


## Usage

### Basic Usage

For pure Python usage:

```bash
cd auth_server
python -m security_service
```
If installing via a Debian package (e.g. using apt-get), System V service files should be placed in system directories. The service can be restarted using:

`sudo systemctl restart python-nmos-oauth`

### Getting Started

Please Check the [README.md](https://github.com/bbc/rd-apmm-python-oauth/tree/master/nmosoauth) in the `nmosoauth` directory for more in-depth instructions on starting the NMOS OAuth2 Server and registering a client.

For information regarding building, testing and packaging this repo, please refer to the [Python Templating Library](https://github.com/bbc/rd-apmm-python-lib-template) for more information.

You can now navigate to `http://127.0.0.1:4999/x-nmos/auth/v1.0/home/` to find the Home Page of the authorization server in order to perform any admin tasks, such as registering users and clients.

## Requirements

* six
* nmoscommon
* Flask
* sqlalchemy
* Flask-SQLAlchemy
* Authlib>=1.1
* Flask-Cors
* requests
* gevent
* systemd
* pyopenssl
