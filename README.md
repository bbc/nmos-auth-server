<!---NAME--->
# AMWA NMOS BCP-003-02 Authorisation Server Implementation
<!---/NAME--->

A Flask-based implementation of an OAuth2 Authorisation Server
based on [AMWA NMOS BCP-003-02](https://amwa-tv.github.io/nmos-api-security/best-practice-authorisation.html) using [RFC 6749](https://tools.ietf.org/html/rfc6749). The API implemented here is a candidate to become the proposed specification AMWA NMOS IS-10.

The server produces access tokens in the form of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519). Dynamic Client Registration is also supported in line with [RFC 7591](https://tools.ietf.org/html/rfc7591).

The core of the implementation uses the [Authlib](https://authlib.org/) Library, and is based on the [Authlib OAuth2 Server Example](https://github.com/authlib/example-oauth2-server).

**Please Check the [README.md](https://github.com/bbc/nmos-auth-server/tree/master/nmosauth) in the `nmosauth` directory for more in-depth instructions on starting the AMWA NMOS Authorisation Server and registering a client.**

## Installation

### System Requirements

*   Linux (untested on Windows and Mac)
*   Python 2.7 and 3.x
*   Python Pip

### Python Requirements
These should be installed automatically as part of the install process.

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

### Python Installation

To install from pip:

```bash
# Install From Pip
$ sudo pip install nmos-auth
```

For pip installations from source:

```bash
# Change to top-level directory
$ cd nmos-auth-server

# Install via pip locally
$ sudo pip install .
```

For basic setuptools installations:

```bash
# Install Python setuptools
$ pip install setuptools

# Install the package
$ cd nmos-auth-server
$ sudo python setup.py install
```

### Testing

Testing of the package can be achieved using tox:
```bash
# Install tox
pip install tox

# Run tests using tox environment for Python3
cd nmos-auth-server
tox -e py3
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
# Execute service file
$ sudo /usr/bin/nmosauth
```
If installing via a Debian package (e.g. using apt-get), Systemd service files should be placed in system directories. The service can be restarted using:

```bash
# Run Service using SystemD
sudo systemctl restart python-nmos-auth
```

### Getting Started

Please Check the [README.md](https://github.com/bbc/nmos-auth-server/tree/master/nmosauth) in the `nmosauth` directory for more in-depth instructions on starting the NMOS Authorisation Server and registering a client.

**You can now navigate to `http://127.0.0.1:4999/x-nmos/auth/v1.0/home/` to find the Home Page of the authorization server** in order to perform any admin tasks, such as registering users and clients.
