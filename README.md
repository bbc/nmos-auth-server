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
*   Python 3.x
*   Python Pip3

### Python3 Requirements

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

Due to the installation needing to install files into system directories (`/var/nmosauth` for system files and `/usr/bin` for executable files) the `--no-binary` flag must be set in order to pull the source distribution from PyPi and not a Wheel (built) distribution.
To install from pip:

```bash
# Install From Pip
$ sudo pip3 install nmos-auth --no-binary nmos-auth
```

For pip3 installations from source:

```bash
# Change to top-level directory
$ cd nmos-auth-server

# Install via pip locally
$ sudo pip3 install . --no-binary nmos-auth
```

For basic setuptools installations:

```bash
# Install Python setuptools
$ sudo pip3 install setuptools

# Install the package
$ cd nmos-auth-server
$ sudo python3 setup.py install
```

### Testing

Testing of the package can be achieved using tox:
```bash
# Install tox
sudo pip3 install tox

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

**NOTE WHEN INSTALLING VIA DEBIAN PACKAGE**: The version of cryptography and pyOpenSSL on the Ubuntu Xenial mirrors are out-of-date. Please install both Cryptography and PyOpenSSL via Pip for compatible versions.


## Usage

### Basic Usage

For pure Python usage:

```bash
# Execute service file
$ sudo /usr/bin/nmosauth
```
If installing via a Debian package (e.g. using apt-get, dpkg, etc), Systemd service files should be placed in system directories. The service can be restarted using:

```bash
# Run Service using SystemD
sudo systemctl restart python3-nmos-auth
```

### Getting Started

Please Check the [README.md](https://github.com/bbc/nmos-auth-server/tree/master/nmosauth) in the `nmosauth` directory for more in-depth instructions on starting the NMOS Authorisation Server and registering a client.

**You can now navigate to `http://127.0.0.1:4999/x-nmos/auth/v1.0/home/` to find the Home Page of the authorization server** in order to perform any admin tasks, such as registering users and clients.
