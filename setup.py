#!/usr/bin/python
#
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

from __future__ import print_function
import os
from setuptools import setup
import subprocess
from setuptools.command.develop import develop
from setuptools.command.install import install

from nmosauth.auth_server.constants import NMOSAUTH_DIR

GEN_CERT_FILE = 'gen_cert.py'
GEN_CERT_PATH = os.path.join(NMOSAUTH_DIR, GEN_CERT_FILE)


# Basic metadata
name = "nmos-auth"
version = "1.0.0"
description = "OAuth2 Server Implementation"
url = 'https://github.com/bbc/nmos-auth-server'
author = 'Danny Meloy'
author_email = 'danny.meloy@bbc.co.uk'
license = 'BSD'
long_description = "OAuth2 Server Implementation to produce JWTs for API Access"


def gen_certs():
    try:
        subprocess.call([GEN_CERT_PATH])
    except Exception as e:
        print('Error: {}. Failed to generate certificates.'.format(str(e)))
        print('Please run "{}" in {}'.format(GEN_CERT_FILE, NMOSAUTH_DIR))
        pass


class PostDevelopCommand(develop):
    """Post-installation for development mode."""
    def run(self):
        develop.run(self)
        gen_certs()


class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        gen_certs()


def is_package(path):
    return (
        os.path.isdir(path) and os.path.isfile(os.path.join(path, '__init__.py'))
    )


def find_packages(path, base=""):
    """ Find all packages in path """
    packages = {}
    for item in os.listdir(path):
        dir = os.path.join(path, item)
        if is_package(dir):
            if base:
                module_name = "%(base)s.%(item)s" % vars()
            else:
                module_name = item
            packages[module_name] = dir
            packages.update(find_packages(dir, module_name))
    return packages


packages = find_packages(".")
package_names = packages.keys()

# This is where you list packages which are required
packages_required = [
    "six",
    "flask",
    "sqlalchemy",
    "flask-sqlalchemy",
    "flask-cors",
    "requests",
    "gevent",
    "nmoscommon",
    "pyopenssl",
    "authlib>=0.11"
]

deps_required = []

setup(
    name=name,
    version=version,
    description=description,
    url=url,
    author=author,
    author_email=author_email,
    license=license,
    packages=package_names,
    package_dir=packages,
    install_requires=packages_required,
    include_package_data=True,
    scripts=[],
    package_data={
        'nmosauth': ['auth_server/templates/*', 'auth_server/static/*']
    },
    data_files=[
        ('/usr/bin', ['bin/nmosauth']),
        (NMOSAUTH_DIR, ['nmosauth/certs/{}'.format(GEN_CERT_FILE)])
    ],
    long_description=long_description,
    cmdclass={
        'develop': PostDevelopCommand,
        'install': PostInstallCommand
    }
)
