#!/usr/bin/python
#
# Copyright 2018 British Broadcasting Corporation
#
# This is an internal BBC tool and is not licensed externally
# If you have received a copy of this erroneously then you do
# not have permission to reproduce it.

from __future__ import print_function
import os
from setuptools import setup


# Basic metadata
name = "nmos-oauth"
version = "0.0.0"
description = "OAuth2 Server Implementation"
url = 'https://github.com/bbc/rd-apmm-python-oauth'
author = 'Danny Meloy'
author_email = 'danny.meloy@bbc.co.uk'
license = 'BSD'
long_description = "OAuth Server Implementation to produce JWTs for API Access"


def is_package(path):
    return (
        os.path.isdir(path) and
        os.path.isfile(os.path.join(path, '__init__.py'))
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
    "flask-sqlalchemy<=1.10",
    "flask-cors",
    "requests",
    "gevent",
    "systemd",
    "nmoscommon",
    "authlib>=0.10",
]

deps_required = []

setup(name=name,
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
        'nmosoauth': ['auth_server/templates/*', 'auth_server/static/*']
      },
      data_files=[
        ('/usr/bin', ['bin/nmosoauth']),
      ],
      long_description=long_description,
      )
