#!/usr/bin/python
#
# Copyright 2018 British Broadcasting Corporation
#
# This is an internal BBC tool and is not licensed externally
# If you have received a copy of this erroneously then you do
# not have permission to reproduce it.

from __future__ import print_function
from setuptools import setup
import os

# Basic metadata
name = "TEMPLATE"
version = "0.0.0"
description = "A template on which to base future python libraries"
url = 'https://github.com/bbc/rd-apmm-python-lib-template'
author = 'James Weaver'
author_email = 'james.barrett@bbc.co.uk'
license = ''
long_description = description


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
    "six"
]

# This is where you list locations for packages not
# available from pip. Each entry must be of the form:
#  <url>#egg=<pkgname>=<version>
# eg. https://github.com/bbc/rd-apmm-python-lib-nmos-common#egg=nmoscommon=0.1.0
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
      scripts=[],
      data_files=[],
      long_description=long_description)
