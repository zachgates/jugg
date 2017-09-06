#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import os
import sys

from shutil import rmtree
from setuptools import find_packages, setup, Command


URL = 'https://github.com/zachgates/jugg'
REQUIRED = [
    'pyarchy',
]


main_dir = os.path.abspath(os.path.dirname(__file__))

with io.open(os.path.join(main_dir, 'README.md'), encoding = 'utf-8') as f:
    README = f.read()
    data = README.split('#', 2)[1].strip().split('\n', 2) + ['', '']
    NAME, SHORT_DESCRIPTION, LONG_DESCRIPTION = data[:3]

ABOUT = {}
with open(os.path.join(main_dir, NAME, '__init__.py')) as f:
    exec(f.read(), ABOUT)


class PublishCommand(Command):
    """Support setup.py publish."""

    description = 'Build and publish the package.'
    user_options = []
    
    @staticmethod
    def status(s):
        """Prints things in bold."""
        print('\033[1m{0}\033[0m'.format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status('Removing previous builds…')

            global main_dir
            rmtree(os.path.join(main_dir, 'dist'))
        except FileNotFoundError:
            pass

        self.status('Building Source and Wheel (universal) distribution…')
        os.system('{0} setup.py sdist bdist_wheel --universal'.format(
            sys.executable))

        self.status('Uploading the package to PyPi via Twine…')
        os.system('twine upload dist/*')

        sys.exit()


setup(
    name = NAME,
    version = ABOUT['__version__'],
    description = SHORT_DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    author = ABOUT['__author__'],
    author_email = ABOUT['__email__'],
    url = URL,
    packages = find_packages(exclude = ('tests',)),
    install_requires = REQUIRED,
    include_package_data = True,
    license = ABOUT['__license__'],
    classifiers = [
        'License :: OSI Approved :: %s License' % ABOUT['__license__'],
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    cmdclass = {
        'publish': PublishCommand,
    },
)
