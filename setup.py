#!/usr/bin/python

#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>

from setuptools import setup
#from distutils.core import setup

import time

version_major = 3
version_minor = 0
version_build = 0
version_devel=''
#version_devel='-dev-' + time.strftime('%Y-%m-%d-%H%M')

version='%d.%d.%d%s' % (version_major, version_minor, version_build, version_devel)

setup(
    name='libsnmp',
    version=version,

    packages=['libsnmp'],
    package_dir = { '':'lib'},
    
    scripts = ['snmpget.py',
               'snmpget-v1.py',
               'snmpget-v2.py',
               'snmpset.py',
               'snmpwalk.py',
               'traplistener.py', 
               'trapsender.py',
               ],

    description='A Python SNMP library',
    long_description='A pure Python implementation of the Simple Network Management Protocol',
    author='Justin Warren',
    author_email='daedalus@eigenmagic.com',
    license='MIT',
    url='https://github.com/jpwarren/libsnmp',

    classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Environment :: Other Environment",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Natural Language :: English",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Topic :: Communications",
    "Topic :: Internet",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Monitoring",
    "Topic :: System :: Networking :: Monitoring",
    ],

    )
