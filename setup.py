#!/usr/bin/env python
# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>

from distutils.core import setup

import time

version_major = 2
version_minor = 0
version_build = 0
version_devel=''
#version_devel='-dev-' + time.strftime('%Y-%m-%d-%H%M')

version='%d.%d.%d%s' % (version_major, version_minor, version_build, version_devel)

setup(
    name='libsnmp',
    version=version,
    description='A Python SNMP library',
    author='Justin Warren',
    author_email='daedalus@eigenmagic.com',
    license='MIT',
    url='http://www.eigenmagic.com',
    packages=['libsnmp'],
    package_dir = { '':'lib'},
    
##     scripts = ['snmpget.py', 
##                'snmpwalk.py',
##                'snmpset.py',
##                'traplistener.py', 
##                'trapsender.py',
##                ],
    )
