#!/usr/bin/env python
# Copyright (c) Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved

# 	$Id$	

from distutils.core import setup

import time

version_major = 0
version_minor = 0
version_build = 1
version_devel=''
version_devel='-dev-' + time.strftime('%Y-%m-%d-%H%M')

version='%d.%d.%d%s' % (version_major, version_minor, version_build, version_devel)

setup(
    name='libsnmp',
    version=version,
    description='An SNMP library',
    author='Justin Warren',
    author_email='daedalus@eigenmagic.com',
    license='Proprietary',
    url='http://www.unicity.com.au/',
    packages=['libsnmp'],
    package_dir = { '':'lib'},
    
    scripts = ['snmpget.py', 
               'snmpwalk.py', 
               'traplistener.py', 
               'trapsender.py',
               ],
    )
