#!/usr/bin/env python
# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (C) 2003 Unicity Pty Ltd <libsnmp@unicity.com.au>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from distutils.core import setup

import time

version_major = 1
version_minor = 0
version_build = 1
version_devel=''
#version_devel='-dev-' + time.strftime('%Y-%m-%d-%H%M')

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
               'snmpset.py',
               'traplistener.py', 
               'trapsender.py',
               ],
    )
