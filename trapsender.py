#!/usr/bin/env python2.3
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

import logging
import socket
import select

import getopt

import sys
sys.path.append('lib')
from libsnmp import debug
from libsnmp import util
from libsnmp import rfc1155
from libsnmp import rfc1157

from libsnmp import v2

import time

sleeptime = 1
microsleep = 0.1

lasttime = 0

##
## This is called when the SNMP has nothing else to do
## We sleep for 5 seconds and then send another trap
##
def whenDone(snmpClient):
    global lasttime
    while( time.time() - lasttime < sleeptime):
        time.sleep(microsleep)
    lasttime = time.time()

    varbind = rfc1157.VarBind( rfc1155.ObjectID('.1.3.6.1.4.5.6.7'), rfc1155.OctetString( time.strftime('%a %d %b %Y %H:%M:%S') ) )
#    print 'varbind: %s' % varbind

    varbindlist = rfc1157.VarBindList( [ varbind ] )
#    print 'varbindlist: %s' % varbindlist

    trapPDU = snmpClient.createTrapPDU( varbindlist )
#    print('pdu: %s' % trapPDU)

## Send to SNMP trap port.
    snmpClient.snmpTrap( ('localhost', 9999), trapPDU )

# Main bits

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# create an snmpmanager
myClient = v2.SNMP( ('localhost', 8888), whenDone )

myClient.run()
