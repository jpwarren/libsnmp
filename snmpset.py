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

from libsnmp import snmpmanager

def checkResponse(snmpClient, msg):
    """ Quick and dirty print of what the message contains
    """
    pdu = msg.data

    if int(msg.data.errorStatus) != 0:
        print 'Error: %s' % msg.data.errorStatus
    else:
        unwrapVarBinds(pdu.varBindList)

def unwrapVarBinds(varBindList):
    """ Display a set of varbinds
    """
#    print '%s' % varBindList
#    print '%s' % varBindList[0].objectID
#    print '%s' % varBindList[0].objectValue
    print '%s = %s: (%s) %s' % ( varBindList[0].objectID, varBindList[0].objectValue.__class__.__name__, varBindList[0].objectValue, varBindList[0].objectValue )

# What to do when we finish
def whenDone(snmpClient):
    sys.exit(0)

# Main bits

#log = logging.getLogger('ping-snmpd')

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# Probably replace with something that assigns a random port
myClient = snmpmanager.snmpManager( whenDone )

#remotesite = ( 'localhost', 161 )
#myClient.snmpGet('.1.3.6.1.2.1.1.1.0', remotesite, checkResponse)
#myClient.snmpGet('.1.3.6.1.2.1.1.3.0', remotesite, checkResponse)

if len(args) != 5:
    print "Usage: snmpset.py <server> <community> <oid> <type> <value>"
    sys.exit(1)
else:
    remotesite = ( args[0], 161 )
    typeval = myClient.typeSetter( args[3] )
    if args[3] == 'i':
        value = int(args[4])
    else:
        value = args[4]
    
    myClient.snmpSet(args[2], typeval, value, remotesite, checkResponse, community=args[1])

#myClient.snmpGet('.1.3.6.1.2.1.1.4.0', remotesite, checkResponse)

myClient.run()
