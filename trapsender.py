#!/usr/bin/python
# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>

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

sleeptime = 5
microsleep = 0.1
endafter = 0
finishat = time.time() + endafter
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

    trapPDU = snmpClient.createTrap( varbindlist )
#    print('pdu: %s' % trapPDU)

## Send to SNMP trap port.
    snmpClient.snmpTrap( ('localhost', 162), trapPDU )

    if finishat > 0 and lasttime > finishat:
        sys.exit(0)

# Main bits

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# create an snmpmanager
myClient = v2.SNMP( ('localhost', 8888), whenDone )

myClient.run()
