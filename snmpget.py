#!/usr/bin/env python2.3
# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# Test basic connectivity to an snmpd

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

from libsnmp import v1

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

def getData():
    (inlist, outlist, errlist) = select.select( [sock], [], [] )
    if inlist:
        data = sock.recv(8096)
    #    log.debug('got data: %s' % util.octetsToHex(data) )
        msg = rfc1157.Message().decode(data)
    #    log.debug('message recvd: %s' % msg)

        checkResponse(msg)

# What to do when we finish
def whenDone(snmpClient):
    sys.exit(0)

# Main bits

#log = logging.getLogger('ping-snmpd')

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# Probably replace with something that assigns a random port
myClient = v1.SNMP( ('localhost', 9999), whenDone )

#remotesite = ( 'localhost', 161 )
#myClient.snmpGet('.1.3.6.1.2.1.1.1.0', remotesite, checkResponse)
#myClient.snmpGet('.1.3.6.1.2.1.1.3.0', remotesite, checkResponse)

if len(args) != 3:
    print "Usage: snmpget.py <server> <community> <oid>"
    sys.exit(1)
else:
    remotesite = ( args[0], 161 )
    myClient.snmpGet(args[2], remotesite, checkResponse, community=args[1])

#myClient.snmpGet('.1.3.6.1.2.1.1.4.0', remotesite, checkResponse)

myClient.run()
