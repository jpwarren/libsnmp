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
from libsnmp import debug
from libsnmp import util
from libsnmp import rfc1155
from libsnmp import rfc1157

from libsnmp import snmpmanager

def checkResponse(snmpClient, msg):
    """ Quick and dirty print of what the message contains
    """
    pdu = msg.data

    if int(pdu.errorStatus) != 0:
        print 'Error: %s' % pdu.errorStatus
    else:
        unwrapVarBinds(pdu.varBindList)

        myClient.snmpGetNext(pdu.varBindList, remotesite, checkResponse, community=args[1])

def unwrapVarBinds(varBindList):
    """ Display a set of varbinds
    """
#    print '%s' % varBindList
#    print '%s' % varBindList[0].objectID
#    print '%s' % varBindList[0].objectValue.value

    print '%s = %s: %s' % ( varBindList[0].objectID, varBindList[0].objectValue.__class__.__name__, varBindList[0].objectValue )
    if varBindList[0].objectValue.__class__.__name__ == 'OctetString':
        print "   hex: %s" % util.octetsToHex(varBindList[0].objectValue.value)
    
    if varBindList[0].objectValue.__class__.__name__ == 'NoSuchObject':
        log.error("No such object!")
        sys.exit(0)

    if varBindList[0].objectValue.__class__.__name__ == 'EndOfMibView':
        log.info("End of MIB View")
        sys.exit(0)
        
# What to do when we finish
def whenDone(snmpClient):
    sys.exit(0)

# Main bits

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# Probably replace with something that assigns a random port
myClient = snmpmanager.snmpManager( whenDone )

if len(args) != 3:
    print "Usage: snmpget.py <server> <community> <oid>"
    sys.exit(1)
else:
    remotesite = ( args[0], 161 )
    myClient.snmpGet(args[2], remotesite, checkResponse, community=args[1])

myClient.run()
