#!/usr/bin/env python2.3
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

from libsnmp import v2

def checkResponse(snmpClient, msg):
    """ Quick and dirty print of what the message contains
    """
    pdu = msg.data
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

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# Listen on SNMP trap port
myClient = v2.SNMP( ('localhost', 9999), trapCallback=checkResponse)
myClient.run()
