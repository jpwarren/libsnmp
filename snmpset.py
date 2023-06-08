#!/usr/bin/env python
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>

import getopt

import sys

sys.path.append('lib')

from libsnmp import snmpmanager


def checkResponse(snmpClient, msg):
    """ Quick and dirty print of what the message contains
    """
    pdu = msg.data

    if int(msg.data.errorStatus) != 0:
        print('Error: %s' % msg.data.errorStatus)
    else:
        unwrapVarBinds(pdu.varBindList)


def unwrapVarBinds(varBindList):
    """ Display a set of varbinds
    """
    #    print '%s' % varBindList
    #    print '%s' % varBindList[0].objectID
    #    print '%s' % varBindList[0].objectValue
    print('%s = %s: (%s) %s' % (
    varBindList[0].objectID, varBindList[0].objectValue.__class__.__name__, varBindList[0].objectValue,
    varBindList[0].objectValue))


# What to do when we finish
def whenDone(snmpClient):
    sys.exit(0)


# Main bits

# log = logging.getLogger('ping-snmpd')

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# Probably replace with something that assigns a random port
myClient = snmpmanager.snmpManager(whenDone)

# remotesite = ( 'localhost', 161 )
# myClient.snmpGet('.1.3.6.1.2.1.1.1.0', remotesite, checkResponse)
# myClient.snmpGet('.1.3.6.1.2.1.1.3.0', remotesite, checkResponse)

if len(args) != 5:
    print("Usage: snmpset.py <server> <community> <oid> <type> <value>")
    sys.exit(1)
else:
    remotesite = (args[0], 161)
    typeval = myClient.typeSetter(args[3])
    if args[3] == 'i':
        value = int(args[4])
    else:
        value = args[4]

    myClient.snmpSet(args[2], typeval, value, remotesite, checkResponse, community=args[1])

# myClient.snmpGet('.1.3.6.1.2.1.1.4.0', remotesite, checkResponse)

myClient.run()
