#!/usr/bin/env python
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>

import getopt
import sys

from libsnmp import v2


def checkResponse(snmpClient, msg):
    """ Quick and dirty print of what the message contains
    """
    pdu = msg.data
    # We want to log traps in the following format:
    # fromaddr, genericTrapNum, genericTrapEnumValue,
    frontbit = ",".join([
        str(pdu.enterprise),
        str(pdu.agentAddr),
        str(pdu.genericTrap.value),
        pdu.genericTrap.enum(),
        str(pdu.specificTrap),
        str(pdu.timestamp.value),
    ])

    print(frontbit)

    for varbind in pdu.varBindList:
        endbit = "%s,%s" % (varbind.objectID, varbind.objectValue)
        print("  %s" % endbit)
        # print ",".join([ frontbit, endbit ])

    # endbit = unwrapVarBinds(pdu.varBindList)


def unwrapVarBinds(varBindList):
    """
    Unwrap the varbinds and return a stringified list
    """
    print('%s' % varBindList)
    #    print '%s' % varBindList[0].objectID
    #    print '%s' % varBindList[0].objectValue
    # print '%s = %s: (%s) %s' % ( varBindList[0].objectID, varBindList[0].objectValue.__class__.__name__, varBindList[0].objectValue, varBindList[0].objectValue )
    return ",".join(["%s,%s" % (varbind.objectID, varbind.objectValue) for varbind in varBindList])


# What to do when we finish
def whenDone(snmpClient):
    sys.exit(0)


# Main bits

# Read command line
options, args = getopt.getopt(sys.argv[1:], '', [])

# Listen on SNMP trap port
myClient = v2.SNMP(('0.0.0.0', 162), trapCallback=checkResponse)
myClient.run()
