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

import rfc1155

import logging
import debug
log = logging.getLogger('rfc1157')

rfc1155.asnTagNumbers = {
    'Get':          0x00,
    'GetNext':      0x01,
    'GetResponse':  0x02,
    'Set':          0x03,
    'Trap':         0x04,
}


class ErrorStatus(rfc1155.Integer):
    """ Error Status
    """
    # define a dictionary of error codes
    errString = { 
        0:      'No Error',
        1:      'Response message would have been too large',
        2:      'There is no such variable name in this MIB',
        3:      'The value given has the wrong type',
        4:      'Object is Read Only',
        5:      'An unknown error occurred'
    }

    errNum = {
        'noError':      0,
        'tooBig':       1,
        'noSuchName':   2,
        'badValue':     3,
        'readOnly':     4,
        'genErr':       5,
    }
    
    def __str__(self):
        """ Return a nicer looking error
        """
        return '%d: %s' % (self.value, self.errString[self.value])

class VarBind(rfc1155.Sequence):
    """ Variable Binding
        This binds a name to an object
    """
    def __init__(self, name=None, value=None):
        if name:
            if not isinstance( name, rfc1155.ObjectID ):
                raise ValueError('name must be an ObjectID')
        if value:
            if not isinstance( value, rfc1155.Asn1Object ):
                raise ValueError('name must be an Asn1Object')

        self.objectID = name
        self.objectValue = value
        rfc1155.Sequence.__init__(self, [ self.objectID, self.objectValue ] )

class VarBindList(rfc1155.SequenceOf):
    """ A Sequence of VarBinds
    """
    def __init__(self, value=[]):
        rfc1155.SequenceOf.__init__(self, VarBind, value)
        return
    pass

class Message(rfc1155.Sequence):
    """ A Message is the base comms type for all SNMP messages
    """

    def __init__(self, version=0, community='public', data=None):
        rfc1155.Sequence.__init__(self)
        self.version = rfc1155.Integer(version)
        self.community = rfc1155.OctetString(community)
        self.data = data

    def __str__(self):
        result = '[%s, ' % self.version
        result += '%s, ' % self.community
        result += '%s]' % self.data
        return result

    def encodeContents(self):
        self.value = []
        self.value.append(self.version)
        self.value.append(self.community)
        self.value.append(self.data)
        return rfc1155.Sequence.encodeContents(self)

    def decode(self, stream):
        objectList = rfc1155.Sequence().decode(stream)

        # Should return a single Sequence
        if len(objectList) != 1:
            raise MessageError('Malformed Message: More than one object decoded.' % len(self.value) )

        # Sequence should contain 3 objects
        if len(objectList[0]) != 3:
            raise MessageError('Malformed Message: Incorrect sequence length %d' % len(self.value) )

        self.version = objectList[0][0]
        self.community = objectList[0][1]
        self.data = objectList[0][2]

        return self

class MessageError(Exception):
    def __init__(self, args=None):
        self.args = args

class RequestPDU(rfc1155.Sequence):
    """ Base class for a non-trap PDU
    """
    asnTagClass = rfc1155.asnTagClasses['CONTEXT']

    def __init__(self, requestID=0, errorStatus=0, errorIndex=0, varBindList=[]):
        """ __init__ allows you to create a new object with no arguments,
            arguments of the class ultimately desired (eg rfc1155.Integer)
            or, to make like easier, it will convert basic strings and ints
            into the ultimately desired objects.
        """
        rfc1155.Sequence.__init__(self)

        self.requestID = rfc1155.Integer(requestID)
        self.errorStatus = ErrorStatus(errorStatus)
        self.errorIndex = rfc1155.Integer(errorIndex)
        self.varBindList = VarBindList(varBindList)

        self.value = [ self.requestID, self.errorStatus, self.errorIndex, self.varBindList ]

    def encodeContents(self):
        self.value = []
        self.value.append(self.requestID)
        self.value.append(self.errorStatus)
        self.value.append(self.errorIndex)
        self.value.append(self.varBindList)
        return rfc1155.Sequence.encodeContents(self)

    def decodeContents(self, stream):
        """ Decode into a GetRequestPDU Object
        """
        objectList = rfc1155.Sequence.decodeContents(self, stream)
        if len(self.value) != 4:
            raise RequestPDUError('Malformed RequestPDU: Incorrect length %d' % len(self.value) )

        # Build things with the correct type
        myVarList = VarBindList()
        for item in objectList[3]:
            myVarList.append( VarBind(item[0], item[1]) )

        return self.__class__( int(objectList[0]), int(objectList[1]), int(objectList[2]), myVarList)
        
class RequestPDUError(Exception):
    def __init__(self, args=None):
        self.args = args

class GetRequestPDU(RequestPDU):
    """ A Get Request PDU
    """
    asnTagNumber = rfc1155.asnTagNumbers['Get']

class GetNextRequestPDU(RequestPDU):
    """ A GetNext Request PDU
    """
    asnTagNumber = rfc1155.asnTagNumbers['GetNext']

class GetResponsePDU(RequestPDU):
    """ A Get Response PDU
    """
    asnTagNumber = rfc1155.asnTagNumbers['GetResponse']

class SetRequestPDU(RequestPDU):
    """ A Set Request PDU
    """
    asnTagNumber = rfc1155.asnTagNumbers['Set']

class GenericTrap(rfc1155.Integer):
    """ Generic Trap type
    """
    genericTraps = {
        0:      'coldStart',
        1:      'warmStart',
        2:      'linkDown',
        3:      'linkUp',
        4:      'authenticationFailure',
        5:      'egpNeighborLoss',
        6:      'enterpriseSpecific',
    }

    def __str__(self):
        """ Return an informative string instead of just a number
        """
        return '%s: %d (%s)' % (self.__class__.__name__, self.value, self.genericTraps[self.value])

class TrapPDU(rfc1155.Sequence):
    """ A Trap PDU
    """
    asnTagClass = rfc1155.asnTagClasses['CONTEXT']
    asnTagNumber = rfc1155.asnTagNumbers['Trap']

    def __init__(self, enterprise=None, agentAddr=None, genericTrap=None, specificTrap=None, timestamp=None, varBindList=None):
        rfc1155.Sequence.__init__(self)

        self.enterprise = enterprise        # rfc1155.ObjectID
        self.agentAddr = agentAddr          # rfc1155.NetworkAddress
        self.genericTrap = genericTrap      # GenericTrap
        self.specificTrap = specificTrap    # rfc1155.Integer
        self.timestamp = timestamp          # rfc1155.TimeTicks
        self.varBindList = varBindList      # VarBindList

        self.value = []
        self.value.append(self.enterprise)
        self.value.append(self.agentAddr)
        self.value.append(self.genericTrap)
        self.value.append(self.specificTrap)
        self.value.append(self.timestamp)
        self.value.append(self.varBindList)

#    def encodeContents(self):
#        return rfc1155.Sequence.encodeContents(self)

    def decodeContents(self, stream):
        """ Decode into a GetRequestPDU Object
        """
        objectList = rfc1155.Sequence.decodeContents(self, stream)

        if len(self.value) != 6:
            raise RequestPDUError('Malformed TrapPDU: Incorrect length %d' % len(self.value) )

        # Build things with the correct type
        myVarList = VarBindList()
        for item in objectList[5]:
            myVarList.append( VarBind(item[0], item[1]) )

        return self.__class__( objectList[0], objectList[1], int(objectList[2]), int(objectList[3]), objectList[4], myVarList)

# Add some new decode types
# The string is evaluated in rfc1155 context
rfc1155.tagDecodeDict[0xa0] = GetRequestPDU
rfc1155.tagDecodeDict[0xa1] = GetNextRequestPDU
rfc1155.tagDecodeDict[0xa2] = GetResponsePDU
rfc1155.tagDecodeDict[0xa3] = SetRequestPDU
rfc1155.tagDecodeDict[0xa4] = TrapPDU
