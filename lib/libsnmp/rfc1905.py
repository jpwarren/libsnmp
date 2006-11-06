# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
#
# SNMPv2 protocol parts

import logging
import debug

import rfc1157
from rfc1902 import *

log = logging.getLogger('rfc1905')

asnTagNumbers['GetBulk'] = 0x05
asnTagNumbers['Inform'] = 0x06
asnTagNumbers['TrapV2'] = 0x07
asnTagNumbers['Report'] = 0x08

max_bindings = 2147483647L

class VarBind(rfc1157.VarBind):
    """ VarBind redefined here to place it in the same namespace
    """
    pass

## We need to add some special types because ucd-snmp uses
## context specific values for the CHOICE within a VarBind
class NoSuchObject(rfc1157.Null):

    def __str__(self):
        return('No Such Object')

class NoSuchInstance(rfc1157.Null):

    def __str__(self):
        return('No Such Instance')

class EndOfMibView(rfc1157.Null):

    def __str__(self):
        return('EndOfMibView')

class VarBindList(rfc1157.VarBindList):
    """ An SNMPv2 VarBindList has a maximum size of max_bindings
    """
    def __init__(self, value=[]):
        if len(value) > max_bindings:
            raise ValueError('A VarBindList must be shorter than %d' % max_bindings)
        rfc1157.VarBindList.__init__(self, value)

class Message(rfc1157.Message):

    def __init__(self, version=1, community='public', data=None):
        rfc1157.Message.__init__(self, version, community, data)

class ErrorStatus(rfc1157.ErrorStatus):
    """ An SNMPv2 Error status
    """
    def __init__(self, value):
        rfc1157.ErrorStatus.__init__(self, value)
        # add to the SNMPv1 error strings
        self.errString[6] = 'Access is not permitted'
        self.errString[7] = 'Type is incorrect'
        self.errString[8] = 'Length is incorrect'
        self.errString[9] = 'Encoding is incorrect'
        self.errString[10] = 'Value is incorrect'
        self.errString[11] = 'No creation'
        self.errString[12] = 'Value is inconsistent'
        self.errString[13] = 'Resourse Unavailable'
        self.errString[14] = 'Commit Failed'
        self.errString[15] = 'Undo Failed'
        self.errString[16] = 'Authorization Error'
        self.errString[17] = 'Not Writable'
        self.errString[18] = 'Inconsistent Name'

        self.errNum[6] = 'noAccess'
        self.errNum[7] = 'wrongType'
        self.errNum[8] = 'wrongLength'
        self.errNum[9] = 'wrongEncoding'
        self.errNum[10] = 'wrongValue'
        self.errNum[11] = 'noCreation'
        self.errNum[12] = 'inconsistentValue'
        self.errNum[13] = 'resourceUnavailable'
        self.errNum[14] = 'commitFailed'
        self.errNum[15] = 'undoFailed'
        self.errNum[16] = 'authorizationError'
        self.errNum[17] = 'notWritable'
        self.errNum[18] = 'inconsistentName'

class PDU(rfc1157.PDU):
    """ SNMPv2 PDUs are very similar to SNMPv1 PDUs
    """
    asnTagClass = asnTagClasses['CONTEXT']

    def __init__(self, requestID=0, errorStatus=0, errorIndex=0, varBindList=[]):
        rfc1157.PDU.__init__(self)

        if errorIndex > max_bindings:
            raise ValueError('errorIndex must be <= %d' % max_bindings)

        self.requestID = Integer32(requestID)
        self.errorStatus = ErrorStatus(errorStatus)
        self.errorIndex = Integer(errorIndex)
        self.varBindList = VarBindList(varBindList)

        self.value = [
            self.requestID,
            self.errorStatus,
            self.errorIndex,
            self.varBindList,
        ]

#    def decodeContents(self, stream):
#        """ Decode into a PDU object
#        """
#        objectList = Sequence.decodeContents(self, stream)
#        if len(self.value) != 4:
#            raise PDUError('Malformed PDU: Incorrect length %d' % len(self.value) )
#
#        # Build things with the correct types
#        for item in objectList[3]:
#            myVarList.append( VarBind(item[0], item[1]) )
#
#        return self.__class__( int(objectList[0]), int(objectList[1]), int(objectList[2]), myVarList)

class BulkPDU(Sequence):
    """ BulkPDU is a new type of PDU specifically for doing GetBulk
        requests in SNMPv2.
    """

    asnTagClass = asnTagClasses['CONTEXT']

    def __init__(self, requestID=0, nonRepeaters=0, maxRepetitions=0, varBindList=[]):
        Sequence.__init__(self)

        if nonRepeaters > max_bindings:
            raise ValueError('nonRepeaters must be <= %d' % max_bindings)
        if maxRepetitions > max_bindings:
            raise ValueError('nonRepeaters must be <= %d' % max_bindings)

        self.requestID = Integer32(requestID)
        self.nonRepeaters = Integer(nonRepeaters)
        self.maxRepetitions = Integer(maxRepetitions)
        self.varBindList = VarBindList(varBindList)

        self.value = [
            self.requestID,
            self.nonRepeaters,
            self.maxRepetitons,
            self.varBindList
        ]

    def decodeContents(self, stream):
        """ Decode into a BulkPDU object
        """
        objectList = Sequence.decodeContents(self, stream)
        if len(self.value) != 4:
            raise PDUError('Malformed BulkPDU: Incorrect length %d' % len(self.value) )

        # Build things with the correct types
        for item in objectList[3]:
            myVarList.append( VarBind(item[0], item[1]) )

        return self.__class__( int(objectList[0]), int(objectList[1]), int(objectList[2]), myVarList)

class Get(PDU):
    """ An SNMPv2 Get Request PDU
    """
    asnTagNumber = asnTagNumbers['Get']

class GetNext(PDU):
    """ An SNMPv2 Get Next Request PDU
    """
    asnTagNumber = asnTagNumbers['GetNext']

class Response(PDU):
    """ An SNMPv2 Response PDU
    """
    asnTagNumber = asnTagNumbers['Response']

class Set(PDU):
    """ An SNMPv2 Set Request PDU
    """
    asnTagNumber = asnTagNumbers['Set']

class GetBulk(BulkPDU):
    """ An SNMPv2 Get Next Request PDU
    """
    asnTagNumber = asnTagNumbers['GetBulk']

class Inform(PDU):
    """ An SNMPv2 Get Next Request PDU
    """
    asnTagNumber = asnTagNumbers['Inform']

class TrapV2(PDU):
    """ An SNMPv2 Trap PDU
    """
    asnTagNumber = asnTagNumbers['TrapV2']

class Report(PDU):
    """ An SNMPv2 Report PDU
    """
    asnTagNumber = asnTagNumbers['Report']

class PDUError(Exception):
    def __init__(self, args=None):
        self.args = args

## Add some new decode types

tagDecodeDict[0xa2] = Response
tagDecodeDict[0xa5] = GetBulk
tagDecodeDict[0xa6] = Inform
tagDecodeDict[0xa7] = TrapV2
tagDecodeDict[0xa8] = Report

## ucd-snmp returns context-specific values at time
tagDecodeDict[0x80] = NoSuchObject
tagDecodeDict[0x81] = NoSuchInstance
tagDecodeDict[0x82] = EndOfMibView
