# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
#
# SNMPv2 stuff from RFC 1902

from .rfc1155 import *

log = logging.getLogger('rfc1902')

## change logging level.. options of:
##
## logging.CRITICAL
## logging.ERROR
## logging.WARN
## logging.INFO
## logging.DEBUG

log.setLevel(logging.INFO)

# Add a new TagNumber for encoding purposes
asnTagNumbers['Counter64'] = 0x06


class Integer32(Integer):
    """ A 32 bit integer
    """
    MINVAL = -2147483648
    MAXVAL = 2147483648


class Counter32(Counter):
    """ A 32 bit counter
    """
    pass


class Guage32(Guage):
    """ A 32 bit Guage
    """
    pass


class Counter64(Counter):
    """ A 64 bit counter
    """
    MINVAL = 0
    MAXVAL = 18446744073709551615

    asnTagClass = asnTagNumbers['Counter64']


class OctetString(OctetString):
    """ An SNMP v2 OctetString must be between
        0 and 65535 bytes in length
    """

    def __init__(self, value=''):
        if len(value) > 65535:
            raise ValueError('OctetString must be shorter than 65535 bytes')

        OctetString.__init__(self, value)


## Modify tag decode lookup table to use SNMPv2 classes
## instead of the old SNMPv1 classes. Little actual difference
## apart from the class names.
tagDecodeDict[0x02] = Integer32
tagDecodeDict[0x41] = Counter32
tagDecodeDict[0x42] = Guage32
tagDecodeDict[0x46] = Counter64
