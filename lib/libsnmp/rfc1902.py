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
#
# SNMPv2 stuff from RFC 1902

import util
import debug
import logging
import types

from rfc1155 import *

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
    MINVAL = -2147483648L
    MAXVAL = 2147483648L

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
    MINVAL = 0L
    MAXVAL = 18446744073709551615L

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
