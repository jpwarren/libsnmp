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
# This file contains all the base types for SNMP with the abstract
# ASN1 stuff removed and a 'hardcoded' definition used instead.  This
# means we don't use an abstract ASN.1 library to figure out what
# stuff is, which is faster for something that is a dedicated
# application of ASN.1, like SNMP.

# I've included here all the basic SNMPv1 types, since they are used
# by SNMPv2 and v3.

import util
import debug
import logging
import types

log = logging.getLogger('Asn1Object')

## change logging level.. options of:
##
## logging.CRITICAL
## logging.ERROR
## logging.WARN
## logging.INFO
## logging.DEBUG
##
log.setLevel(logging.INFO)

asnTagClasses = {
    'UNIVERSAL':    0x00,
    'APPLICATION':  0x40,
    'CONTEXT':      0x80,
    'PRIVATE':      0xC0
}

asnTagFormats = {
    'PRIMITIVE':    0x00,
    'CONSTRUCTED':  0x20
}

asnTagNumbers = {
    
    'Integer':      0x02,
    'OctetString':  0x04,
    'Null':         0x05,
    'ObjectID':     0x06,
    'Sequence':     0x10,
    
    # Application types
    
    'IPAddress':        0x00,
    'Counter':          0x01,
    'Guage':            0x02,
    'TimeTicks':        0x03,
    'Opaque':           0x04,
}


class Asn1Object:

    """Base class for all Asn1Objects This is only intended to
    support a specific subset of ASN1 stuff as defined by the RFCs to
    keep things as simple as possible."""
    
    ##
    ## The asnTag is a number used with BER to encode/decode the
    ## object.
    ##
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = None
    
    value = None
    
    def __init__(self):
        return
    
    def encode(self):
        
        """ encode() this Asn1Object using BER"""
        
        contents = self.encodeContents()
        
        resultlist = []
        resultlist.append(self.encodeIdentifier())
        resultlist.append(self.encodeLength(len(contents)))
        resultlist.append(contents)
        
        result = ''.join(resultlist)
        
        return result
    
    ##
    ##
    def decodeTag(self, stream):

        """Decode a BER tag field, returning the tag and the remainder
        of the stream"""

        tag = ord(stream[0])
        n = 1
        if tag & 0x1F == 0x1F:
            
            ## A large tag is encoded using concatenated 7-bit values
            ## over the following octets, ignoring the initial 5 bits
            ## in the first octet.  The 8th bit represents a
            ## follow-on.
            
            tag = 0
            while 1:
                byte = ord(stream[n])
                tag = (tag << 7) | (byte & 0x7F)
                n += 1
                if not byte & 0x80: break
                pass
            pass

        return tag, stream[n:]
    
    ##
    ##
    def decodeLength(self, stream):
        
        """Decode a BER length field, returing the length and the
        remainder of the stream"""
        
        length = ord(stream[0])
        n = 1
        if length & 0x80:
            
            ## Multi-Octet length encoding.  The first octet
            ## represents the run-length (the number of octets used to
            ## build the length)
            
            run = length & 0x7F
            length = 0
            for i in xrange(run):
                length = (length << 8) | ord(stream[n])
                n += 1
                pass
            pass
        return length, stream[n:]
    
    ##
    ##
    def decode(self, stream):
        
        """decode() an octet stream into a sequence of Asn1Objects
        This method should be overridden by subclasses to define how
        to decode one of themselves from a fixed length stream.  This
        general case method looks at the identifier at the beginning
        of a stream of octets and uses the appropriate decode() method
        of that known object.  Attempts to decode() an unknown object
        type result in an error.  """

        if type(stream) != types.StringType:
            raise TypeError('stream should be of type StringType, not %s' % type(stream) )
        
        objects = []
        while len(stream) > 0:
            
            (tag, stream) = self.decodeTag(stream)
            (length, stream) = self.decodeLength(stream)

            objectData = stream[:length]
            stream = stream[length:]
            
            try:
                decoder = tagDecodeDict[tag]()
            except KeyError:
                raise ValueError('Unknown ASN.1 Type %d' % (tag) )
            
            objects.append( decoder.decodeContents(objectData) )
            pass
        
        return objects
    
    def encodeContents(self):

        """encodeContents should be overridden by subclasses to encode
        the contents of a particular type"""
        
        raise NotImplementedError
    
    def encodeIdentifier(self):

        """encodeIdentifier() returns encoded identifier octets for
        this object.  Section 6.3 of ITU-T-X.209 """
        
        if self.asnTagNumber < 0x1F:
            result = chr(self.asnTagClass | self.asnTagFormat | self.asnTagNumber)
            
        else:
            
            ## Encode each number of the asnTagNumber from 31 upwards
            ## as a sequence of 7-bit numbers with bit 8 set to 1 for
            ## all but the last octet. Bit 8 set to 0 signifies the
            ## last octet of the Identifier octets
            
            # encode the first octet
            resultlist = []
            resultlist.append(chr(self.asnTagClass | self.asnTagFormat | 0x1F))
            
            # encode each subsequent octet
            integer = self.asnTagNumber
            while integer != -1:
                resultlist.append(chr(integer & 0xFF))
                integer = integer >> 8
                pass
            result = ''.join(resultlist)
            pass
        
        return result

    def encodeLength(self, length):
        
        """encodeLength() takes the length of the contents and
        produces the encoding for that length.  Section 6.3 of
        ITU-T-X.209 """
        
        if length < 127:
            result = chr( length & 0xff )
            pass
        
        else:
            
            # Long form - Octet one is the number of octets used to
            # encode the length It has bit 8 set to 1 and the
            # remaining 7 bits are used to encode the number of octets
            # used to encode the length Each subsequent octet uses all
            # 8 bits to encode the length
            
            if __debug__: log.debug('Long length encoding required for length of %d' % length)

            resultlist = []
            numOctets = 0
            while length > 0:
                resultlist.insert(0, chr(length & 0xff))
                length = length >> 8
                numOctets += 1
                pass
            
            # Add a 1 to the front of the octet
            if __debug__: log.debug('long length encoding of: %d octets' % numOctets)
            numOctets = numOctets | 0x80
            resultlist.insert(0, chr(numOctets & 0xff))
            
            result = ''.join(resultlist)
            pass
        
        return result
    
    def encodeEndOfContents(self):
        return '\000\000'
    
    ##
    ## 
    def __eq__(self, other):
        """
        Compare two instance by comparison of their value fields
        only.
        """
        
        return isinstance(other, self.__class__) and self.value == other.value
#        return self.value == other.value
    
    ##
    ##
    def __ne__(self, other):
        
        """Compare two objects for inequality"""
        
        return not (self == other)
    pass

class Integer(Asn1Object):
    """An ASN.1 Integer type"""
    
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagNumber = asnTagNumbers['Integer']
    
    MINVAL = -2147483648L
    MAXVAL =  2147483647L
    
    def __init__(self, value=0L):
        Asn1Object.__init__(self)
        if not self.MINVAL <= value <= self.MAXVAL:
            if __debug__: log.debug('minval: %d' % self.MINVAL)
            if __debug__: log.debug('maxval: %d' % self.MAXVAL)
            raise ValueError('Integer value of %d is out of bounds' % value)
        
        self.value = value
        return
    
    def __str__(self):
        return '%d' % self.value

    def __int__(self):
        return int(self.value)

    def __long__(self):
        return self.value

    def __hex__(self):
        return hex(self.value)

    def __oct__(self):
        return oct(self.value)

    def __call__(self):
        """ Return the value of the Integer when referring to it directly
        """
        return self.value

    # Define some handy arithmetic operations
    def __eq__(self, other):
        try:
            if self.value == long(other):
                return True

        except:
            raise

        return False

    def __add__(self, integer):
        """ Add a value
        """
        if not isinstance(integer, self.__class__):
            integer = self.__class__(integer)

        return self.__class__(self.value + integer.value)

    def __sub__(self, integer):
        if not isinstance(value, self.__class__):
            value = self.__class__(value)
        return self.__class__(self.value + integer.value)

    def encodeContents(self):

        ## We handle two special cases otherwise we handle positive
        ## and negative numbers independently
        
        integer = self.value
        
        if integer == 0:
            return '\000'
            
        elif integer == -1:
            return '\377'
        
        elif integer > 0:
            result = []
            while integer != 0:
                result.insert(0, integer & 0xff)
                integer >>= 8
                pass
            
            if result[0] & 0x80:
                result.insert(0, 0)
                pass
            
            return ''.join(map(chr, result))
        
        else:
            result = []
            while integer != -1:
                result.insert(0, integer & 0xff)
                integer >>= 8
                pass
            
            if result[0] & 0x80 != 0x80:
                result.insert(0, 0)
                pass
            
            return ''.join(map(chr, result))
        
        pass
    
    
    def decodeContents(self, stream):
        """ Decode some input octet stream into a signed ASN.1 integer
        """
        ##
        ## This method wins because it's consistently the fastest
        ##
        
        input = map(ord, stream)
        
        if __debug__: log.debug('Decoding %s' % util.octetsToHex(stream) )
        
        self.value = 0L
        byte = input[0]
        if (byte & 0x80) == 0x80:
            negbit = 0x80L
            self.value = byte & 0x7f
            
            for i in xrange(1, len(input)):
                negbit <<= 8
                self.value = (self.value << 8) | input[i]
                pass
            
            self.value = self.value - negbit
            
        else:
            self.value = long(byte)
            for i in xrange(1,len(input)):
                self.value = (self.value << 8) | input[i]
                pass
            pass
        
        if __debug__: log.debug('decoded as: %d' % self.value)
        
        return self
    
    def decodeTwosInteger1(self, stream):
        
        """ One algorithm for decoding twos complement Integers """
        
        ##
        ## Original pysnmp algorithm
        ##
        bytes = map(ord, stream)
        if bytes[0] & 0x80:
            bytes.insert(0, -1L)
            pass
        
        result = reduce(lambda x,y: x<<8 | y, bytes, 0L)
        
        return result
    
    def decodeTwosInteger2(self, stream):
        
        """A second algorithm for decoding twos complement Integers
        Coded from scratch by jpw """
        
        val = 0
        byte = ord(stream[0])
        if (byte & 0x80) == 0x80:
            negbit = 0x80L
            val = byte & 0x7f

            for i in range(len(stream)-1):
                byte = ord(stream[i+1])
                negbit <<= 8
                val = (val << 8) | byte
                pass
            
            val = val - negbit
            
        else:
            val = byte
            for i in range(len(stream)-1):
                byte = ord(stream[i+1])
                val = (val<<8) | byte
                pass
            pass
        return val
    
    def decodeTwosInteger3(self, stream):
        
        """ A third algorithm for decoding twos complement Integers
        Coded from scratch by jpw """
        
        val = 0
        bytes = map(ord, stream)

        if bytes[0] & 0x80:
            bytes[0] = bytes[0] & 0x7f      # invert bit 8
            negbit = 0x80L
            for i in bytes:
                negbit <<= 8
                val = (val << 8) | i
                pass
            val = val - (negbit >> 8)
            
        else:
            for i in bytes:
                val = (val << 8) | i
                pass
            pass
        
        return val

    pass

class OctetString(Asn1Object):
    
    """An ASN.1 Octet String type"""
    
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagNumber = asnTagNumbers['OctetString']
    
    def __init__(self, value=''):
        Asn1Object.__init__(self)
        self.value = value
        return
    
    def __str__(self):
        return self.value
    
    def encodeContents(self):
        
        """An OctetString is already encoded. Whee!"""
        
        return self.value
    
    def decodeContents(self, stream):
        
        """An OctetString is already decoded. Whee!  """
        
        self.value = stream
        return self
    
    def __hex__(self):
        
        return ''.join( [ '%.2X' % ord(x) for x in self.value ] )
    
    def __oct__(self):
        
        return ''.join( [ '%3o' % ord(x) for x in self.value ] )

    pass


class ObjectID(Asn1Object):
    
    """An ASN.1 Object Identifier type """
    
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = asnTagNumbers['ObjectID']
    
    def __init__(self, value=None):
        
        """Create an ObjectID - value is a list of subids as a string
        or list"""
        
        Asn1Object.__init__(self)
        
        if type(value) == types.StringType:
            
            value = value.lstrip('.')
            subidlist = value.split('.')
            self.value = []
            
            for subid in subidlist:
                number = int(subid)
                if number < 0 or number > 0x7FFFFFFF:
                    raise ValueError("SubID our of range")
                self.value.append(number)
                pass
            pass
            
        elif type(value) == types.ListType or type(value) == types.NoneType:
            self.value = value
            
        elif type(value) == types.TupleType:
            self.value = list(value)
            
        else:
            raise TypeError('unknown type passed as OID')
        
        return
    
    def __str__(self):

        if self.value is not None:
            return '.'.join( [str(x) for x in self.value] )
        else:
            return ''
        pass
    
    def __len__(self):
        
        """Return the length of the value field"""
        
        if self.value is None:
            return 0
        else:
            return len(self.value)
        pass
    
    def isPrefixOf(self, other):

        """Compares this ObjectID with another ObjectID and returns
        non-None if this ObjectID is a prefix of the other one."""
        
        if not isinstance(other, self.__class__):
            raise TypeError('wrong type in comparison')
        if len(other) < len(self):
            return False
        for i in range(len(self)):
            if self.value[i] != other.value[i]:
                return False
            pass
        return True
    
    def encodeContents(self):
        
        """encode() an objectID into an octet stream """
        
        result = []
        idlist = self.value[:]
        
        # Do the bit with the first 2 subids
        # section 22.4 of X.209
        idlist.reverse()
        subid1 = (idlist.pop() * 40) + idlist.pop()
        idlist.reverse()
        idlist.insert(0, subid1)
        
        for subid in idlist:
            if subid < 128:
                result.append(chr(subid & 0x7f))
            else:
                position = len(result)
                result.append(chr(subid & 0x7f))
                
                subid = subid >> 7
                while subid > 0:
                    result.insert(position, chr(0x80 | (subid & 0x7f)))
                    subid = subid >> 7
                    pass
                pass
            pass
        
        return ''.join(result)
    
    ##
    ##
    def decodeContents(self, stream):
        
        """decode() a stream into an ObjectID()"""
        
        self.value = []
        
        bytes = map(ord, stream)
        
        if len(stream) == 0:
            raise ValueError('stream of zero length in %s' % self.__class__.__name__)
        
        ##
        ## Do the funky decode of the first octet
        ##

        if bytes[0] < 128:
            self.value.append( int(bytes[0] / 40) )
            self.value.append( int(bytes[0] % 40) )

        else:
            
            ## I haven't bothered putting in the convoluted logic here
            ## because the highest likely assignment for the first
            ## octet is 83 according to Annex B of X.208 Those X.209
            ## does give as an example 2.100.3, which is kinda stupid.
            ## Actually, a lot of the space-saving encodings, like
            ## this first octet, are a real PITA later on.  So yeah,
            ## stuff it, we'll just raise an exception.
            
            raise NotImplementedError('First octet is > 128! Unsupported oid detected')
        
        ##
        ## Decode the rest of the octets
        ##
        
        n = 1
        
        while n < len(bytes):
            subid = bytes[n]
            n += 1
            ##
            ## If bit 8 is not set, this is the last octet of this subid
            ## If bit 8 is set, the subid spans this octet and the ones
            ## afterwards, up until bit 8 isn't set.
            ##
            if subid & 0x80 == 0x80:
                val = subid & 0x7f
                while (subid & 0x80) == 0x80:
                    subid = bytes[n]
                    n += 1
                    val = (val << 7) | (subid & 0x7f)
                    pass
                self.value.append(val)
            else:
                self.value.append(subid)
                pass
            pass
        
        return self
    pass

class Null(Asn1Object):
    
    """An ASN.1 Object Identifier type"""
    
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = asnTagNumbers['Null']
    
    def __str__(self):
        return '<Null>'
    
    def encodeContents(self):
        return ''
    
    def decodeContents(self, stream):
        if len(stream) != 0:
            raise ValueError('Input stream too long for %s' % self.__class__.__name__)
        return self
    pass

##
##
class Sequence(Asn1Object):
    
    """A Sequence is basically a list of name, value pairs with the
    name being an object Type and the value being an instance of an
    Asn1Object of that Type."""
    
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagFormat = asnTagFormats['CONSTRUCTED']
    asnTagNumber = asnTagNumbers['Sequence']
    
    value = []
    
    def __init__(self, value=[]):
        Asn1Object.__init__(self)
        self.value = value
        return
    
    def __str__(self):
        result = '['
        res = []
        for item in self.value:
            res.append( '%s' % item )
            pass
        
        result += ', '.join(res)
        
        result += ']'
        return result
    
    def __len__(self):
        return len(self.value)
    
    def __getitem__(self, index):
        return self.value[index]
    
    ## We want to implement some usual sequence stuff for this type
    ## such as slices, etc.
    
    def append(self, val):
        self.value.append(val)
        
    def encodeContents(self):

        """ To encode a Sequence, we simply encode() each sub-object
        in turn."""
        
        if __debug__: log.debug('Encoding sequence contents...')
        resultlist = []
        for elem in self.value:
            resultlist.append(elem.encode())
            pass
        
        result = ''.join(resultlist)
        
        return result
    
    def decodeContents(self, stream):
        
        """decode a sequence of objects"""
        
        objectList = self.decode(stream)

        self.value = objectList
        #return Sequence(objectList)
        return self
    pass

class SequenceOf(Sequence):
    
    """A SequenceOf is a special kind of sequence that places a
    constraint on the kind of objects it can contain.  It is variable
    in length."""
    
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagFormat = asnTagFormats['CONSTRUCTED']
    asnTagNumber = asnTagNumbers['Sequence']
    
    def __init__(self, componentType=Asn1Object, value=[]):
        Sequence.__init__(self)
        self.componentType = componentType
        
        ## Add each item in the list to ourselves, which automatically
        ## checks each one to ensure it is of the correct type.
        
        self.value = []
        for item in value:
            self.append(item)
            pass
        return
    
    def append(self, value):
        if not isinstance( value, self.componentType ):
            raise ValueError('%s: cannot contain components of type: %s' % (self.__class__.__name__, value.__class__.__name__) )
        Sequence.append(self, value)
        return
    pass

class IPAddress(OctetString):

    """An IpAddress is a special type of OctetString.  It represents a
    32-bit internet address as an OctetString of length 4, in network
    byte order.  """
    
    asnTagClass = asnTagClasses['APPLICATION']    
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = asnTagNumbers['IPAddress']
    
    def __init__(self, value=None):
        OctetString.__init__(self, value)
        
        if type(value) == types.StringType:
            self.value = ''
            listform = value.split('.')
            
            if len(listform) != 4:
                raise ValueError('IPAddress must be of length 4')
            
            for item in listform:
                self.value += chr(int(item))
                pass
            pass
        elif type(value) == types.ListType:
            if len(value) != 4:
                raise ValueError('IPAddress must be of length 4')
            pass
        else:
            self.value = ''
            pass
        return
    
    def decodeContents(self, stream):
        
        """An IPAddress is already decoded. Whee!"""
        
        self.value = stream
        return self
    
    def __str__(self):
        result = []
        for item in self.value:
            result.append( '%d' % ord(item) )
            pass
        return '.'.join(result)
    pass

class NetworkAddress(IPAddress):
    
    """ A Network Address is a CHOICE with only one possible value:
        internet
    """
    
    name = 'internet'
    pass

class Counter(Integer):

    """ A counter starts at zero and keeps going to a maximum integer
        value of 2^32-1 where it wraps back to zero.
    """
    
    asnTagClass = asnTagClasses['APPLICATION']
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = asnTagNumbers['Counter']
    
    MINVAL = 0L
    MAXVAL = 4294967295L
    
    def __add__(self, val):
        
        """ We only add to a counter, and we check for a wrap
            condition.
        """
        
        if self.value + val > self.MAXVAL:
            self.value = val - ( self.MAXVAL - self.value )
        else:
            self.value += val
            pass
        return
    
    def decodeContents(self, stream):
        
        result = Integer.decodeContents(self, stream)
        
        ## Some agents encode Counters incorrectly (hello Solaris) as
        ## a negative number.  I'm assuming most SNMP libraries don't
        ## notice the problem because the are written in C and cast
        ## the result to an unsigned int - problem solved (if
        ## accidentally).  This ugly hack on their behalf flips the
        ## value over to the positive world.
        
        if self.value < 0:
            self.value += 0x100000000L
            pass
        return self
    
    pass

class Guage(Integer):

    """ A Guage is a non negative integer.  It may increase or
        decrease. It latches at a maximum value.
    """
    
    asnTagClass = asnTagClasses['APPLICATION']
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = asnTagNumbers['Guage']
    
    MINVAL = 0
    MAXVAL = 4294967295L
    
    def __add__(self, val):
        
        """Add to the Guage, latching at the maximum"""

        if self.value + val > MAXVAL:
            self.value = MAXVAL
        else:
            self.value += val
            pass
        return
    
    def __sub__(self, val):

        """Subtract from the Guage, latching at zerod """
        
        if self.value - val < self.MINVAL:
            self.value = self.MINVAL
        else:
            self.value -= val
            pass
        return
    
    pass

class TimeTicks(Integer):
    
    """ TimeTicks is the number of hundredths of a second since an
        epoch, specified at object creation time
    """
    
    asnTagClass = asnTagClasses['APPLICATION']
    asnTagFormat = asnTagFormats['PRIMITIVE']
    asnTagNumber = asnTagNumbers['TimeTicks']
    
    MINVAL = 0
    MAXVAL = 4294967295L
    
    epoch = None
    
    def __init__(self, value=0, epoch=None):
        Integer.__init__(self, value)
        if epoch:
            self.epoch = epoch
            pass
        return
    pass

#    def __str__(self):
#        """ Format the TimeTicks value into an actual
#            time/date stamp based on the epoch.
#        """

class Opaque(OctetString):

    """Opaque is a fun type that allows you to pass arbitrary ASN.1
    encoded stuff in an object. The value is some ASN.1 syntax encoded
    using BER which this object encodes as an OctetString.  We don't
    do any decoding of this object because we don't have to, and that
    makes this all much quicker.  """

    pass

class DecodeError(Exception):
    def __init__(self, args=None):
        self.args = args
        return
    
    pass

##
## Lookup table for object decoding
##
tagDecodeDict = {
    
    0x02:   Integer,
    0x04:   OctetString,
    0x05:   Null,
    0x06:   ObjectID,
    0x30:   Sequence,
    
    # Application types
    
    0x40:   IPAddress,
    0x41:   Counter,
    0x42:   Guage,
    0x43:   TimeTicks,
    0x44:   Opaque,
    
    }
