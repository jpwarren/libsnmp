# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# This file contains all the base types for SNMP with the abstract
# ASN1 stuff removed and a 'hardcoded' definition used instead.
# This means we don't use an abstract ASN.1 library to figure out
# what stuff is, which is faster for something that is a dedicated
# application of ASN.1, like SNMP.
#
# This file is designed to be a drop in replacement for pysnmp code

from string import split

import util
import debug
import logging

import array

log = logging.getLogger('Asn1Object')

##
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
    'IPAdrress':        0x00,
    'Counter':          0x01,
    'Guage':            0x02,
    'TimeTicks':        0x03,
    'Opaque':           0x04,
}


class Asn1Object:
    """ Base class for all Asn1Objects
        This is only intended to support a specific subset
        of ASN1 stuff as defined by the RFCs to keep things
        as simple as possible.
    """

    # The asnTag is a number used with BER to 
    # encode/decode the object
    asnTagNumber = None
    asnTagClass = asnTagClasses['UNIVERSAL']
    asnTagFormat = asnTagFormats['PRIMITIVE']

    value = None

    def __init__(self):
        pass

    def encode(self):
        """ encode() this Asn1Object using BER 
        """
        result = ''

        result += self.encodeIdentifier()
        contents = self.encodeContents()

        # What we do for lengths depends on whether this is
        # a definite or indefinite object.
        # Assuming definite objects for the moment.
        result += self.encodeLength(len(contents))
        result += contents
        return result

    def decode(self, stream):
        """ decode() an octet stream into a sequence of Asn1Objects
            This method should be overridden by subclasses to define
            how to decode one of themselves from a fixed length
            stream. 
            This general case method looks at the identifier at the
            beginning of a stream of octets and uses the appropriate
            decode() method of that known object.
            Attempts to decode() an unknown object type result in an
            error.
        """
        objects = []
        while len(stream) > 0:

            n = 0
            try:
                tag = ord(stream[0])
                if __debug__: log.debug('tag: 0x%02x' % tag)
                n += 1

                ##
                ## Consider the rare case of multi-byte tags.
                ##

                if tag & 0x1f == 0x1f:
                    if __debug__: log.info('Multi-octet ID encoding detected')
                    subid = ord(stream[n])
                    while subid & 0x80:
                        n += 1
                        (tag, subid) = (tag<<8) | subid, ord(stream[n])
                        pass

                    if __debug__: log.info(' multibyte tag: 0x02x' % tag)
                    pass
                stream = stream[n:]
                pass
            except:
                raise

            # Now that we know what the tag is, we have to figure
            # out how long this object is
            n = 0
            try:
                length = ord(stream[0])
                if length & 0x80:
                    n = length & 0x7f
                    length = 0
                    for i in range(n):
                        length = (length << 8) | ord(stream[i+1])

                stream = stream[n+1:]

            except IndexError:
                raise DecodeError('Encoding has no length octet: %s [%s]' % (className, objectData) )

            # Now we know the type and length of the encoded
            # octet, so we pass those octets to the specific
            # deciding method for the object type.
            objectData = stream[:length]
            stream = stream[length:]

            # Lookup the classname in the decoding dictionary
            try:
                classType = tagDecodeDict[tag]
            except KeyError:
                raise ValueError('Unknown ASN.1 Type %d' % (tag) )

            decoder = classType()

            log.debug('decoding a %s...' % decoder)

            objects.append( decoder.decodeContents(objectData) )

            if __debug__:
                if __debug__: log.debug('contents: %s' % objects)
                for item in objects:
                    if __debug__: log.debug('  item: %s' % item)
                    pass
                pass

            pass

        return objects

    def encodeContents(self):
        """ encodeContents should be overridden by subclasses
            to encode the contents of a particular type
        """
        raise NotImplementedError

    def encodeIdentifier(self):
        """ encodeIdentifier() returns encoded identifier octets
            for this object.
            Section 6.3 of ITU-T-X.209
        """
        result = ''

        if self.asnTagNumber <= 30:
            result += chr(self.asnTagClass | self.asnTagFormat | self.asnTagNumber)

        else:
            # encode each number of the asnTagNumber from 31 upwards
            # as a sequence of 7-bit numbers with bit 8 set to 1
            # for all but the last octet. Bit 8 set to 0 signifies
            # the last octet of the Identifier octets

            # encode the first octet
            result += self.asnTagClass | self.asnTagFormat | 0x1f

            # encode each subsequent octet
            integer = self.asnTagNumber
            while integer != -1:
                (integer, result) = integer>>8, result + chr(integer & 0xff)
                pass
            pass
        return result

    def encodeLength(self, length, isDefinite=None):
        """ encodeLength() takes the length of the contents and
            produces the encoding for that length.
            Section 6.3 of ITU-T-X.209
        """
        result = ''
        # Short form
        if length < 127:
            result += chr( length & 0xff )

        # Long form
        # Octet one is the number of octets used to encode the length
        # It has bit 8 set to 1 and the remaining 7 bits are used to
        # encode the number of octets used to encode the length
        # Each subsequent octet uses all 8 bits to encode the length

        else:
            if __debug__: log.debug('Long length encoding required for length of %d' % length)
            numOctets = 0
            while length > 0:
                (length, result) = length>>8, chr(length & 0xff) + result
                numOctets += 1

            # Add a 1 to the front of the octet
            if __debug__: log.debug('long length encoding of: %d octets' % numOctets)
            numOctets = numOctets | 0x80
            result = chr(numOctets & 0xff) + result

        return result

    def encodeEndOfContents(self):
        return '\000\000'

class Integer(Asn1Object):
    """ An ASN.1 Integer type
    """
    asnTagNumber = asnTagNumbers['Integer']
    MAXVAL = 21344432L
    MINVAL = -21344432L

    def __init__(self, value=0L):
        Asn1Object.__init__(self)
        if not self.MINVAL <= value <= self.MAXVAL:
            if __debug__: log.debug('minval: %d' % self.MINVAL)
            if __debug__: log.debug('maxval: %d' % self.MAXVAL)
            raise ValueError('Integer value of %d is out of bounds' % value)

        self.value = value

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
        result = ''

        integer = self.value
        if __debug__: log.debug('Encoding Integer %d' % integer )
        if integer == 0:
            result = '\000'

        elif integer == -1:
            result = '\377'

        elif integer > 0:
            while integer != 0:
                integer, result = integer>>8, chr(integer & 0xff) + result
                pass

            if ord(result[0]) & 0x80:
                result = chr(0x00) + result
                pass
            pass

        else:
            while integer != -1:
                integer, result = integer>>8, chr(integer & 0xff) + result

            if ord(result[0]) & 0x80 != 0x80:
                result = chr(0x00) + result


        if __debug__: log.debug('Encoded Integer as: %s' % util.octetsToHex(result) )

        return result

    def decodeContents(self, stream):
        """ Decode some input octet stream into a signed ASN.1 integer
        """
        ##
        ## This method wins because it's consistently the fastest
        ##

        if __debug__: log.debug('Decoding %s' % util.octetsToHex(stream) )
        self.value = 0
        byte = ord(stream[0])
        if (byte & 0x80) == 0x80:
            negbit = 0x80L
            self.value = byte & 0x7f

            for i in range(len(stream)-1):
                byte = ord(stream[i+1])
                negbit <<= 8
                self.value = (self.value << 8) | byte

            self.value = self.value - negbit

        else:
            self.value = byte
            for i in range(len(stream)-1):
                byte = ord(stream[i+1])
                self.value = (self.value<<8) | byte

        if __debug__: log.debug('decoded as: %d' % self.value)

        return self

    def decodeTwosInteger1(self, stream):
        """ One algorithm for decoding twos complement Integers
        """
        ##
        ## Original pysnmp algorithm
        ##
        bytes = map(ord, stream)
        if bytes[0] & 0x80:
            bytes.insert(0, -1L)
        result = reduce(lambda x,y: x<<8 | y, bytes, 0L)

        return result

    def decodeTwosInteger2(self, stream):
        """ A second algorithm for decoding twos complement Integers
            Coded from scratch by jpw
        """
        val = 0
        byte = ord(stream[0])
        if (byte & 0x80) == 0x80:
            negbit = 0x80L
            val = byte & 0x7f

            for i in range(len(stream)-1):
                byte = ord(stream[i+1])
                negbit <<= 8
                val = (val << 8) | byte

            val = val - negbit

        else:
            val = byte
            for i in range(len(stream)-1):
                byte = ord(stream[i+1])
                val = (val<<8) | byte

        return val

    def decodeTwosInteger3(self, stream):
        """ A third algorithm for decoding twos complement Integers
            Coded from scratch by jpw
        """
        val = 0
        bytes = map(ord, stream)

        if bytes[0] & 0x80:
            bytes[0] = bytes[0] & 0x7f      # invert bit 8
            negbit = 0x80L
            for i in bytes:
                negbit <<= 8
                val = (val << 8) | i
            val = val - (negbit >> 8)

        else:
            for i in bytes:
                val = (val << 8) | i

        return val

class OctetString(Asn1Object):
    """ An ASN.1 Octet String type
    """
    asnTagNumber = asnTagNumbers['OctetString']

    def __init__(self, value=''):
        Asn1Object.__init__(self)
        self.value = value

    def __str__(self):
        return self.value

    def encodeContents(self):
        """ An OctetString is already encoded. Whee!
        """
        return self.value

    def decodeContents(self, stream):
        """ An OctetString is already decoded. Whee!
        """
        return OctetString(stream)

    def __hex__(self):
        result = ''
        for i in range(len(self.value)):
            result += '%.2x' % ord(self.value[i])
        return result

    def __oct__(self):
        result = ''
        for i in range(len(self.value)):
            result += '\%.3o' % ord(self.value[i])
        return result

class ObjectID(Asn1Object):
    """ An ASN.1 Object Identifier type
    """
    asnTagNumber = asnTagNumbers['ObjectID']

    def __init__(self, value=None, stringval=None):
        """ value is a list of subids
            stringval is a ObjectID is dotted notation in leading
            dot form, eg: .1.3.6.1.2.1.1.1.0
        """ 
        Asn1Object.__init__(self)

        if stringval:
            vals = split(stringval, '.')
            if vals[0] != '':
                raise ValueError('ObjectID string must be in leading dot form')
            self.value = []
            # ignore the first item due to leading dot form
            for item in vals[1:]:
                val = int(item)
                if val < 0:
                    raise ValueError("SubIDs cannot be negative")
                self.value.append( val )

        elif value:
            self.value = value

    def __str__(self):
        result = ['',]
        if self.value:
            for num in self.value:
                result.append('%d' % num)
        return '.'.join(result)

    def isPrefix(self, objId):
        """ Compares this ObjectID with another ObjectID and
            returns non-None if this ObjectID is a prefix of
            the other one.
        """
        if not isinstance(objId, self.__class__):
            raise NotImplementedError
        return cmp(self.value, objId.value)

    def encodeContents(self):
        """ encode() an objectID into an octet stream
        """
        result = []
        idlist = self.value[:]

        # Do the bit with the first 2 subids
        # section 22.4 of X.209
        idlist.reverse()
        subid1 = (idlist.pop() * 40) + idlist.pop()
        idlist.reverse()
        idlist.insert(0, subid1)

        # encode each subid
        for subid in idlist:
            if subid < 128:
                result.append('%c' % (subid & 0x7f) )

            else:
                res = []
                res.append( '%c' % (subid & 0x7f) )

                subid = subid >> 7
                while subid > 0:
                    res.insert( 0, '%c' % (0x80 | (subid & 0x7f)) )
                    subid = subid >> 7

                result += res

        return ''.join(result)

    def decodeContents(self, stream):
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
            # I haven't bothered putting in the convoluted logic
            # here because the highest likely assignment for
            # the first octet is 83 according to Annex B of X.208
            # Those X.209 does give as an example 2.100.3, which 
            # is kinda stupid.
            # Actually, a lot of the space-saving encodings, like
            # this first octet, are a real PITA later on.
            # So yeah, stuff it, we'll just raise an exception.
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
                val = 0
                val = (val << 7) | (subid & 0x7f)
                while (subid & 0x80) == 0x80:
                    subid = bytes[n]
                    n += 1
                    val = (val << 7) | (subid & 0x7f)
                self.value.append(val)
            else:
                self.value.append(subid)

        return self

class Null(Asn1Object):
    """ An ASN.1 Object Identifier type
    """
    asnTagNumber = asnTagNumbers['Null']

    def __str__(self):
        return '<Null>'

    def encodeContents(self):
        return ''

    def decodeContents(self, stream):
        if len(stream) != 0:
            raise ValueError('Input stream too long for %s' % self.__class__.__name__)

        return Null()

class Sequence(Asn1Object):
    """ A Sequence is basically a list of name, value pairs
        with the name being an object Type and the value being
        an instance of an Asn1Object of that Type.
    """
    asnTagNumber = asnTagNumbers['Sequence']
    asnTagFormat = asnTagFormats['CONSTRUCTED']
    value = []

    def __init__(self, value=[]):
        Asn1Object.__init__(self)
        self.value = value

    def __str__(self):
        result = '['
        res = []
        for item in self.value:
            res.append( '%s' % item )

        result += ', '.join(res)

        result += ']'
        return result

    def __len__(self):
        return len(self.value)

    def __getitem__(self, index):
        return self.value[index]

    # We want to implement some usual sequence stuff for this type
    # such as slices, etc.
    def append(self, val):
        self.value.append(val)

    def encodeContents(self):
        """ To encode a Sequence, we simply encode() each sub-object 
            in turn.
        """
        result = ''
        if __debug__: log.debug('Encoding sequence contents...')
        for elem in self.value:
            result += elem.encode()

        return result

    def decodeContents(self, stream):
        """ decode a sequence of objects
        """
        objectList = self.decode(stream)

        return Sequence(objectList)

class SequenceOf(Sequence):
    """ A SequenceOf is a special kind of sequence
        that places a constraint on the kind of objects
        it can contain.
        It is variable in length.
    """

    def __init__(self, componentType=Asn1Object, value=[]):
        Sequence.__init__(self)
        self.componentType = componentType

        # Add each item in the list to ourselves, which
        # automatically checks each one to ensure it is
        # of the correct type.
        self.value = []
        for item in value:
            self.append(item)

    def append(self, value):
        if not isinstance( value, self.componentType ):
            raise ValueError('%s: cannot contain components of type: %s' % (self.__class__.__name__, value.__class__.__name__) )
        Sequence.append(self, value)

class IPAddress(OctetString):
    """ An IpAddress is a special type of OctetString.
        It represents a 32-bit internet address as an
        OctetString of length 4, in network byte order.
    """

    def __init__(self, value='', stringval=None):
        OctetString.__init__(self, value)
        if value:
            if len(value) != 4:
                raise ValueError('IPAddress must be of length 4')
            pass

        if stringval:
            self.value = ''
            listform = split(stringval, '.')
            if len(listform) != 4:
                raise ValueError('IPAddress must be of length 4')

            for item in listform:
                self.value += chr(int(item))
                pass

    def __str__(self):
        result = []
        for item in self.value:
            result.append( '%d' % ord(item) )
        return '.'.join(result)

class NetworkAddress(IPAddress):
    """ A Network Address is a CHOICE with only one possible
        value: internet
    """
    name = 'internet'

class Counter(Integer):
    """ A counter starts at zero and keeps going to a maximum
        integer value of 2^32-1 where it wraps back to zero.
    """
    MINVAL = 0
    MAXVAL = 4294967295L

    def __add__(self, val):
        """ We only add to a counter, and we check for a wrap condition
        """
        if self.value + val > self.MAXVAL:
            self.value = val - ( self.MAXVAL - self.value )
        else:
            self.value += val

class Guage(Integer):
    """ A Guage is a non negative integer.
        It may increase or decrease.
        It latches at a maximum value.
    """
    MINVAL = 0
    MAXVAL = 4294967295L

    def __add__(self, val):
        """ Add to the Guage, latching at the maximum
        """
        if self.value + val > MAXVAL:
            self.value = MAXVAL
        else:
            self.value += val

    def __sub__(self, val):
        """ Subtract from the Guage, latching at zero
        """
        if self.value - val < self.MINVAL:
            self.value = self.MINVAL
        else:
            self.value -= val

class TimeTicks(Integer):
    """ TimeTicks is the number of hundredths of a second
        since an epoch, specified at object creation time
    """
    asnTagClass = asnTagClasses['APPLICATION']
    asnTagNumber = asnTagNumbers['TimeTicks']
    # Default to unix epoch
    epoch = 'Jan 1 1970'
    MINVAL = 0
    MAXVAL = 4294967295L

    def __init__(self, value=0, epoch=None):
        Integer.__init__(self, value)
        if epoch:
            self.epoch = epoch

#    def __str__(self):
#        """ Format the TimeTicks value into an actual
#            time/date stamp based on the epoch.
#        """

class Opaque(OctetString):
    """ Opaque is a fun type that allows you to pass arbitrary
        ASN.1 encoded stuff in an object. The value is some ASN.1
        syntax encoded using BER which this object encodes as an
        OctetString.
        We don't do any decoding of this object because we don't
        have to, and that makes this all much quicker.
    """

class DecodeError(Exception):
    def __init__(self, args=None):
        self.args = args

# Lookup table for object decoding
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
