# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# Unit tests for the encoder/decoder

import unittest
import logging
import string

import sys
sys.path.append('../lib')

from libsnmp import util
from libsnmp import debug
from libsnmp import rfc1155

# Some integer encodings to check
test_integers = {
    0:          '\000',
    5:          '\005',
    15:         '\017',
    73:         '\111',
    128:        '\000\200',
    -127:        '\201',
    -128:        '\200',
    124787:     '\001\347\163',
    -1:         '\377',
    -267:       '\376\365',
    -5848548:   '\246\302\034'
}

# octetstrings are simple, since they stay as they are
test_octetstrings = [
    'fred',
    'the small frog sat in the well',
    '43 403i 594 5908kjljdfj weljf',

]

test_objectids = {
    '.1.2.4.5.6':                    '\052\004\005\006',
    '.2.3.3':                        '\123\003',
    '.0.2.8.5':                      '\002\010\005',
    '.1.2.65.7.3394.23.5.115.46':    '\052\101\007\232\102\027\005\163\056'
}

test_sequences = {
    '\002\001\016':         [ rfc1155.Integer(14), ],
    '\002\002\006\321':         [ rfc1155.Integer(1745), ],
    '\002\001\077\005\000':         [ rfc1155.Integer(63), rfc1155.Null() ], 
    '\006\006\051\006\005\054\003\005\004\004\142\154\141\150\002\003\001\202\037':         [ rfc1155.ObjectID(stringval='.1.1.6.5.44.3.5'), rfc1155.OctetString('blah'), rfc1155.Integer(98847) ]

}

test_sequenceOf = {
    'blah':  [ rfc1155.Integer, [ rfc1155.Integer(7), rfc1155.Integer(5567), rfc1155.Integer(84743) ] ],

    'fred':  [ rfc1155.ObjectID, [ rfc1155.ObjectID(stringval='.1.2.4.3'), rfc1155.ObjectID(stringval='.1.0.4.6.44') ] ]
}

test_ipaddresses = {
    'blah':     '10.232.8.4',
    'fred':     '255.255.255.0',
    'albert':   '232.66.1.44',
}

test_octets = {
    # A fully encoded integer
    '\002\001\005':         [5, ],
    # Another fully encoded integer
    '\002\003\001\347\163': [124787, ],
    # three integers
    '\002\003\246\302\034\002\003\001\347\163\002\001\337': [-5848548, 124787, -1],

    # a simple octet string
    '\004\036the small frog sat in the well':   ['the small frog sat in the well'],

    # some object IDs
    '\006\002\123\003':                 [ [2, 3, 3], ],
    '\006\004\052\004\005\006':         [ [1, 2, 4, 5, 6], ],
    '\006\011\052\101\007\232\102\027\005\163\056':     [ [1, 2, 65, 7, 3394, 23, 5, 115, 46], ],

    # A Null
    '\005\000':         [ None, ],

}

class EncoderTest(unittest.TestCase):

    def setUp(self):
        self.log = logging.getLogger('EncoderTest')
        self.log.setLevel(logging.DEBUG)

    def tearDown(self):
        logging.shutdown()

    def test_integerEncode(self):
        """ Test encoding of Integer type
        """
        for item in test_integers.keys():
            myobj = rfc1155.Integer(item)
#            self.log.debug('Encoding int: %s' % myobj() )
            octets = myobj.encodeContents()
#            self.log.debug('Got value [length %s]: %s, oct: %s' % ( len(octets), util.octetsToHex(octets), util.octetsToOct(octets)) )
#            self.log.debug('check against handcode: %s [%d] %s' % ( util.octetsToHex(test_integers[item]), len(octets), util.octetsToOct(test_integers[item]) ) )
            self.assertEquals(test_integers[item], octets)

    def test_integerEncodeDecode(self):
        """ Test encode/decode of Integer type
        """
        for item in test_integers.keys():
            myobj = rfc1155.Integer(item)
#            self.log.debug('Encoding int: %s' % myobj() )
            octets = myobj.encodeContents()
#            self.log.debug('Got value [length %s]: %s, oct: %s' % ( len(octets), util.octetsToHex(octets), util.octetsToOct(octets)) )
            object = myobj.decodeContents(octets)
#            self.log.debug('Got value [%s]: %s' % ( object, object.value) )
            self.assertEquals(item, object.value)

    def test_octetStringEncode(self):
        """ Test encode of OctetString type
        """
#        self.log.debug('testing octet string in octal and hex')
        for item in test_octetstrings:
            myobj = rfc1155.OctetString(item)
#            self.log.debug('as hex: %s' % hex(myobj) )
#            self.log.debug('as octal: %s' % oct(myobj) )
            octets = myobj.encodeContents()
            self.assertEquals(item, octets)

    def test_octetStringEncodeDecode(self):
        """ Test encode/decode of OctetString type
        """
        for item in test_octetstrings:
            myobj = rfc1155.OctetString(item)
            octets = myobj.encodeContents()
            object = myobj.decodeContents(octets)
            self.assertEquals(item, object.value)

    def test_objectidEncode(self):
        """ Test encode of ObjectID type
        """
        for item in test_objectids.keys():
            myobj = rfc1155.ObjectID(stringval=item)
            octets = myobj.encodeContents()
#            self.log.debug('Got value [length %s]: %s, oct: %s' % ( len(octets), util.octetsToHex(octets), util.octetsToOct(octets)) )
            self.assertEquals(test_objectids[item], octets)

    def test_objectidEncodeDecode(self):
        """ Test encode/decode of ObjectID type
        """
        for item in test_objectids.keys():
            myobj = rfc1155.ObjectID(stringval=item)
            octets = myobj.encodeContents()
            object = myobj.decodeContents(octets)
            result = ['',]
            for num in object.value:
                result.append( '%d' % num )
            result = '.'.join(result)
            self.assertEquals(item, result)

    def test_nullEncode(self):
        """ Test encode of Null type
        """
        myobj = rfc1155.Null()
        octets = myobj.encodeContents()
        self.assertEquals(octets, '')

    def test_nullEncodeDecode(self):
        """ Test encode/decode of Null type
        """
        myobj = rfc1155.Null()
        octets = myobj.encodeContents()
        object = myobj.decodeContents(octets)
        self.assertEquals(object.value, None)

    def test_sequenceEncode(self):
        """ Test encode of Sequence type
        """
        for item in test_sequences.keys():
            myobj = rfc1155.Sequence(test_sequences[item])
            octets = myobj.encodeContents()
#            self.log.debug('Got value [length %s]: %s, oct: %s' % ( len(octets), util.octetsToHex(octets), util.octetsToOct(octets)) )
            self.assertEquals(item, octets)

    def test_sequenceEncodeDecode(self):
        """ Test encode/decode of Sequence type
        """
        for item in test_sequences.keys():
            myobj = rfc1155.Sequence(test_sequences[item])
            octets = myobj.encodeContents()
            object = myobj.decodeContents(octets)
            for x, y in zip(myobj.value, object.value):
                self.assertEquals(x.__class__, y.__class__)
                self.assertEquals(x.value, y.value)

    def test_sequenceofEncode(self):
        """ Test encode of SequenceOf type
        """
        for item in test_sequenceOf.keys():
            myobj = rfc1155.SequenceOf(test_sequenceOf[item][0], test_sequenceOf[item][1])
#            self.log.debug('SequenceOf: %s' % myobj)

    def test_sequenceofEncodeDecode(self):
        """ Test encode/decode of SequenceOf type
        """
        for item in test_sequenceOf.keys():
            myobj = rfc1155.SequenceOf(test_sequenceOf[item][0], test_sequenceOf[item][1])
#            self.log.debug('SequenceOf: %s' % myobj)
            octets = myobj.encodeContents()
            object = myobj.decodeContents(octets)
            for x, y in zip(myobj.value, object.value):
                self.assertEquals(x.__class__, y.__class__)
                self.assertEquals(x.value, y.value)

    def test_sequenceofNegativeTest_Type(self):
        """ Test mismatching SequenceOf types
        """
        self.assertRaises(ValueError, rfc1155.SequenceOf, rfc1155.Integer, [rfc1155.OctetString('fhdhd')])

    def test_ipAddressEncode(self):
        """ Test encode of IPAddress type
        """
        for item in test_ipaddresses.keys():
            myobj = rfc1155.IPAddress(stringval=test_ipaddresses[item])
#            self.log.debug('IPAddress: %s' % myobj)


    def test_octetDecode(self):
        """ Test decoding of multiple object types
        """
        decoder = rfc1155.Asn1Object()
        for item in test_octets.keys():
#            self.log.debug('decoding octets: %s [%s]' % ( item, util.octetsToHex(item) ))
            objectList = decoder.decode( item )

#            self.log.debug('objectList: %s' % objectList)
#            for object in objectList:
#                self.log.debug('object: %s, value: %s' % ( object.__class__.__name__, object) )

if __name__ == '__main__':
    unittest.main()

