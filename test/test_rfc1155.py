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

class EncoderTest(unittest.TestCase):
    
    def setUp(self):
        self.log = logging.getLogger('EncoderTest')
        self.log.setLevel(logging.DEBUG)
        return
    
    def tearDown(self):
        logging.shutdown()
        return
    
    def test_objectid_equality(self):
        
        """test equality of objects sourced from different initialisation values"""
        
        input_a = [1,3,6,1,2,1,2,3,234,23,4,23,423,234,23423423,4234] # list
        input_b = tuple(input_a)        # tuple
        input_c = '.'.join( [ str(x) for x in input_a] ) # string no leading dot
        input_d = '.' + input_c         # string leading dot
        

        object_a = rfc1155.ObjectID(input_a)
        object_b = rfc1155.ObjectID(input_b)
        object_c = rfc1155.ObjectID(input_c)
        object_d = rfc1155.ObjectID(input_d)
        object_e = rfc1155.ObjectID('.1.3')
        object_f = rfc1155.ObjectID().decode(object_a.encode())[0]
        object_g = rfc1155.Asn1Object().decode(object_a.encode())[0]        
        
        self.assertEquals(object_a, object_a)
        self.assertEquals(object_a, object_b)
        self.assertEquals(object_a, object_c)
        self.assertEquals(object_a, object_d)
        self.assertNotEquals(object_a, object_e)
        self.assertEquals(object_a, object_f)
        self.assertEquals(object_a, object_g)        
        
        self.assertEquals(object_b, object_a)
        self.assertEquals(object_b, object_b)
        self.assertEquals(object_b, object_c)
        self.assertEquals(object_b, object_d)
        self.assertNotEquals(object_b, object_e)        
        self.assertEquals(object_b, object_f)
        self.assertEquals(object_b, object_g)        
        
        pass
        
        return
    
    def test_objectid_length(self):
        
        """test length"""

        input_a = [1,3,6,1,2,1,2,3,234,23,4,23,423,234,23423423,4234] # list
        input_b = tuple(input_a)        # tuple
        input_c = '.'.join( [ str(x) for x in input_a] ) # string no leading dot
        input_d = '.' + input_c         # string leading dot
        
        object_a = rfc1155.ObjectID(input_a)
        object_b = rfc1155.ObjectID(input_b)
        object_c = rfc1155.ObjectID(input_c)
        object_d = rfc1155.ObjectID(input_d)
        object_e = rfc1155.ObjectID('.1.3')
        
        self.assertEquals(len(object_a), len(input_a))
        self.assertEquals(len(object_b), len(input_a))
        self.assertEquals(len(object_c), len(input_a))
        self.assertEquals(len(object_d), len(input_a))
        self.assertNotEquals(len(object_b), len(object_e))
        
        return
    
    pass

if __name__ == '__main__':
    unittest.main()

