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
        
        group = (
            (1,3,6,1,2,1,2,1,2,1,2,1,21,23423,1,2,3,4,3,4,5,34,5,2348535,1,45345,345),
            [1,2,4,4,3,4,345,345,34,4],
            [1,3],
            #[],
            #(),
            )
        
        for value in group:
            valuestr = '.' + '.'.join([ str(x) for x in value])
            print valuestr
            a = rfc1155.ObjectID(value)
            b = rfc1155.ObjectID(valuestr)
            c = rfc1155.ObjectID().decode(a.encode())
            d = rfc1155.ObjectID('.1.3')
        
            
            self.assertEquals(a,b)
            self.assertEquals(b,a)
            self.assertEquals(a,c)
            self.assertEquals(c,a)
            self.assertEquals(b,c)
            self.assertEquals(c,b)
            self.assertNotEquals(a,d)
            self.assertNotEquals(b,d)
            self.assertNotEquals(c,d)
            pass
        
        return
    
    def test_objectid_length(self):
        
        """test length"""
        
        group = (
            (1,2,3,4,3,4,34534534,345,345,345,345,456,456,567,567,567,1,1,1,1,1,1,1,1,1,1,0),
            (),
            [123,23423,4,234],
            []
            )
        
        for value in group:
            
            valuestr = '.' + '.'.join([ str(x) for x in value])
            a = rfc1155.ObjectID(value)
            b = rfc1155.ObjectID(valuestr)
            self.assertEquals(len(value), len(a))
            self.assertEquals(len(value), len(b))        
            pass
        
        return
    
    pass

if __name__ == '__main__':
    unittest.main()

