# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# Unit tests for Messages

import unittest
import logging

import sys

sys.path.append('../lib')

from libsnmp import util
from libsnmp import debug
from libsnmp import rfc1155
from libsnmp import rfc1157

class MessagesTest(unittest.TestCase):

    def setUp(self):
        self.log = logging.getLogger('Messages')
        self.log.setLevel(logging.DEBUG)

    def tearDown(self):
        logging.shutdown()

    def test_Message1(self):
        """ Test encode/decode of Message
        """
        # Set up a Get request for the system uptime
        oid = rfc1155.ObjectID('.1.3.6.1.2.1.1.3.0')
        val = rfc1155.Null()
        variable = rfc1157.VarBind( oid, val )
        object = rfc1157.VarBindList( [variable, ] )
        message = rfc1157.Message( data=object.encode() )

        octets = message.encode()
        self.log.debug('octets: %s' % util.octetsToHex(octets) )

        # now decode it
        msg = rfc1157.Message().decode(octets)

        self.log.debug('decoded message: %s' % msg)

if __name__ == '__main__':
    unittest.main()

