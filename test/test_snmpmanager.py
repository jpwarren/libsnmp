import unittest
from unittest.mock import MagicMock
from libsnmp import rfc1157, rfc1905, v1, v2
from libsnmp.rfc1155 import ObjectID
from libsnmp.snmpmanager import snmpManager


class TestSNMPManager(unittest.TestCase):
    def setUp(self):
        self.manager = snmpManager()

    def tearDown(self):
        self.manager = None

    def test_createGetRequestPDU(self):
        varbindlist = rfc1157.VarBindList([rfc1157.VarBind(ObjectID('1.3.6.1.2.1.1.1.0'), rfc1157.Null())])
        pdu = self.manager.createGetRequestPDU(varbindlist, version=1)
        self.assertIsInstance(pdu, rfc1157.Get)
        self.assertEqual(pdu.requestID, 0)

    def test_createGetNextRequestPDU(self):
        varbindlist = rfc1157.VarBindList([rfc1157.VarBind(ObjectID('1.3.6.1.2.1.1.1.0'), rfc1157.Null())])
        pdu = self.manager.createGetNextRequestPDU(varbindlist, version=1)
        self.assertIsInstance(pdu, rfc1157.GetNext)
        self.assertEqual(pdu.requestID, 0)

    def test_createSetRequestPDU(self):
        varbindlist = rfc1157.VarBindList([rfc1157.VarBind(ObjectID('1.3.6.1.2.1.1.1.0'), rfc1157.Integer(10))])
        pdu = self.manager.createSetRequestPDU(varbindlist, version=1)
        self.assertIsInstance(pdu, rfc1157.Set)
        self.assertEqual(pdu.requestID, 0)

    def test_createGetRequestMessage(self):
        message = self.manager.createGetRequestMessage('1.3.6.1.2.1.1.1.0', community='public', version=1)
        self.assertIsInstance(message, rfc1157.Message)

    def test_createGetNextRequestMessage(self):
        varbindlist = rfc1157.VarBindList([rfc1157.VarBind(ObjectID('1.3.6.1.2.1.1.1.0'), rfc1157.Null())])
        message = self.manager.createGetNextRequestMessage(varbindlist, community='public', version=1)
        self.assertIsInstance(message, rfc1157.Message)

    def test_createSetRequestMessage(self):
        message = self.manager.createSetRequestMessage('1.3.6.1.2.1.1.1.0', 0x02, 1, community='public', version=1)
        self.assertIsInstance(message, rfc1157.Message)
        self.assertEqual(message.community.value, 'public')
        self.assertIsInstance(message.data, rfc1157.Set)
