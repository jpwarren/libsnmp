import unittest
import asyncore
from unittest.mock import MagicMock

from libsnmp import role
from libsnmp.asynrole import Manager


class TestManager(unittest.TestCase):

    def setUp(self):
        self.cb_fun = MagicMock()
        self.cb_ctx = MagicMock()
        self.dst = ('127.0.0.1', 161)
        self.interface = ('0.0.0.0', 0)
        self.timeout = 0.25

        self.manager = Manager((self.cb_fun, self.cb_ctx), self.dst, self.interface, self.timeout)

    def tearDown(self):
        pass

    def test_init_valid_parameters(self):
        self.assertEqual(self.manager.cb_fun, self.cb_fun)
        self.assertEqual(self.manager.cb_ctx, self.cb_ctx)
        self.assertEqual(self.manager.timeout, self.timeout)
        self.assertIsInstance(self.manager.manager, role.manager)

    def test_init_invalid_callback_function(self):
        with self.assertRaises(ValueError):
            Manager((None, self.cb_ctx), self.dst, self.interface, self.timeout)

    def test_send(self):
        req = MagicMock()
        dst = ('127.0.0.1', 161)
        self.manager.manager.send = MagicMock()
        self.manager.send(req, dst)
        self.manager.manager.send.assert_called_once_with(req, dst)

    def test_handle_read(self):
        response = MagicMock()
        src = ('127.0.0.1', 161)
        self.manager.manager.read = MagicMock(return_value=(response, src))
        self.manager.cb_fun = MagicMock()
        self.manager.handle_read()
        self.manager.cb_fun.assert_called_once_with(self.manager, self.cb_ctx, (response, src), (None, None, None))

    def test_writable(self):
        self.assertEqual(self.manager.writable(), 0)

    def test_handle_connect(self):
        self.manager.handle_connect()

    def test_handle_close(self):
        self.manager.manager.close = MagicMock()
        self.manager.handle_close()
        self.manager.manager.close.assert_called_once()

    def test_handle_error_value_error(self):
        exc_type = ValueError
        exc_value = MagicMock()
        exc_traceback = MagicMock()
        self.manager.cb_fun = MagicMock()
        self.manager.handle_error(exc_type, exc_value, exc_traceback)
        self.manager.cb_fun.assert_called_once_with(self.manager, self.cb_ctx, (None, None), (exc_type, exc_value, exc_traceback))

    def test_handle_error_other_errors(self):
        exc_type = RuntimeError
        exc_value = MagicMock()
        exc_traceback = MagicMock()
        self.manager.cb_fun = MagicMock()
        with self.assertRaises(RuntimeError):
            self.manager.handle_error(exc_type, exc_value, exc_traceback)
        self.manager.cb_fun.assert_not_called()

    def test_poll(self):
        asyncore.poll = MagicMock()
        self.manager.poll()
        asyncore.poll.assert_called_once_with(self.timeout)


if __name__ == '__main__':
    unittest.main()
